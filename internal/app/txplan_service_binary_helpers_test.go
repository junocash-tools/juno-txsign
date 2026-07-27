//go:build e2e

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/txplansignservice"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func signPlanViaUnixServiceBinary(t *testing.T, txplan types.TxPlan, seeds []string) txsign.Result {
	t.Helper()
	planBytes, err := json.Marshal(txplan)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(planBytes)
	request := txplansignservice.SignRequest{
		Version:      txplansignservice.JSONVersionV1,
		PlanDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		TxPlanBase64: base64.StdEncoding.EncodeToString(planBytes),
	}
	var last string
	for index, seed := range seeds {
		request.AttemptID = fmt.Sprintf("regtest-binary-service-%d", index)
		result, status, response := invokeUnixSignerBinary(t, txplan, seed, request)
		last = response
		if status == http.StatusOK {
			return result
		}
	}
	t.Fatalf("built Unix signer could not sign with candidate seeds: %s", last)
	return txsign.Result{}
}

func invokeUnixSignerBinary(
	t *testing.T,
	txplan types.TxPlan,
	seed string,
	request txplansignservice.SignRequest,
) (txsign.Result, int, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "juno-txsign-binary-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketDir := filepath.Join(root, "socket")
	secretDir := filepath.Join(root, "secrets")
	for _, dir := range []string{socketDir, secretDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	seedPath := filepath.Join(secretDir, "seed.b64")
	if err := os.WriteFile(seedPath, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	network := normalizedTestNetwork(txplan.Chain)
	coinType := uint32(8135)
	if network == "mainnet" {
		coinType = 8133
	} else if network == "testnet" {
		coinType = 8134
	}
	ufvk, err := txsign.DeriveUFVK(context.Background(), seed, coinType, txplan.Account)
	if err != nil {
		t.Fatal(err)
	}
	bindingsPath := filepath.Join(secretDir, "bindings.json")
	bindingsPayload, err := json.Marshal(map[string]any{
		"version": "v1",
		"bindings": []map[string]any{{
			"wallet_id": txplan.WalletID,
			"account":   txplan.Account,
			"network":   network,
			"ufvk":      ufvk,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingsPath, bindingsPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(socketDir, "signer.sock")
	journalDir := filepath.Join(root, "journal")
	command := exec.Command(
		filepath.Join(repoRoot(), "bin", "juno-txsign"),
		"serve-txplan",
		"--socket", socketPath,
		"--journal-dir", journalDir,
		"--seed-file", seedPath,
		"--bindings-file", bindingsPath,
	)
	command.Env = withoutEnv(os.Environ(), txplansignservice.EnvSeedBase64)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start built Unix signer: %v", err)
	}
	waitDone := make(chan struct{})
	var waitMu sync.Mutex
	var waitErr error
	go func() {
		err := command.Wait()
		waitMu.Lock()
		waitErr = err
		waitMu.Unlock()
		close(waitDone)
	}()
	readWaitErr := func() error {
		waitMu.Lock()
		defer waitMu.Unlock()
		return waitErr
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			select {
			case <-waitDone:
				return
			default:
			}
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitDone:
				err := readWaitErr()
				if err != nil {
					t.Errorf("built Unix signer shutdown: %v stderr=%s", err, stderr.String())
				}
			case <-time.After(30 * time.Second):
				_ = command.Process.Kill()
				<-waitDone
				t.Error("built Unix signer did not shut down gracefully")
			}
		})
	}
	defer stop()

	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}

	deadline := time.Now().Add(15 * time.Second)
	for {
		healthRequest, err := http.NewRequest(http.MethodGet, "http://unix/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, healthErr := client.Do(healthRequest)
		if healthErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-waitDone:
			return txsign.Result{}, 0, fmt.Sprintf("signer exited before readiness: %v stderr=%s", readWaitErr(), stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("built Unix signer not ready: %s", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	call := func() (txplansignservice.SignResponse, int, string) {
		payload, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		httpRequest, err := http.NewRequest(http.MethodPost, "http://unix"+txplansignservice.SignPath, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatalf("call built Unix signer: %v", err)
		}
		defer response.Body.Close()
		var decoded txplansignservice.SignResponse
		if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(decoded)
		return decoded, response.StatusCode, string(raw)
	}
	response, status, raw := call()
	if status != http.StatusOK || response.Data == nil {
		return txsign.Result{}, status, raw
	}
	replay, replayStatus, replayRaw := call()
	if replayStatus != http.StatusOK || replay.Data == nil || !replay.Data.Replayed ||
		replay.Data.RawTxHex != response.Data.RawTxHex {
		t.Fatalf("built Unix signer replay status=%d body=%s", replayStatus, replayRaw)
	}
	stop()
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("built Unix signer left socket after graceful shutdown: %v", err)
	}
	return txsign.Result{
		TxID:                       response.Data.TxID,
		RawTxHex:                   response.Data.RawTxHex,
		FeeZat:                     response.Data.FeeZat,
		OrchardOutputActionIndices: response.Data.OrchardOutputActionIndices,
		OrchardChangeActionIndex:   response.Data.OrchardChangeActionIndex,
	}, status, raw
}

func withoutEnv(environment []string, key string) []string {
	prefix := key + "="
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
