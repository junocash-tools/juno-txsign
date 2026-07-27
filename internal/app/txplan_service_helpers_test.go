//go:build integration || e2e

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/txplansignservice"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func signPlanViaUnixService(t *testing.T, txplan types.TxPlan, seeds []string) txsign.Result {
	t.Helper()
	planBytes, err := json.Marshal(txplan)
	if err != nil {
		t.Fatalf("marshal service TxPlan: %v", err)
	}
	digest := sha256.Sum256(planBytes)
	request := txplansignservice.SignRequest{
		Version:      txplansignservice.JSONVersionV1,
		PlanDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		TxPlanBase64: base64.StdEncoding.EncodeToString(planBytes),
	}

	var lastResponse string
	for i, seed := range seeds {
		request.AttemptID = fmt.Sprintf("regtest-service-%d", i)
		result, replay, status, response := invokeUnixSigner(t, txplan, seed, request)
		lastResponse = response
		if status != http.StatusOK {
			continue
		}
		if replay {
			t.Fatal("first Unix signer response was unexpectedly a replay")
		}
		return result
	}
	t.Fatalf("no candidate seed signed through Unix service: %s", lastResponse)
	return txsign.Result{}
}

func invokeUnixSigner(
	t *testing.T,
	txplan types.TxPlan,
	seed string,
	request txplansignservice.SignRequest,
) (txsign.Result, bool, int, string) {
	t.Helper()
	root := t.TempDir()
	journalDir := filepath.Join(root, "journal")
	journal, err := txplansignservice.OpenJournal(journalDir)
	if err != nil {
		t.Fatalf("open service journal: %v", err)
	}
	defer journal.Close()
	network := normalizedTestNetwork(txplan.Chain)
	coinType := uint32(8135)
	if network == "mainnet" {
		coinType = 8133
	} else if network == "testnet" {
		coinType = 8134
	}
	ufvk, err := txsign.DeriveUFVK(context.Background(), seed, coinType, txplan.Account)
	if err != nil {
		t.Fatalf("derive service UFVK: %v", err)
	}
	binding := txplansignservice.Binding{
		WalletID: txplan.WalletID,
		Account:  txplan.Account,
		Network:  network,
		UFVK:     ufvk,
	}
	if err := txplansignservice.VerifySeedBindings(context.Background(), seed, []txplansignservice.Binding{binding}); err != nil {
		t.Fatalf("verify service binding: %v", err)
	}
	api, err := txplansignservice.New(
		journal,
		txplansignservice.NewSeedSigner(seed),
		txplansignservice.Policy{Bindings: []txplansignservice.Binding{binding}},
		1,
	)
	if err != nil {
		t.Fatalf("new service API: %v", err)
	}

	socketDir, err := os.MkdirTemp("/tmp", "juno-txsign-test-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("protect socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "signer.sock")
	listener, err := txplansignservice.OpenUnixListener(socketPath)
	if err != nil {
		t.Fatalf("open service socket: %v", err)
	}
	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-serverDone
	}()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}

	call := func() (txplansignservice.SignResponse, int, string) {
		payload, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal service request: %v", err)
		}
		httpRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix"+txplansignservice.SignPath, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("new service request: %v", err)
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatalf("call service: %v", err)
		}
		defer response.Body.Close()
		var decoded txplansignservice.SignResponse
		var raw bytes.Buffer
		decoder := json.NewDecoder(io.TeeReader(response.Body, &raw))
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("decode service response: %v", err)
		}
		return decoded, response.StatusCode, raw.String()
	}

	response, status, raw := call()
	if status != http.StatusOK || response.Data == nil {
		return txsign.Result{}, false, status, raw
	}
	firstRawTx := response.Data.RawTxHex
	replay, replayStatus, replayRaw := call()
	if replayStatus != http.StatusOK || replay.Data == nil || !replay.Data.Replayed {
		t.Fatalf("service replay status=%d body=%s", replayStatus, replayRaw)
	}
	if replay.Data.RawTxHex != firstRawTx || replay.Data.TxID != response.Data.TxID {
		t.Fatal("service replay changed signed transaction")
	}
	return txsign.Result{
		TxID:                       response.Data.TxID,
		RawTxHex:                   response.Data.RawTxHex,
		FeeZat:                     response.Data.FeeZat,
		OrchardOutputActionIndices: response.Data.OrchardOutputActionIndices,
		OrchardChangeActionIndex:   response.Data.OrchardChangeActionIndex,
	}, response.Data.Replayed, status, raw
}

func normalizedTestNetwork(chain string) string {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "main", "mainnet":
		return "mainnet"
	case "test", "testnet":
		return "testnet"
	default:
		return "regtest"
	}
}
