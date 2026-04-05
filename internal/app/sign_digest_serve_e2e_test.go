//go:build e2e

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
)

func TestE2E_Serve_SignDigest(t *testing.T) {
	const (
		digestHex = "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"
		signerKey = "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	bin := filepath.Join(repoRoot(), "bin", "juno-txsign")
	listen := mustFreeAddrForServe(t)
	baseURL := "http://" + listen

	cmd := exec.CommandContext(ctx, bin, "serve", "--listen", listen)
	cmd.Env = append(cmd.Environ(), digestsign.EnvSignerKeys+"="+signerKey)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		case <-done:
		}
		if t.Failed() {
			t.Logf("serve stderr:\n%s", stderr.String())
			t.Logf("serve stdout:\n%s", stdout.String())
		}
	})

	if err := waitForServeHealthz(ctx, baseURL+"/healthz"); err != nil {
		t.Fatalf("healthz: %v\nstderr=%s", err, stderr.String())
	}

	body, err := json.Marshal(digestsign.SignDigestRequest{
		Version: digestsign.JSONVersionV1,
		Digest:  digestHex,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+digestsign.SignDigestPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post sign-digest: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed digestsign.SignDigestResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("decode response: %v body=%s", err, strings.TrimSpace(string(respBody)))
	}
	if parsed.Version != digestsign.JSONVersionV1 || parsed.Status != "ok" {
		t.Fatalf("unexpected response: %+v", parsed)
	}
	if len(parsed.Data.Signatures) != 1 {
		t.Fatalf("signature count=%d want=1", len(parsed.Data.Signatures))
	}
}

func mustFreeAddrForServe(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitForServeHealthz(ctx context.Context, url string) error {
	deadline := time.Now().Add(20 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("timeout")
}
