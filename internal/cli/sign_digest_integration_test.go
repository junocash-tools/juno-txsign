//go:build integration

package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
	"github.com/Abdullah1738/juno-txsign/internal/digestsignhttp"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestIntegration_RunSignDigest_MultiEndpoint(t *testing.T) {
	const (
		digestHex  = "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"
		localKey   = "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"
		remoteKey1 = "8f2a5594909ad95b6f06ea6f933f2f898e6f6f5024de10ca47a57f077e8de6f6"
		remoteKey2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)

	t.Setenv(digestsign.EnvSignerKeys, localKey)

	digest, err := digestsign.ParseDigestHex(digestHex)
	if err != nil {
		t.Fatalf("ParseDigestHex: %v", err)
	}

	srv1 := mustTLSOperatorServer(t, []string{remoteKey1})
	srv2 := mustTLSOperatorServer(t, []string{remoteKey2})

	roots := x509.NewCertPool()
	roots.AddCert(srv1.Certificate())
	roots.AddCert(srv2.Certificate())

	prevFactory := newHTTPClient
	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots},
			},
		}
	}
	t.Cleanup(func() {
		newHTTPClient = prevFactory
	})

	var out, errBuf bytes.Buffer
	code := RunWithIO([]string{
		"sign-digest",
		"--digest", digestHex,
		"--operator-endpoint", srv1.URL,
		"--operator-endpoint", srv2.URL,
		"--json",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q body=%q", code, errBuf.String(), out.String())
	}
	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}

	var resp struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Data    struct {
			Signatures []string `json:"signatures"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode json: %v (%q)", err, out.String())
	}
	if resp.Version != "v1" || resp.Status != "ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Data.Signatures) != 3 {
		t.Fatalf("signature count=%d want=3", len(resp.Data.Signatures))
	}

	addrs := make([]string, 0, len(resp.Data.Signatures))
	for i, sigHex := range resp.Data.Signatures {
		raw, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil {
			t.Fatalf("sig[%d] decode: %v", i, err)
		}
		compact := make([]byte, 65)
		compact[0] = raw[64]
		copy(compact[1:], raw[:64])

		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			t.Fatalf("sig[%d] recover: %v", i, err)
		}
		addrs = append(addrs, strings.ToLower(testEVMAddressHex(pub)))
	}
	for i := 1; i < len(addrs); i++ {
		if addrs[i-1] >= addrs[i] {
			t.Fatalf("addresses not strictly ascending: %v", addrs)
		}
	}
}

func mustTLSOperatorServer(t *testing.T, signerKeys []string) *httptest.Server {
	t.Helper()

	api, err := digestsignhttp.New(signerKeys)
	if err != nil {
		t.Fatalf("digestsignhttp.New: %v", err)
	}

	srv := httptest.NewTLSServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}
