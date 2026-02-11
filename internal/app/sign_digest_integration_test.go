//go:build integration

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestIntegration_SignDigest_GoldenRecovery(t *testing.T) {
	const (
		digestHex = "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"
		key1      = "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"
		key2      = "8f2a5594909ad95b6f06ea6f933f2f898e6f6f5024de10ca47a57f077e8de6f6"
	)

	digest, err := digestsign.ParseDigestHex(digestHex)
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/juno-txsign", "sign-digest", "--digest", digestHex, "--json")
	cmd.Dir = repoRoot()
	cmd.Env = append(
		cmd.Environ(),
		digestsign.EnvSignerKeys+"="+key2+","+key1, // intentionally unsorted
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sign-digest command failed: %v", err)
	}

	var resp struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Data    struct {
			Signatures []string `json:"signatures"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode json: %v (%q)", err, string(out))
	}
	if resp.Version != "v1" || resp.Status != "ok" {
		t.Fatalf("unexpected response: %s", string(out))
	}
	if len(resp.Data.Signatures) != 2 {
		t.Fatalf("signature count=%d want=2", len(resp.Data.Signatures))
	}

	addrs := make([]string, 0, 2)
	for i, sigHex := range resp.Data.Signatures {
		raw, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil {
			t.Fatalf("sig[%d] decode: %v", i, err)
		}
		if len(raw) != 65 {
			t.Fatalf("sig[%d] len=%d want=65", i, len(raw))
		}
		if raw[64] != 27 && raw[64] != 28 {
			t.Fatalf("sig[%d] v=%d want 27|28", i, raw[64])
		}

		compact := make([]byte, 65)
		compact[0] = raw[64]
		copy(compact[1:], raw[:64])
		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			t.Fatalf("sig[%d] recover: %v", i, err)
		}
		addrs = append(addrs, strings.ToLower(evmAddressHexForTest(pub)))
	}

	for i := 1; i < len(addrs); i++ {
		if addrs[i-1] > addrs[i] {
			t.Fatalf("addresses not sorted: %v", addrs)
		}
	}

	// Golden recovered signer set for the digest above and keys {key1,key2}.
	const (
		wantAddr1 = "0x61e6ac04e9658b38e85f7d6621b770f6d5150595"
		wantAddr2 = "0x73e5dbe48f8f9019ceb638b69aadb5d37c4ae2fc"
	)
	if addrs[0] != wantAddr1 || addrs[1] != wantAddr2 {
		t.Fatalf("recovered addresses=%v want=[%s %s]", addrs, wantAddr1, wantAddr2)
	}
}
