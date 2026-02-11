package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func TestRunSign_JSONErrorIncludesVersion(t *testing.T) {
	var out, errBuf bytes.Buffer

	code := RunWithIO([]string{"sign", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}

	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, out.String())
	}
	if v["version"] != "v1" || v["status"] != "err" {
		t.Fatalf("unexpected json: %v", v)
	}
}

func TestRunSignDigest_UsageRequiresJSON(t *testing.T) {
	t.Setenv(digestsign.EnvSignerKeys, "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a")

	var out, errBuf bytes.Buffer
	code := RunWithIO([]string{"sign-digest", "--digest", "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("code=%d want=2", code)
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected stdout: %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "--json is required") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}

func TestRunSignDigest_InvalidDigest_ErrorEnvelope(t *testing.T) {
	t.Setenv(digestsign.EnvSignerKeys, "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a")

	var out, errBuf bytes.Buffer
	code := RunWithIO([]string{"sign-digest", "--digest", "0x1234", "--json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}

	var resp struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, out.String())
	}
	if resp.Version != "v1" || resp.Status != "err" {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
	if resp.Error.Code == "" || resp.Error.Message == "" {
		t.Fatalf("missing error body: %+v", resp.Error)
	}
}

func TestRunSignDigest_MissingSignerKeys_ErrorEnvelope(t *testing.T) {
	t.Setenv(digestsign.EnvSignerKeys, "")

	var out, errBuf bytes.Buffer
	code := RunWithIO([]string{"sign-digest", "--digest", "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1", "--json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}

	var resp struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, out.String())
	}
	if resp.Version != "v1" || resp.Status != "err" {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
	if resp.Error.Code != "sign_failed" {
		t.Fatalf("unexpected error code: %q", resp.Error.Code)
	}
}

func TestRunSignDigest_OKEnvelopeAndSignatureRules(t *testing.T) {
	t.Setenv(digestsign.EnvSignerKeys, strings.Join([]string{
		"8f2a5594909ad95b6f06ea6f933f2f898e6f6f5024de10ca47a57f077e8de6f6",
		"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a",
	}, ","))

	const digestHex = "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"
	digest, err := digestsign.ParseDigestHex(digestHex)
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	var out, errBuf bytes.Buffer
	code := RunWithIO([]string{"sign-digest", "--digest", digestHex, "--json"}, &out, &errBuf)
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
		t.Fatalf("invalid json: %v (%q)", err, out.String())
	}
	if resp.Version != "v1" || resp.Status != "ok" {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
	if len(resp.Data.Signatures) != 2 {
		t.Fatalf("signature count=%d want=2", len(resp.Data.Signatures))
	}

	addresses := make([]string, 0, len(resp.Data.Signatures))
	seen := map[string]struct{}{}
	for i, sigHex := range resp.Data.Signatures {
		if !strings.HasPrefix(sigHex, "0x") {
			t.Fatalf("sig[%d] missing 0x", i)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil {
			t.Fatalf("sig[%d] hex decode: %v", i, err)
		}
		if len(raw) != 65 {
			t.Fatalf("sig[%d] len=%d want=65", i, len(raw))
		}
		v := raw[64]
		if v != 27 && v != 28 {
			t.Fatalf("sig[%d] v=%d want 27|28", i, v)
		}
		r := new(big.Int).SetBytes(raw[:32])
		s := new(big.Int).SetBytes(raw[32:64])
		if r.Sign() <= 0 {
			t.Fatalf("sig[%d] r not positive", i)
		}
		if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(secp256k1.S256().Params().N), 1)) > 0 {
			t.Fatalf("sig[%d] high-s", i)
		}

		compact := make([]byte, 65)
		compact[0] = v
		copy(compact[1:], raw[:64])
		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			t.Fatalf("sig[%d] recover: %v", i, err)
		}
		addr := strings.ToLower(testEVMAddressHex(pub))
		if _, ok := seen[addr]; ok {
			t.Fatalf("duplicate address: %s", addr)
		}
		seen[addr] = struct{}{}
		addresses = append(addresses, addr)
	}

	for i := 1; i < len(addresses); i++ {
		if addresses[i-1] > addresses[i] {
			t.Fatalf("addresses not sorted: %v", addresses)
		}
	}
}

func testEVMAddressHex(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}
