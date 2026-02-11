package digestsign

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestParseDigestHex(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		wantOK bool
	}{
		{name: "valid prefixed", in: "0x1111111111111111111111111111111111111111111111111111111111111111", wantOK: true},
		{name: "valid unprefixed", in: "1111111111111111111111111111111111111111111111111111111111111111", wantOK: true},
		{name: "missing", in: "", wantOK: false},
		{name: "short", in: "0x1234", wantOK: false},
		{name: "bad hex", in: "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDigestHex(tc.in)
			if (err == nil) != tc.wantOK {
				t.Fatalf("err=%v wantOK=%v", err, tc.wantOK)
			}
		})
	}
}

func TestSignDigest_SortedUniqueAndValid(t *testing.T) {
	digest, err := ParseDigestHex("0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	// Intentionally unsorted by signer address.
	keys := []string{
		"8f2a5594909ad95b6f06ea6f933f2f898e6f6f5024de10ca47a57f077e8de6f6",
		"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a",
	}

	sigs, err := SignDigest(digest, keys)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sigs) != len(keys) {
		t.Fatalf("signature count mismatch: got %d want %d", len(sigs), len(keys))
	}

	gotAddrs := make([]string, 0, len(sigs))
	seen := map[string]struct{}{}
	for i, sigHex := range sigs {
		if !strings.HasPrefix(sigHex, "0x") {
			t.Fatalf("sig[%d] missing 0x prefix", i)
		}
		sig := strings.TrimPrefix(sigHex, "0x")
		if len(sig) != 130 {
			t.Fatalf("sig[%d] length=%d want=130", i, len(sig))
		}
		raw, err := hex.DecodeString(sig)
		if err != nil {
			t.Fatalf("sig[%d] hex decode: %v", i, err)
		}
		v := raw[64]
		if v != 27 && v != 28 {
			t.Fatalf("sig[%d] v=%d want 27 or 28", i, v)
		}

		r := new(big.Int).SetBytes(raw[:32])
		s := new(big.Int).SetBytes(raw[32:64])
		if s.Cmp(secp256k1HalfN) > 0 {
			t.Fatalf("sig[%d] high-s", i)
		}
		if r.Sign() <= 0 {
			t.Fatalf("sig[%d] r not positive", i)
		}

		compact := make([]byte, 65)
		compact[0] = v
		copy(compact[1:], raw[:64])
		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			t.Fatalf("sig[%d] recover: %v", i, err)
		}
		addr := strings.ToLower(evmAddressHex(pub))
		if _, ok := seen[addr]; ok {
			t.Fatalf("duplicate recovered signer address: %s", addr)
		}
		seen[addr] = struct{}{}
		gotAddrs = append(gotAddrs, addr)
	}

	for i := 1; i < len(gotAddrs); i++ {
		if gotAddrs[i-1] > gotAddrs[i] {
			t.Fatalf("signer addresses not sorted: %v", gotAddrs)
		}
	}
}

func TestSignDigest_RejectsDuplicateSignerAddress(t *testing.T) {
	digest, err := ParseDigestHex("0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	// Same key twice -> same recovered signer address.
	keys := []string{
		"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a",
		"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a",
	}

	if _, err := SignDigest(digest, keys); err == nil {
		t.Fatalf("expected duplicate signer error")
	}
}
