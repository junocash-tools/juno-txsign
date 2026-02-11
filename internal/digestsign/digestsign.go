package digestsign

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const EnvSignerKeys = "JUNO_TXSIGN_SIGNER_KEYS"

var secp256k1HalfN = new(big.Int).Rsh(new(big.Int).Set(secp256k1.S256().Params().N), 1)

type signerSignature struct {
	address string
	sigHex  string
}

func ParseDigestHex(raw string) ([]byte, error) {
	digestHex := strings.TrimSpace(raw)
	if digestHex == "" {
		return nil, errors.New("digest is required")
	}
	digestHex = strings.TrimPrefix(strings.ToLower(digestHex), "0x")
	if len(digestHex) != 64 {
		return nil, errors.New("digest must be 32-byte hex")
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, errors.New("digest must be 32-byte hex")
	}
	if len(digest) != 32 {
		return nil, errors.New("digest must be 32-byte hex")
	}
	return digest, nil
}

func parseSignerKeys(raw string) ([]string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, fmt.Errorf("%s is required", EnvSignerKeys)
	}

	var parts []string
	if strings.HasPrefix(v, "[") {
		// Optional JSON array input.
		var arr []string
		if err := jsonUnmarshal([]byte(v), &arr); err != nil {
			return nil, fmt.Errorf("%s must be a comma-separated list or JSON array of 32-byte hex keys", EnvSignerKeys)
		}
		parts = arr
	} else {
		parts = strings.Split(v, ",")
	}

	out := make([]string, 0, len(parts))
	for i, p := range parts {
		k := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(p), "0x"))
		if k == "" {
			return nil, fmt.Errorf("%s[%d] is empty", EnvSignerKeys, i)
		}
		if len(k) != 64 {
			return nil, fmt.Errorf("%s[%d] must be 32-byte hex", EnvSignerKeys, i)
		}
		if _, err := hex.DecodeString(k); err != nil {
			return nil, fmt.Errorf("%s[%d] must be 32-byte hex", EnvSignerKeys, i)
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is required", EnvSignerKeys)
	}
	return out, nil
}

var jsonUnmarshal = func(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

func LoadSignerKeysFromEnv() ([]string, error) {
	return parseSignerKeys(os.Getenv(EnvSignerKeys))
}

func SignDigest(digest []byte, signerKeys []string) ([]string, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be 32 bytes")
	}
	if len(signerKeys) == 0 {
		return nil, errors.New("no signer keys")
	}

	signed := make([]signerSignature, 0, len(signerKeys))
	seenAddr := make(map[string]struct{}, len(signerKeys))

	for i, keyHex := range signerKeys {
		keyBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(keyHex)), "0x"))
		if err != nil {
			return nil, fmt.Errorf("signer key %d invalid", i)
		}
		priv := secp256k1.PrivKeyFromBytes(keyBytes)

		compact := ecdsa.SignCompact(priv, digest, false) // [header || R || S]
		if len(compact) != 65 {
			return nil, fmt.Errorf("signer key %d signature invalid", i)
		}
		v := compact[0]
		if v != 27 && v != 28 {
			return nil, fmt.Errorf("signer key %d signature v invalid", i)
		}

		s := new(big.Int).SetBytes(compact[33:65])
		if s.Cmp(secp256k1HalfN) > 0 {
			return nil, fmt.Errorf("signer key %d signature has high-s", i)
		}

		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			return nil, fmt.Errorf("signer key %d signature recovery failed", i)
		}
		addr := strings.ToLower(evmAddressHex(pub))
		if _, exists := seenAddr[addr]; exists {
			return nil, fmt.Errorf("duplicate signer address: %s", addr)
		}
		seenAddr[addr] = struct{}{}

		sigOut := make([]byte, 65)
		copy(sigOut[:32], compact[1:33])  // r
		copy(sigOut[32:64], compact[33:]) // s
		sigOut[64] = v

		signed = append(signed, signerSignature{
			address: addr,
			sigHex:  "0x" + hex.EncodeToString(sigOut),
		})
	}

	sort.Slice(signed, func(i, j int) bool {
		return signed[i].address < signed[j].address
	})

	out := make([]string, len(signed))
	for i := range signed {
		out[i] = signed[i].sigHex
	}
	return out, nil
}

func evmAddressHex(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 65 bytes, 0x04 || X || Y
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}
