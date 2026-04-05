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

const (
	JSONVersionV1  = "v1"
	SignDigestPath = "/v1/sign-digest"
)

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

	signed := make([]string, 0, len(signerKeys))

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

		signed = append(signed, compactSignatureHex(compact))
	}

	return NormalizeSignatures(digest, signed)
}

func NormalizeSignatures(digest []byte, signatures []string) ([]string, error) {
	validated, err := validateSignatures(digest, signatures)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(validated))
	for i := range validated {
		out[i] = validated[i].sigHex
	}
	return out, nil
}

func MergeSignatureSets(digest []byte, signatureSets ...[]string) ([]string, error) {
	total := 0
	for _, set := range signatureSets {
		total += len(set)
	}
	flat := make([]string, 0, total)
	for _, set := range signatureSets {
		flat = append(flat, set...)
	}
	return NormalizeSignatures(digest, flat)
}

func validateSignatures(digest []byte, signatures []string) ([]signerSignature, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be 32 bytes")
	}
	if len(signatures) == 0 {
		return nil, errors.New("no signatures")
	}

	validated := make([]signerSignature, 0, len(signatures))
	seenAddr := make(map[string]struct{}, len(signatures))

	for i, sigHex := range signatures {
		normalized, raw, err := parseSignatureHex(sigHex)
		if err != nil {
			return nil, fmt.Errorf("signature %d invalid: %w", i, err)
		}

		v := raw[64]
		if v != 27 && v != 28 {
			return nil, fmt.Errorf("signature %d v invalid", i)
		}

		r := new(big.Int).SetBytes(raw[:32])
		if r.Sign() <= 0 {
			return nil, fmt.Errorf("signature %d r invalid", i)
		}

		s := new(big.Int).SetBytes(raw[32:64])
		if s.Cmp(secp256k1HalfN) > 0 {
			return nil, fmt.Errorf("signature %d has high-s", i)
		}

		compact := make([]byte, 65)
		compact[0] = v
		copy(compact[1:], raw[:64])

		pub, _, err := ecdsa.RecoverCompact(compact, digest)
		if err != nil {
			return nil, fmt.Errorf("signature %d recovery failed", i)
		}
		addr := strings.ToLower(evmAddressHex(pub))
		if _, exists := seenAddr[addr]; exists {
			return nil, fmt.Errorf("duplicate signer address: %s", addr)
		}
		seenAddr[addr] = struct{}{}

		validated = append(validated, signerSignature{
			address: addr,
			sigHex:  normalized,
		})
	}

	sort.Slice(validated, func(i, j int) bool {
		return validated[i].address < validated[j].address
	})
	return validated, nil
}

func parseSignatureHex(sigHex string) (string, []byte, error) {
	trimmed := strings.TrimSpace(sigHex)
	if !strings.HasPrefix(trimmed, "0x") && !strings.HasPrefix(trimmed, "0X") {
		return "", nil, errors.New("must be 0x-prefixed 65-byte hex")
	}

	rawHex := strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	if len(rawHex) != 130 {
		return "", nil, errors.New("must be 0x-prefixed 65-byte hex")
	}

	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", nil, errors.New("must be 0x-prefixed 65-byte hex")
	}
	if len(raw) != 65 {
		return "", nil, errors.New("must be 0x-prefixed 65-byte hex")
	}
	return "0x" + hex.EncodeToString(raw), raw, nil
}

func compactSignatureHex(compact []byte) string {
	sigOut := make([]byte, 65)
	copy(sigOut[:32], compact[1:33])  // r
	copy(sigOut[32:64], compact[33:]) // s
	sigOut[64] = compact[0]
	return "0x" + hex.EncodeToString(sigOut)
}

func evmAddressHex(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 65 bytes, 0x04 || X || Y
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}
