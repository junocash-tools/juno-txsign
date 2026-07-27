package txsign

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseExtFinalizeResponseOmitsActionMappings(t *testing.T) {
	const valid = `{"status":"ok","txid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","raw_tx_hex":"00","fee_zat":"10000"}`
	result, err := parseExtFinalizeResponse(valid)
	if err != nil {
		t.Fatalf("parseExtFinalizeResponse: %v", err)
	}
	if result.TxID != strings.Repeat("a", 64) || result.RawTxHex != "00" || result.FeeZat != "10000" {
		t.Fatalf("unexpected result: %+v", result)
	}

	for _, field := range []string{"orchard_output_action_indices", "orchard_change_action_index"} {
		t.Run(field, func(t *testing.T) {
			withMapping := strings.TrimSuffix(valid, "}") + `,"` + field + `":null}`
			if _, err := parseExtFinalizeResponse(withMapping); err == nil {
				t.Fatalf("expected %s to be rejected", field)
			}
		})
	}
}

func TestDeriveUFVKBindsSeedNetworkAndAccount(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(bytesOf(64, 7))
	main, err := DeriveUFVK(context.Background(), seed, 8133, 0)
	if err != nil {
		t.Fatal(err)
	}
	regtest, err := DeriveUFVK(context.Background(), seed, 8135, 0)
	if err != nil {
		t.Fatal(err)
	}
	accountOne, err := DeriveUFVK(context.Background(), seed, 8133, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(main, "jview1") || !strings.HasPrefix(regtest, "jviewregtest1") {
		t.Fatalf("unexpected UFVK prefixes: main=%q regtest=%q", main, regtest)
	}
	if main == regtest || main == accountOne {
		t.Fatal("UFVK derivation is not bound to network/account")
	}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = value
	}
	return result
}
