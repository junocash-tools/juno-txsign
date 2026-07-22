package txsign

import (
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
