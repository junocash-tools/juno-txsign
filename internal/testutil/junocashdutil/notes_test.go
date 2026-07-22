package junocashdutil

import (
	"strings"
	"testing"
)

func TestParseUnspentOrchardPreservesAccountAndAddress(t *testing.T) {
	raw := []byte(`[
		{"txid":"AA","pool":"orchard","outindex":0,"spendable":true,"account":0,"address":"uregtest0","amount":0.00000001},
		{"txid":"BB","pool":"orchard","outindex":2,"spendable":true,"account":1,"address":"uregtest1","amount":1.23456789},
		{"txid":"CC","pool":"sapling","outindex":3,"spendable":true,"account":1,"address":"zs1","amount":2},
		{"txid":"DD","pool":"orchard","outindex":4,"spendable":false,"account":1,"address":"uregtest1","amount":3},
		{"txid":"EE","pool":"orchard","outindex":5,"spendable":true,"account":2,"amount":4}
	]`)

	notes, err := parseUnspentOrchard(raw)
	if err != nil {
		t.Fatalf("parseUnspentOrchard: %v", err)
	}
	if len(notes) != 3 {
		t.Fatalf("notes = %d, want 3", len(notes))
	}
	if got := notes[0]; got.TxID != "aa" || got.OutIndex != 0 || got.AmountZat != 1 || got.Account != 0 || got.Address != "uregtest0" {
		t.Fatalf("account 0 note = %+v", got)
	}
	if got := notes[1]; got.TxID != "bb" || got.OutIndex != 2 || got.AmountZat != 123456789 || got.Account != 1 || got.Address != "uregtest1" {
		t.Fatalf("account 1 note = %+v", got)
	}
	if got := notes[2]; got.TxID != "ee" || got.OutIndex != 5 || got.AmountZat != 400000000 || got.Account != 2 || got.Address != "" {
		t.Fatalf("internal recipient note = %+v", got)
	}
}

func TestParseUnspentOrchardRejectsMissingAccount(t *testing.T) {
	raw := []byte(`[{"txid":"AA","pool":"orchard","outindex":0,"spendable":true,"address":"uregtest0","amount":1}]`)

	_, err := parseUnspentOrchard(raw)
	if err == nil || !strings.Contains(err.Error(), "missing account") {
		t.Fatalf("error = %v, want missing account", err)
	}
}
