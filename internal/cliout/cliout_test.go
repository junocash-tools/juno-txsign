package cliout

import "testing"

func TestSignJSONData_ActionIndicesGate(t *testing.T) {
	change := uint32(7)
	out := SignOutput{
		TxID:                       "txid",
		RawTxHex:                   "rawtx",
		FeeZat:                     "10000",
		OrchardOutputActionIndices: []uint32{3, 1},
		OrchardChangeActionIndex:   &change,
	}

	without := SignJSONData(out, false)
	if _, ok := without["orchard_output_action_indices"]; ok {
		t.Fatalf("expected orchard_output_action_indices to be omitted")
	}
	if _, ok := without["orchard_change_action_index"]; ok {
		t.Fatalf("expected orchard_change_action_index to be omitted")
	}

	with := SignJSONData(out, true)
	if got, ok := with["orchard_output_action_indices"]; !ok || got == nil {
		t.Fatalf("expected orchard_output_action_indices to be present")
	}
	if got, ok := with["orchard_change_action_index"]; !ok || got == nil {
		t.Fatalf("expected orchard_change_action_index to be present")
	}
}
