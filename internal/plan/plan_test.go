package plan

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-sdk-go/types"
)

func TestValidateTxPlanV0_RequiresVersionV0(t *testing.T) {
	plan := types.TxPlan{Version: types.V1}
	if err := ValidateTxPlanV0(plan); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBuildSendRequestJSON_ValidatesSeedBase64(t *testing.T) {
	path := make([]string, 32)
	for i := range path {
		path[i] = strings.Repeat("f", 64)
	}

	txplan := types.TxPlan{
		Version:      types.V0,
		Kind:         types.TxPlanKindWithdrawal,
		WalletID:     "hot",
		CoinType:     8135,
		Account:      0,
		Chain:        "regtest",
		BranchID:     0x4dec4df0,
		AnchorHeight: 1,
		Anchor:       strings.Repeat("a", 64),
		ExpiryHeight: 2,
		Outputs: []types.TxOutput{
			{ToAddress: "j1test", AmountZat: "1"},
		},
		ChangeAddress: "j1change",
		FeeZat:        "10000",
		Notes: []types.OrchardSpendNote{
			{
				NoteID:          strings.Repeat("1", 64) + ":0",
				ActionNullifier: strings.Repeat("b", 64),
				CMX:             strings.Repeat("c", 64),
				Position:        0,
				Path:            path,
				EphemeralKey:    strings.Repeat("d", 64),
				EncCiphertext:   strings.Repeat("e", 104),
			},
		},
	}

	if _, err := BuildSendRequestJSON(txplan, "not-base64"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateTxPlanV0_RejectsUnknownKind(t *testing.T) {
	plan := types.TxPlan{
		Version: types.V0,
		Kind:    types.TxPlanKind("nope"),
	}
	if err := ValidateTxPlanV0(plan); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateTxPlanV0_BindsNetworkToCoinType(t *testing.T) {
	tests := []struct {
		name     string
		chain    string
		coinType uint32
		wantErr  bool
	}{
		{name: "main", chain: "main", coinType: 8133},
		{name: "mainnet", chain: "mainnet", coinType: 8133},
		{name: "test", chain: "test", coinType: 8134},
		{name: "testnet", chain: "testnet", coinType: 8134},
		{name: "regtest", chain: "regtest", coinType: 8135},
		{name: "main_with_testnet_coin", chain: "main", coinType: 8134, wantErr: true},
		{name: "testnet_with_regtest_coin", chain: "testnet", coinType: 8135, wantErr: true},
		{name: "regtest_with_main_coin", chain: "regtest", coinType: 8133, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := validTxPlanV0()
			plan.Chain = tt.chain
			plan.CoinType = tt.coinType
			err := ValidateTxPlanV0(plan)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTxPlanV0() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTxPlanV0_RejectsMoreThan200Notes(t *testing.T) {
	plan := validTxPlanV0()
	note := plan.Notes[0]
	plan.Notes = make([]types.OrchardSpendNote, 200)
	for i := range plan.Notes {
		plan.Notes[i] = note
		plan.Notes[i].NoteID = fmt.Sprintf("%064x:0", i+1)
	}
	if err := ValidateTxPlanV0(plan); err != nil {
		t.Fatalf("200 notes rejected: %v", err)
	}

	plan.Notes = append(plan.Notes, note)
	if err := ValidateTxPlanV0(plan); err == nil || !strings.Contains(err.Error(), "notes too large") {
		t.Fatalf("expected notes-too-large error, got %v", err)
	}
}

func validTxPlanV0() types.TxPlan {
	path := make([]string, 32)
	for i := range path {
		path[i] = strings.Repeat("f", 64)
	}
	return types.TxPlan{
		Version:       types.V0,
		Kind:          types.TxPlanKindWithdrawal,
		WalletID:      "hot",
		CoinType:      8135,
		Chain:         "regtest",
		BranchID:      0x4dec4df0,
		AnchorHeight:  1,
		Anchor:        strings.Repeat("a", 64),
		ExpiryHeight:  2,
		Outputs:       []types.TxOutput{{ToAddress: "jregtest1recipient", AmountZat: "1"}},
		ChangeAddress: "jregtest1change",
		FeeZat:        "10000",
		Notes: []types.OrchardSpendNote{{
			NoteID:          strings.Repeat("1", 64) + ":0",
			ActionNullifier: strings.Repeat("b", 64),
			CMX:             strings.Repeat("c", 64),
			Path:            path,
			EphemeralKey:    strings.Repeat("d", 64),
			EncCiphertext:   strings.Repeat("e", 104),
		}},
	}
}

func TestBuildSendRequestJSON_AllowsMultipleOutputs(t *testing.T) {
	path := make([]string, 32)
	for i := range path {
		path[i] = strings.Repeat("f", 64)
	}

	txplan := types.TxPlan{
		Version:      types.V0,
		Kind:         types.TxPlanKindWithdrawal,
		WalletID:     "hot",
		CoinType:     8135,
		Account:      0,
		Chain:        "regtest",
		BranchID:     0x4dec4df0,
		AnchorHeight: 1,
		Anchor:       strings.Repeat("a", 64),
		ExpiryHeight: 2,
		Outputs: []types.TxOutput{
			{ToAddress: "j1a", AmountZat: "1"},
			{ToAddress: "j1b", AmountZat: "2"},
		},
		ChangeAddress: "j1change",
		FeeZat:        "15000",
		Notes: []types.OrchardSpendNote{
			{
				NoteID:          strings.Repeat("1", 64) + ":0",
				ActionNullifier: strings.Repeat("b", 64),
				CMX:             strings.Repeat("c", 64),
				Position:        0,
				Path:            path,
				EphemeralKey:    strings.Repeat("d", 64),
				EncCiphertext:   strings.Repeat("e", 104),
			},
		},
	}

	raw, err := BuildSendRequestJSON(txplan, strings.Repeat("a", 44))
	if err != nil {
		t.Fatalf("BuildSendRequestJSON: %v", err)
	}

	var got struct {
		Type    string           `json:"type"`
		Outputs []types.TxOutput `json:"outputs"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != "send" {
		t.Fatalf("type=%q", got.Type)
	}
	if len(got.Outputs) != 2 {
		t.Fatalf("outputs=%d want %d", len(got.Outputs), 2)
	}
}

func TestValidateTxPlanV0_RejectsInvalidNoteIDs(t *testing.T) {
	txid := strings.Repeat("1", 64)
	tests := []struct {
		name        string
		noteID      string
		wantMessage string
	}{
		{name: "missing", noteID: "", wantMessage: "note_id required"},
		{name: "surrounding whitespace", noteID: " " + txid + ":0", wantMessage: "lowercase txid:action_index"},
		{name: "uppercase txid", noteID: strings.Repeat("A", 64) + ":0", wantMessage: "lowercase txid:action_index"},
		{name: "nonhex txid", noteID: strings.Repeat("g", 64) + ":0", wantMessage: "lowercase txid:action_index"},
		{name: "short txid", noteID: strings.Repeat("1", 63) + ":0", wantMessage: "lowercase txid:action_index"},
		{name: "missing action index", noteID: txid + ":", wantMessage: "lowercase txid:action_index"},
		{name: "negative action index", noteID: txid + ":-1", wantMessage: "lowercase txid:action_index"},
		{name: "nondecimal action index", noteID: txid + ":a", wantMessage: "lowercase txid:action_index"},
		{name: "leading-zero action index", noteID: txid + ":00", wantMessage: "lowercase txid:action_index"},
		{name: "extra separator", noteID: txid + ":0:1", wantMessage: "lowercase txid:action_index"},
		{name: "uint32 overflow", noteID: txid + ":4294967296", wantMessage: "action_index must be uint32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := validTxPlanV0()
			plan.Notes[0].NoteID = tt.noteID
			err := ValidateTxPlanV0(plan)
			if err == nil || !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("ValidateTxPlanV0() error = %v, want message %q", err, tt.wantMessage)
			}
		})
	}
}

func TestValidateTxPlanV0_AcceptsMaximumNoteActionIndex(t *testing.T) {
	plan := validTxPlanV0()
	plan.Notes[0].NoteID = strings.Repeat("f", 64) + ":4294967295"

	if err := ValidateTxPlanV0(plan); err != nil {
		t.Fatalf("ValidateTxPlanV0() rejected uint32 maximum: %v", err)
	}
}

func TestValidateTxPlanV0_RejectsDuplicateNoteIDs(t *testing.T) {
	plan := validTxPlanV0()
	plan.Notes = append(plan.Notes, plan.Notes[0])

	err := ValidateTxPlanV0(plan)
	if err == nil || !strings.Contains(err.Error(), "notes[1].note_id duplicates notes[0].note_id") {
		t.Fatalf("ValidateTxPlanV0() error = %v, want duplicate note_id error", err)
	}
}

func TestBuildRequestsPreserveRequiredNoteID(t *testing.T) {
	plan := validTxPlanV0()
	tests := []struct {
		name  string
		build func() (string, error)
	}{
		{
			name: "direct signing",
			build: func() (string, error) {
				return BuildSendRequestJSON(plan, strings.Repeat("a", 44))
			},
		},
		{
			name: "external signing",
			build: func() (string, error) {
				return BuildExtPrepareRequestJSON(plan, "jview1test")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := tt.build()
			if err != nil {
				t.Fatalf("build request: %v", err)
			}

			var request struct {
				Notes []map[string]any `json:"notes"`
			}
			if err := json.Unmarshal([]byte(raw), &request); err != nil {
				t.Fatalf("unmarshal request: %v", err)
			}
			if len(request.Notes) != 1 {
				t.Fatalf("notes=%d want=1", len(request.Notes))
			}
			if got := request.Notes[0]["note_id"]; got != plan.Notes[0].NoteID {
				t.Fatalf("note_id=%v want=%q", got, plan.Notes[0].NoteID)
			}
		})
	}
}
