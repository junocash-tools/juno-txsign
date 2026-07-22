package plan

import (
	"encoding/json"
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

func TestBuildExtPrepareRequestJSON_OmitsOptionalEmptyNoteID(t *testing.T) {
	raw, err := BuildExtPrepareRequestJSON(validTxPlanV0(), "jview1test")
	if err != nil {
		t.Fatalf("BuildExtPrepareRequestJSON: %v", err)
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
	if _, ok := request.Notes[0]["note_id"]; ok {
		t.Fatal("empty diagnostic note_id must be omitted")
	}
}
