package plan

import (
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
