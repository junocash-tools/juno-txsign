//go:build integration

package app

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestIntegration_SignAndBuildRawTx(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

	seeds := seedCandidatesFromNode(t, jd)
	planWithdrawal := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)
	planMultiOutput := buildSingleNoteSendPlan(t, rpc, jd, []types.TxOutput{
		{ToAddress: toAddr, AmountZat: "1000000"},
		{ToAddress: toAddr, AmountZat: "2000000"},
	}, changeAddr, types.TxPlanKindWithdrawal)
	planSweep := buildSingleNoteSweepPlan(t, rpc, jd, toAddr, toAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	signOK := func(t *testing.T, plan types.TxPlan, expectChange bool) {
		t.Helper()
		var (
			res     txsign.Result
			lastErr error
		)
		for _, seed := range seeds {
			r, err := txsign.Sign(ctx, plan, seed)
			if err == nil {
				res = r
				lastErr = nil
				goto ok
			}
			lastErr = err
		}
	ok:
		if lastErr != nil {
			t.Fatalf("sign: %v", lastErr)
		}
		if res.TxID == "" || len(res.TxID) != 64 {
			t.Fatalf("txid invalid")
		}
		if res.RawTxHex == "" {
			t.Fatalf("raw tx empty")
		}
		if _, err := hex.DecodeString(res.RawTxHex); err != nil {
			t.Fatalf("raw tx hex invalid")
		}

		if len(res.OrchardOutputActionIndices) != len(plan.Outputs) {
			t.Fatalf("orchard output index count mismatch: got %d want %d", len(res.OrchardOutputActionIndices), len(plan.Outputs))
		}
		if (res.OrchardChangeActionIndex != nil) != expectChange {
			t.Fatalf("change action index mismatch: got %v want %v", res.OrchardChangeActionIndex != nil, expectChange)
		}

		var decoded struct {
			Orchard struct {
				Actions []any `json:"actions"`
			} `json:"orchard"`
		}
		if err := rpc.Call(ctx, "decoderawtransaction", []any{res.RawTxHex}, &decoded); err != nil {
			t.Fatalf("decoderawtransaction: %v", err)
		}

		outputCount := len(plan.Outputs)
		if res.OrchardChangeActionIndex != nil {
			outputCount++
		}
		wantActions := outputCount
		if len(plan.Notes) > wantActions {
			wantActions = len(plan.Notes)
		}
		if wantActions < 2 {
			wantActions = 2
		}
		if len(decoded.Orchard.Actions) != wantActions {
			t.Fatalf("orchard action count mismatch: got %d want %d", len(decoded.Orchard.Actions), wantActions)
		}

		seen := make(map[uint32]struct{})
		for _, idx := range res.OrchardOutputActionIndices {
			if int(idx) >= len(decoded.Orchard.Actions) {
				t.Fatalf("orchard output action index out of range: %d", idx)
			}
			if _, ok := seen[idx]; ok {
				t.Fatalf("duplicate orchard output action index: %d", idx)
			}
			seen[idx] = struct{}{}
		}
		if res.OrchardChangeActionIndex != nil {
			idx := *res.OrchardChangeActionIndex
			if int(idx) >= len(decoded.Orchard.Actions) {
				t.Fatalf("orchard change action index out of range: %d", idx)
			}
			if _, ok := seen[idx]; ok {
				t.Fatalf("duplicate orchard change action index: %d", idx)
			}
		}
	}

	t.Run("withdrawal", func(t *testing.T) { signOK(t, planWithdrawal, true) })
	t.Run("multi_output", func(t *testing.T) { signOK(t, planMultiOutput, true) })
	t.Run("sweep", func(t *testing.T) { signOK(t, planSweep, false) })
}
