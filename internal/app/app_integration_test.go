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

	signOK := func(t *testing.T, plan types.TxPlan) {
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
	}

	t.Run("withdrawal", func(t *testing.T) { signOK(t, planWithdrawal) })
	t.Run("multi_output", func(t *testing.T) { signOK(t, planMultiOutput) })
	t.Run("sweep", func(t *testing.T) { signOK(t, planSweep) })
}
