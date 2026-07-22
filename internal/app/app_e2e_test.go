//go:build e2e

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
)

func TestE2E_SignThenBroadcastAndMine(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)
	foreignDestination := newUnifiedAddressForDifferentAccount(t, jd, 0)

	seeds := seedCandidatesFromNode(t, jd)

	tmp := t.TempDir()
	txplanPath := filepath.Join(tmp, "txplan.json")
	seedPath := filepath.Join(tmp, "seed.base64")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	bin := filepath.Join(repoRoot(), "bin", "juno-txsign")

	type signResult struct {
		TxID                       string
		RawTxHex                   string
		OrchardOutputActionIndices []uint32
		OrchardChangeActionIndex   *uint32
	}

	signWithAnySeed := func(t *testing.T, plan types.TxPlan) signResult {
		t.Helper()
		var (
			out     []byte
			lastErr error
		)
		for _, seed := range seeds {
			planJSON, err := json.Marshal(plan)
			if err != nil {
				t.Fatalf("marshal txplan: %v", err)
			}
			if err := os.WriteFile(txplanPath, append(planJSON, '\n'), 0o600); err != nil {
				t.Fatalf("write txplan: %v", err)
			}
			if err := os.WriteFile(seedPath, []byte(seed+"\n"), 0o600); err != nil {
				t.Fatalf("write seed: %v", err)
			}

			cmd := exec.CommandContext(ctx, bin, "sign", "--txplan", txplanPath, "--seed-file", seedPath, "--json", "--action-indices")
			b, err := cmd.Output()
			if err == nil {
				out = b
				lastErr = nil
				goto ok
			}
			lastErr = err
		}
	ok:
		if lastErr != nil {
			var ee *exec.ExitError
			if errors.As(lastErr, &ee) {
				t.Fatalf("juno-txsign: %s", strings.TrimSpace(string(ee.Stderr)))
			}
			t.Fatalf("juno-txsign: %v", lastErr)
		}

		var resp struct {
			Status string `json:"status"`
			Data   struct {
				TxID                       string   `json:"txid"`
				RawTxHex                   string   `json:"raw_tx_hex"`
				OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices"`
				OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index"`
			} `json:"data"`
		}
		decodeJSON(t, out, &resp)
		if resp.Status != "ok" {
			t.Fatalf("unexpected status")
		}
		if resp.Data.TxID == "" || resp.Data.RawTxHex == "" {
			t.Fatalf("missing tx")
		}
		return signResult{
			TxID:                       resp.Data.TxID,
			RawTxHex:                   resp.Data.RawTxHex,
			OrchardOutputActionIndices: resp.Data.OrchardOutputActionIndices,
			OrchardChangeActionIndex:   resp.Data.OrchardChangeActionIndex,
		}
	}

	broadcastMineAndAssert := func(t *testing.T, plan types.TxPlan, res signResult, outputAccounts []uint32) {
		t.Helper()
		assertDecodedOrchardTransaction(t, ctx, rpc, res.RawTxHex, res.TxID, plan, res.OrchardOutputActionIndices, res.OrchardChangeActionIndex)
		totalInput := orchardPlanInputValue(t, ctx, jd, 0, plan)

		var acceptedTxID string
		if err := rpc.Call(ctx, "sendrawtransaction", []any{res.RawTxHex}, &acceptedTxID); err != nil {
			t.Fatalf("sendrawtransaction: %v", err)
		}
		if !strings.EqualFold(acceptedTxID, res.TxID) {
			t.Fatalf("txid mismatch")
		}

		hash := mineUntilTxConfirmed(t, rpc, jd, res.TxID)

		var blk struct {
			Tx []string `json:"tx"`
		}
		if err := rpc.Call(ctx, "getblock", []any{hash, 1}, &blk); err != nil {
			t.Fatalf("getblock: %v", err)
		}

		var found bool
		for _, got := range blk.Tx {
			if strings.EqualFold(got, res.TxID) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tx not mined")
		}

		waitForOrchardPlanEffects(t, ctx, jd, res.TxID, 0, totalInput, plan, res.OrchardOutputActionIndices, outputAccounts, res.OrchardChangeActionIndex, 0)
	}

	t.Run("withdrawal", func(t *testing.T) {
		plan := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)
		res := signWithAnySeed(t, plan)
		if res.OrchardChangeActionIndex == nil {
			t.Fatalf("expected change output")
		}
		broadcastMineAndAssert(t, plan, res, []uint32{0})
	})

	t.Run("multi_output", func(t *testing.T) {
		plan := buildSingleNoteSendPlan(t, rpc, jd, []types.TxOutput{
			{ToAddress: toAddr, AmountZat: "1000000"},
			{ToAddress: toAddr, AmountZat: "2000000"},
		}, changeAddr, types.TxPlanKindWithdrawal)
		res := signWithAnySeed(t, plan)
		if res.OrchardChangeActionIndex == nil {
			t.Fatalf("expected change output")
		}
		broadcastMineAndAssert(t, plan, res, []uint32{0, 0})
	})

	t.Run("sweep", func(t *testing.T) {
		plan := buildSingleNoteSweepPlan(t, rpc, jd, foreignDestination.Address, foreignDestination.Address)
		res := signWithAnySeed(t, plan)
		if res.OrchardChangeActionIndex != nil {
			t.Fatalf("expected no change output")
		}
		broadcastMineAndAssert(t, plan, res, []uint32{foreignDestination.Account})
	})
}
