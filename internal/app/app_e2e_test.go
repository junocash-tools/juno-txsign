//go:build e2e

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/junocashdutil"
)

func TestE2E_SignThenBroadcastAndMine(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

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

	broadcastMineAndAssert := func(t *testing.T, plan types.TxPlan, res signResult, spentNoteID string) {
		t.Helper()

		var acceptedTxID string
		if err := rpc.Call(ctx, "sendrawtransaction", []any{res.RawTxHex}, &acceptedTxID); err != nil {
			t.Fatalf("sendrawtransaction: %v", err)
		}
		if !strings.EqualFold(acceptedTxID, res.TxID) {
			t.Fatalf("txid mismatch")
		}

		if err := mineOne(ctx, jd); err != nil {
			t.Fatalf("mine: %v", err)
		}

		var height int64
		if err := rpc.Call(ctx, "getblockcount", nil, &height); err != nil {
			t.Fatalf("getblockcount: %v", err)
		}
		hash, err := rpc.GetBlockHash(ctx, height)
		if err != nil {
			t.Fatalf("getblockhash: %v", err)
		}

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

		waitSpendableOrchardNoteNot(t, jd, spentNoteID)

		// Verify Orchard action indices match the notes the node wallet sees for this tx.
		if len(res.OrchardOutputActionIndices) != len(plan.Outputs) {
			t.Fatalf("orchard output index count mismatch: got %d want %d", len(res.OrchardOutputActionIndices), len(plan.Outputs))
		}

		notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, 0)
		if err != nil {
			t.Fatalf("z_listunspent: %v", err)
		}
		var txNotes []junocashdutil.UnspentOrchardNote
		for _, n := range notes {
			if strings.EqualFold(n.TxID, res.TxID) {
				txNotes = append(txNotes, n)
			}
		}
		if len(txNotes) == 0 {
			t.Fatalf("expected unspent orchard notes for tx")
		}

		for i := range plan.Outputs {
			amt, err := strconv.ParseUint(strings.TrimSpace(plan.Outputs[i].AmountZat), 10, 64)
			if err != nil {
				t.Fatalf("outputs[%d].amount_zat invalid: %v", i, err)
			}
			wantIdx := res.OrchardOutputActionIndices[i]

			var ok bool
			for _, n := range txNotes {
				if n.OutIndex == wantIdx && n.AmountZat == amt {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("missing orchard note for outputs[%d] at action_index=%d", i, wantIdx)
			}
		}

		if res.OrchardChangeActionIndex != nil {
			wantIdx := *res.OrchardChangeActionIndex
			var ok bool
			for _, n := range txNotes {
				if n.OutIndex == wantIdx {
					if n.AmountZat == 0 {
						t.Fatalf("change note amount is 0")
					}
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("missing orchard change note at action_index=%d", wantIdx)
			}
		}
	}

	t.Run("withdrawal", func(t *testing.T) {
		plan := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)
		res := signWithAnySeed(t, plan)
		if res.OrchardChangeActionIndex == nil {
			t.Fatalf("expected change output")
		}
		broadcastMineAndAssert(t, plan, res, plan.Notes[0].NoteID)
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
		broadcastMineAndAssert(t, plan, res, plan.Notes[0].NoteID)
	})

	t.Run("sweep", func(t *testing.T) {
		plan := buildSingleNoteSweepPlan(t, rpc, jd, toAddr, toAddr)
		res := signWithAnySeed(t, plan)
		broadcastMineAndAssert(t, plan, res, plan.Notes[0].NoteID)
		if res.OrchardChangeActionIndex != nil {
			t.Fatalf("expected no change output")
		}
	})
}

func mineOne(ctx context.Context, jd *containers.Junocashd) error {
	_, err := jd.ExecCLI(ctx, "generate", "1")
	return err
}
