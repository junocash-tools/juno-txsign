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
	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
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

	signWithAnySeed := func(t *testing.T, plan types.TxPlan) (string, string) {
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

			cmd := exec.CommandContext(ctx, bin, "sign", "--txplan", txplanPath, "--seed-file", seedPath, "--json")
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
				TxID     string `json:"txid"`
				RawTxHex string `json:"raw_tx_hex"`
			} `json:"data"`
		}
		decodeJSON(t, out, &resp)
		if resp.Status != "ok" {
			t.Fatalf("unexpected status")
		}
		if resp.Data.TxID == "" || resp.Data.RawTxHex == "" {
			t.Fatalf("missing tx")
		}
		return resp.Data.TxID, resp.Data.RawTxHex
	}

	broadcastMineAndAssert := func(t *testing.T, txid, rawTxHex, spentNoteID string) {
		t.Helper()

		var acceptedTxID string
		if err := rpc.Call(ctx, "sendrawtransaction", []any{rawTxHex}, &acceptedTxID); err != nil {
			t.Fatalf("sendrawtransaction: %v", err)
		}
		if !strings.EqualFold(acceptedTxID, txid) {
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
			if strings.EqualFold(got, txid) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tx not mined")
		}

		waitWalletTx(t, jd, txid)
		waitSpendableOrchardNoteNot(t, jd, spentNoteID)
	}

	t.Run("withdrawal", func(t *testing.T) {
		plan := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)
		txid, raw := signWithAnySeed(t, plan)
		broadcastMineAndAssert(t, txid, raw, plan.Notes[0].NoteID)
	})

	t.Run("multi_output", func(t *testing.T) {
		plan := buildSingleNoteSendPlan(t, rpc, jd, []types.TxOutput{
			{ToAddress: toAddr, AmountZat: "1000000"},
			{ToAddress: toAddr, AmountZat: "2000000"},
		}, changeAddr, types.TxPlanKindWithdrawal)
		txid, raw := signWithAnySeed(t, plan)
		broadcastMineAndAssert(t, txid, raw, plan.Notes[0].NoteID)
	})

	t.Run("sweep", func(t *testing.T) {
		plan := buildSingleNoteSweepPlan(t, rpc, jd, toAddr, toAddr)
		txid, raw := signWithAnySeed(t, plan)
		broadcastMineAndAssert(t, txid, raw, plan.Notes[0].NoteID)
	})
}

func mineOne(ctx context.Context, jd *containers.Junocashd) error {
	_, err := jd.ExecCLI(ctx, "generate", "1")
	return err
}
