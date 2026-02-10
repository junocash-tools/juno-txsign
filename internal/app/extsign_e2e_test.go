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

	"github.com/Abdullah1738/juno-txsign/internal/testutil/junocashdutil"
)

func TestE2E_ExtPrepareFinalizeThenBroadcastAndMine(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

	ufvk := exportUFVK(t, jd, toAddr)
	seeds := seedCandidatesFromNode(t, jd)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tmp := t.TempDir()
	txplanPath := filepath.Join(tmp, "txplan.json")
	preparedPath := filepath.Join(tmp, "prepared.json")
	requestsPath := filepath.Join(tmp, "requests.json")
	seedPath := filepath.Join(tmp, "seed.base64")
	sigsPath := filepath.Join(tmp, "sigs.json")

	txbuild := txbuildBin(t)
	plan := writeTxPlanSendViaTxbuild(t, ctx, txbuild, jd, txplanPath, toAddr, "1000000", changeAddr)
	if err := validatePlanBasics(plan); err != nil {
		t.Fatalf("txplan invalid: %v", err)
	}

	txsignBin := filepath.Join(repoRoot(), "bin", "juno-txsign")
	signerBin := spendAuthSignerBin(t)

	prepare := exec.CommandContext(ctx, txsignBin,
		"ext-prepare",
		"--txplan", txplanPath,
		"--ufvk", ufvk,
		"--out-prepared", preparedPath,
		"--out-requests", requestsPath,
	)
	if out, err := prepare.Output(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("juno-txsign ext-prepare: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("juno-txsign ext-prepare: %v", err)
	}

	requestsRaw, err := os.ReadFile(requestsPath)
	if err != nil {
		t.Fatalf("read signing requests: %v", err)
	}
	var reqs struct {
		Version  string `json:"version"`
		Requests []any  `json:"requests"`
	}
	if err := json.Unmarshal(requestsRaw, &reqs); err != nil {
		t.Fatalf("signing requests json invalid: %v", err)
	}
	if strings.TrimSpace(reqs.Version) == "" || len(reqs.Requests) == 0 {
		t.Fatalf("signing requests empty")
	}
	if len(reqs.Requests) != len(plan.Notes) {
		t.Fatalf("signing request count mismatch: got %d want %d", len(reqs.Requests), len(plan.Notes))
	}

	type signResult struct {
		TxID                       string
		RawTxHex                   string
		OrchardOutputActionIndices []uint32
		OrchardChangeActionIndex   *uint32
	}

	var (
		res     signResult
		lastErr error
	)
	for _, seed := range seeds {
		if err := os.WriteFile(seedPath, []byte(seed+"\n"), 0o600); err != nil {
			t.Fatalf("write seed: %v", err)
		}

		if err := runSpendAuthSigner(t, ctx, signerBin, requestsPath, seedPath, sigsPath, plan.CoinType, plan.Account); err != nil {
			lastErr = err
			continue
		}

		finalize := exec.CommandContext(ctx, txsignBin,
			"ext-finalize",
			"--prepared-tx", preparedPath,
			"--sigs", sigsPath,
			"--json",
			"--action-indices",
		)
		out, err := finalize.Output()
		if err != nil {
			lastErr = err
			continue
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
			lastErr = errors.New("unexpected status")
			continue
		}
		if resp.Data.TxID == "" || resp.Data.RawTxHex == "" {
			lastErr = errors.New("missing tx")
			continue
		}
		res = signResult{
			TxID:                       resp.Data.TxID,
			RawTxHex:                   resp.Data.RawTxHex,
			OrchardOutputActionIndices: resp.Data.OrchardOutputActionIndices,
			OrchardChangeActionIndex:   resp.Data.OrchardChangeActionIndex,
		}
		lastErr = nil
		goto ok
	}
ok:
	if lastErr != nil {
		t.Fatalf("ext-finalize: %v", lastErr)
	}

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

	waitSpendableOrchardNoteNot(t, jd, plan.Notes[0].NoteID)

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
