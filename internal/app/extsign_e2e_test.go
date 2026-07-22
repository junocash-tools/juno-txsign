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
	preparedRaw, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared tx: %v", err)
	}
	var preparedMetadata struct {
		OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices"`
		OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index"`
	}
	if err := json.Unmarshal(preparedRaw, &preparedMetadata); err != nil {
		t.Fatalf("prepared tx JSON invalid: %v", err)
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
		TxID     string
		RawTxHex string
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
		)
		out, err := finalize.Output()
		if err != nil {
			lastErr = err
			continue
		}

		var resp struct {
			Status string `json:"status"`
			Data   struct {
				TxID     string `json:"txid"`
				RawTxHex string `json:"raw_tx_hex"`
			} `json:"data"`
		}
		decodeJSON(t, out, &resp)
		var rawEnvelope map[string]any
		decodeJSON(t, out, &rawEnvelope)
		data, ok := rawEnvelope["data"].(map[string]any)
		if !ok {
			lastErr = errors.New("missing data")
			continue
		}
		if _, ok := data["orchard_output_action_indices"]; ok {
			lastErr = errors.New("ext-finalize echoed output action indices")
			continue
		}
		if _, ok := data["orchard_change_action_index"]; ok {
			lastErr = errors.New("ext-finalize echoed change action index")
			continue
		}
		if resp.Status != "ok" {
			lastErr = errors.New("unexpected status")
			continue
		}
		if resp.Data.TxID == "" || resp.Data.RawTxHex == "" {
			lastErr = errors.New("missing tx")
			continue
		}
		res = signResult{
			TxID:     resp.Data.TxID,
			RawTxHex: resp.Data.RawTxHex,
		}
		lastErr = nil
		goto ok
	}
ok:
	if lastErr != nil {
		t.Fatalf("ext-finalize: %v", lastErr)
	}
	assertDecodedOrchardTransaction(t, ctx, rpc, res.RawTxHex, res.TxID, plan, preparedMetadata.OrchardOutputActionIndices, preparedMetadata.OrchardChangeActionIndex)
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

	outputAccounts := make([]uint32, len(plan.Outputs))
	waitForOrchardPlanEffects(t, ctx, jd, res.TxID, 0, totalInput, plan, preparedMetadata.OrchardOutputActionIndices, outputAccounts, preparedMetadata.OrchardChangeActionIndex, 0)
}
