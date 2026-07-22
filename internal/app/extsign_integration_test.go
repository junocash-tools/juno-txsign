//go:build integration

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestIntegration_ExtPrepareThenFinalize(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)
	foreignChangeAddr := newUnifiedAddressForDifferentAccount(t, jd, 0).Address

	ufvk := exportUFVK(t, jd, toAddr)
	seeds := seedCandidatesFromNode(t, jd)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tmp := t.TempDir()
	txplanPath := filepath.Join(tmp, "txplan.json")
	requestsPath := filepath.Join(tmp, "requests.json")
	seedPath := filepath.Join(tmp, "seed.base64")
	sigsPath := filepath.Join(tmp, "sigs.json")

	txbuild := txbuildBin(t)
	plan := writeTxPlanSendViaTxbuild(t, ctx, txbuild, jd, txplanPath, toAddr, "1000000", changeAddr)

	if err := validatePlanBasics(plan); err != nil {
		t.Fatalf("txplan invalid: %v", err)
	}

	t.Run("rejects_foreign_change_address", func(t *testing.T) {
		foreignPlan := plan
		foreignPlan.ChangeAddress = foreignChangeAddr
		_, err := txsign.ExtPrepare(ctx, foreignPlan, ufvk)
		if err == nil || !strings.Contains(err.Error(), "change_address_not_owned") {
			t.Fatalf("expected change ownership error, got %v", err)
		}
	})

	t.Run("allows_foreign_destination_without_change", func(t *testing.T) {
		sweepPlan := buildSingleNoteSweepPlan(t, rpc, jd, foreignChangeAddr, foreignChangeAddr)
		prepared, err := txsign.ExtPrepare(ctx, sweepPlan, ufvk)
		if err != nil {
			t.Fatalf("ext-prepare no-change sweep: %v", err)
		}
		var envelope struct {
			OrchardChangeActionIndex *uint32 `json:"orchard_change_action_index"`
		}
		if err := json.Unmarshal(prepared.PreparedTx, &envelope); err != nil {
			t.Fatalf("decode prepared tx: %v", err)
		}
		if envelope.OrchardChangeActionIndex != nil {
			t.Fatalf("unexpected change action index: %d", *envelope.OrchardChangeActionIndex)
		}
	})

	t.Run("rejects_implicit_201st_output", func(t *testing.T) {
		tooMany := plan
		tooMany.Outputs = make([]types.TxOutput, 200)
		for i := range tooMany.Outputs {
			tooMany.Outputs[i] = types.TxOutput{ToAddress: toAddr, AmountZat: "1"}
		}
		tooMany.FeeZat = "1000000"
		_, err := txsign.ExtPrepare(ctx, tooMany, ufvk)
		if err == nil || !strings.Contains(err.Error(), "outputs_invalid") {
			t.Fatalf("expected total-output limit error, got %v", err)
		}
	})

	res, err := txsign.ExtPrepare(ctx, plan, ufvk)
	if err != nil {
		t.Fatalf("ext-prepare: %v", err)
	}

	if len(res.SigningRequests.Requests) != len(plan.Notes) {
		t.Fatalf("signing request count mismatch: got %d want %d", len(res.SigningRequests.Requests), len(plan.Notes))
	}
	var preparedMetadata struct {
		OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices"`
		OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index"`
	}
	if err := json.Unmarshal(res.PreparedTx, &preparedMetadata); err != nil {
		t.Fatalf("decode prepared tx metadata: %v", err)
	}

	writeSigningRequests(t, requestsPath, res.SigningRequests)

	signer := spendAuthSignerBin(t)

	var (
		finalized txsign.ExtFinalizeResult
		lastErr   error
	)
	for _, seed := range seeds {
		if err := os.WriteFile(seedPath, []byte(seed+"\n"), 0o600); err != nil {
			t.Fatalf("write seed: %v", err)
		}

		if err := runSpendAuthSigner(t, ctx, signer, requestsPath, seedPath, sigsPath, plan.CoinType, plan.Account); err != nil {
			lastErr = err
			continue
		}

		raw, err := os.ReadFile(sigsPath)
		if err != nil {
			t.Fatalf("read sigs: %v", err)
		}
		var sigs txsign.SpendAuthSigSubmission
		if err := json.Unmarshal(raw, &sigs); err != nil {
			lastErr = err
			continue
		}

		r, err := txsign.ExtFinalize(ctx, res.PreparedTx, sigs)
		if err == nil {
			finalized = r
			lastErr = nil
			goto ok
		}
		lastErr = err
	}
ok:
	if lastErr != nil {
		t.Fatalf("ext-finalize: %v", lastErr)
	}

	if finalized.TxID == "" || len(finalized.TxID) != 64 {
		t.Fatalf("txid invalid")
	}
	if finalized.RawTxHex == "" {
		t.Fatalf("raw tx empty")
	}
	if _, err := hex.DecodeString(finalized.RawTxHex); err != nil {
		t.Fatalf("raw tx hex invalid")
	}

	if len(preparedMetadata.OrchardOutputActionIndices) != len(plan.Outputs) {
		t.Fatalf("orchard output index count mismatch: got %d want %d", len(preparedMetadata.OrchardOutputActionIndices), len(plan.Outputs))
	}

	var decoded struct {
		Orchard struct {
			Actions []any `json:"actions"`
		} `json:"orchard"`
	}
	if err := rpc.Call(ctx, "decoderawtransaction", []any{finalized.RawTxHex}, &decoded); err != nil {
		t.Fatalf("decoderawtransaction: %v", err)
	}

	// Expected action count matches ZIP-317 fee model:
	// actions = max(2, max(spends, outputs)), where outputs includes change.
	outputCount := len(plan.Outputs)
	if preparedMetadata.OrchardChangeActionIndex != nil {
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
	for _, idx := range preparedMetadata.OrchardOutputActionIndices {
		if int(idx) >= len(decoded.Orchard.Actions) {
			t.Fatalf("orchard output action index out of range: %d", idx)
		}
		if _, ok := seen[idx]; ok {
			t.Fatalf("duplicate orchard output action index: %d", idx)
		}
		seen[idx] = struct{}{}
	}
	if preparedMetadata.OrchardChangeActionIndex != nil {
		idx := *preparedMetadata.OrchardChangeActionIndex
		if int(idx) >= len(decoded.Orchard.Actions) {
			t.Fatalf("orchard change action index out of range: %d", idx)
		}
		if _, ok := seen[idx]; ok {
			t.Fatalf("duplicate orchard change action index: %d", idx)
		}
	}

	// Sanity: plan fee must be parseable and match finalized fee field format.
	if _, err := strconv.ParseUint(strings.TrimSpace(plan.FeeZat), 10, 64); err != nil {
		t.Fatalf("plan fee invalid")
	}
	if _, err := strconv.ParseUint(strings.TrimSpace(finalized.FeeZat), 10, 64); err != nil {
		t.Fatalf("finalized fee invalid")
	}
}
