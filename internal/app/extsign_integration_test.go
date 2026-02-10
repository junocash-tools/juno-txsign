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

	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestIntegration_ExtPrepareThenFinalize(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

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

	res, err := txsign.ExtPrepare(ctx, plan, ufvk)
	if err != nil {
		t.Fatalf("ext-prepare: %v", err)
	}

	if len(res.SigningRequests.Requests) != len(plan.Notes) {
		t.Fatalf("signing request count mismatch: got %d want %d", len(res.SigningRequests.Requests), len(plan.Notes))
	}

	writeSigningRequests(t, requestsPath, res.SigningRequests)

	signer := spendAuthSignerBin(t)

	var (
		finalized txsign.Result
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

	if len(finalized.OrchardOutputActionIndices) != len(plan.Outputs) {
		t.Fatalf("orchard output index count mismatch: got %d want %d", len(finalized.OrchardOutputActionIndices), len(plan.Outputs))
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
	if finalized.OrchardChangeActionIndex != nil {
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
	for _, idx := range finalized.OrchardOutputActionIndices {
		if int(idx) >= len(decoded.Orchard.Actions) {
			t.Fatalf("orchard output action index out of range: %d", idx)
		}
		if _, ok := seen[idx]; ok {
			t.Fatalf("duplicate orchard output action index: %d", idx)
		}
		seen[idx] = struct{}{}
	}
	if finalized.OrchardChangeActionIndex != nil {
		idx := *finalized.OrchardChangeActionIndex
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
