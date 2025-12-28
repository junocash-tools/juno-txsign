//go:build integration || e2e

package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/junocashd"
	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/chain"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/junocashdutil"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/mnemonic"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/witness"
)

func coinTypeForChain(chain string) uint32 {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "regtest":
		return 8135
	case "test", "testnet":
		return 8134
	default:
		return 8133
	}
}

func startJunocashd(t *testing.T) (*containers.Junocashd, *junocashd.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	jd, err := containers.StartJunocashd(ctx)
	if err != nil {
		t.Fatalf("start junocashd: %v", err)
	}
	t.Cleanup(func() {
		termCtx, termCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer termCancel()
		_ = jd.Terminate(termCtx)
	})

	rpc := junocashd.New(jd.RPCURL, jd.RPCUser, jd.RPCPassword)
	return jd, rpc
}

func mineAndShieldOnce(t *testing.T, jd *containers.Junocashd, orchardAddr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := junocashdutil.GenerateBlocks(ctx, jd, 101); err != nil {
		t.Fatalf("generate: %v", err)
	}

	txid, err := junocashdutil.ShieldCoinbaseTo(ctx, jd, orchardAddr)
	if err != nil {
		t.Fatalf("shield coinbase: %v", err)
	}

	waitWalletTx(t, jd, txid)

	if err := junocashdutil.GenerateBlocks(ctx, jd, 2); err != nil {
		t.Fatalf("confirm blocks: %v", err)
	}

	waitSpendableOrchardNote(t, jd)
}

func waitWalletTx(t *testing.T, jd *containers.Junocashd, txid string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		_, err := jd.ExecCLI(ctx, "gettransaction", txid)
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("tx not seen by wallet")
		case <-ticker.C:
		}
	}
}

func waitSpendableOrchardNote(t *testing.T, jd *containers.Junocashd) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, 0)
		if err == nil && len(notes) > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("orchard note not spendable")
		case <-ticker.C:
		}
	}
}

func waitSpendableOrchardNoteNot(t *testing.T, jd *containers.Junocashd, excludeNoteID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	excludeNoteID = strings.TrimSpace(excludeNoteID)

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, 0)
		if err == nil && len(notes) > 0 {
			var excludedPresent bool
			var otherPresent bool
			for _, n := range notes {
				id := fmt.Sprintf("%s:%d", n.TxID, n.OutIndex)
				if excludeNoteID != "" && strings.EqualFold(id, excludeNoteID) {
					excludedPresent = true
					continue
				}
				otherPresent = true
			}
			if !excludedPresent && otherPresent {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("orchard note not spendable")
		case <-ticker.C:
		}
	}
}

func seedCandidatesFromNode(t *testing.T, jd *containers.Junocashd) []string {
	t.Helper()
	ctx := context.Background()

	raw, err := jd.ExecCLI(ctx, "z_getseedphrase")
	if err != nil {
		t.Fatalf("z_getseedphrase: %v", err)
	}
	mn, err := mnemonic.Extract24Words(string(raw))
	if err != nil {
		t.Fatalf("parse seed phrase: %v", err)
	}
	entropyB64, err := mnemonic.EntropyBase64FromMnemonic(mn)
	if err != nil {
		t.Fatalf("decode seed phrase: %v", err)
	}
	seedB64, err := mnemonic.SeedBase64FromMnemonic(mn)
	if err != nil {
		t.Fatalf("decode seed phrase: %v", err)
	}

	entropy, err := base64.StdEncoding.DecodeString(entropyB64)
	if err != nil || len(entropy) != 32 {
		t.Fatalf("entropy base64 invalid")
	}
	seed64, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed64) != 64 {
		t.Fatalf("seed base64 invalid")
	}

	add := func(out *[]string, seen map[string]struct{}, b []byte) {
		s := base64.StdEncoding.EncodeToString(b)
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		*out = append(*out, s)
	}

	var out []string
	seen := make(map[string]struct{})

	add(&out, seen, entropy)
	entropyRev := make([]byte, len(entropy))
	copy(entropyRev, entropy)
	for i, j := 0, len(entropyRev)-1; i < j; i, j = i+1, j-1 {
		entropyRev[i], entropyRev[j] = entropyRev[j], entropyRev[i]
	}
	add(&out, seen, entropyRev)

	add(&out, seen, seed64)
	add(&out, seen, seed64[:32])
	add(&out, seen, seed64[32:])

	sumEnt := sha256.Sum256(entropy)
	add(&out, seen, sumEnt[:])
	sumSeed := sha256.Sum256(seed64)
	add(&out, seen, sumSeed[:])

	return out
}

func unifiedAddress(t *testing.T, jd *containers.Junocashd, account uint32) string {
	t.Helper()
	ctx := context.Background()
	addr, err := junocashdutil.GetUnifiedAddressForAccount(ctx, jd, account)
	if err != nil {
		t.Fatalf("z_getaddressforaccount: %v", err)
	}
	return addr
}

func buildSingleNoteWithdrawalPlan(t *testing.T, rpc *junocashd.Client, jd *containers.Junocashd, toAddr, changeAddr string, amountZat uint64) types.TxPlan {
	t.Helper()
	return buildSingleNoteSendPlan(t, rpc, jd, []types.TxOutput{
		{ToAddress: toAddr, AmountZat: strconv.FormatUint(amountZat, 10)},
	}, changeAddr, types.TxPlanKindWithdrawal)
}

func buildSingleNoteSendPlan(t *testing.T, rpc *junocashd.Client, jd *containers.Junocashd, outputs []types.TxOutput, changeAddr string, kind types.TxPlanKind) types.TxPlan {
	t.Helper()
	ctx := context.Background()

	info, err := chain.GetChainInfo(ctx, rpc)
	if err != nil {
		t.Fatalf("chain info: %v", err)
	}
	if info.Height < 0 || info.Height > int64(^uint32(0)) {
		t.Fatalf("chain height invalid: %d", info.Height)
	}
	anchorHeight := uint32(info.Height)

	orch, err := chain.BuildOrchardIndex(ctx, rpc, int64(anchorHeight))
	if err != nil {
		t.Fatalf("orchard index: %v", err)
	}
	if len(orch.CMXHex) == 0 {
		t.Fatalf("orchard commitments empty")
	}

	notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, 0)
	if err != nil {
		t.Fatalf("z_listunspent: %v", err)
	}
	if len(notes) == 0 {
		t.Fatalf("no spendable orchard notes")
	}

	n := notes[0]
	key := fmt.Sprintf("%s:%d", n.TxID, n.OutIndex)
	act, ok := orch.ByOutpoint[key]
	if !ok {
		t.Fatalf("missing orchard action for note %s", key)
	}

	const expiryOffset = uint32(40)
	expiryHeight := anchorHeight + expiryOffset

	var totalOut uint64
	for i, o := range outputs {
		amt, err := strconv.ParseUint(strings.TrimSpace(o.AmountZat), 10, 64)
		if err != nil || amt == 0 {
			t.Fatalf("outputs[%d].amount_zat invalid", i)
		}
		totalOut += amt
	}

	// We choose amounts so that change > 0 and a change output will be created.
	outputCount := len(outputs) + 1
	actions := outputCount
	if actions < 2 {
		actions = 2
	}
	feeZat := uint64(5_000) * uint64(actions)
	if n.AmountZat <= totalOut+feeZat {
		t.Fatalf("insufficient note value")
	}

	w, err := witness.OrchardWitness(orch.CMXHex, []uint32{act.Position})
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if len(w.Paths) != 1 || w.Paths[0].Position != act.Position {
		t.Fatalf("witness mismatch")
	}
	if len(w.Paths[0].AuthPath) != 32 {
		t.Fatalf("witness path length mismatch")
	}

	plan := types.TxPlan{
		Version:       types.V0,
		Kind:          kind,
		WalletID:      "test-wallet",
		CoinType:      coinTypeForChain(info.Chain),
		Account:       0,
		Chain:         info.Chain,
		BranchID:      info.BranchID,
		AnchorHeight:  anchorHeight,
		Anchor:        w.Root,
		ExpiryHeight:  expiryHeight,
		Outputs:       outputs,
		ChangeAddress: changeAddr,
		FeeZat:        strconv.FormatUint(feeZat, 10),
		Notes: []types.OrchardSpendNote{
			{
				NoteID:          key,
				ActionNullifier: act.Nullifier,
				CMX:             act.CMX,
				Position:        act.Position,
				Path:            w.Paths[0].AuthPath,
				EphemeralKey:    act.EphemeralKey,
				EncCiphertext:   act.EncCiphertext,
			},
		},
	}

	if err := validatePlanBasics(plan); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
	return plan
}

func buildSingleNoteSweepPlan(t *testing.T, rpc *junocashd.Client, jd *containers.Junocashd, toAddr, changeAddr string) types.TxPlan {
	t.Helper()
	ctx := context.Background()

	info, err := chain.GetChainInfo(ctx, rpc)
	if err != nil {
		t.Fatalf("chain info: %v", err)
	}
	if info.Height < 0 || info.Height > int64(^uint32(0)) {
		t.Fatalf("chain height invalid: %d", info.Height)
	}
	anchorHeight := uint32(info.Height)

	orch, err := chain.BuildOrchardIndex(ctx, rpc, int64(anchorHeight))
	if err != nil {
		t.Fatalf("orchard index: %v", err)
	}
	if len(orch.CMXHex) == 0 {
		t.Fatalf("orchard commitments empty")
	}

	notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, 0)
	if err != nil {
		t.Fatalf("z_listunspent: %v", err)
	}
	if len(notes) == 0 {
		t.Fatalf("no spendable orchard notes")
	}

	n := notes[0]
	key := fmt.Sprintf("%s:%d", n.TxID, n.OutIndex)
	act, ok := orch.ByOutpoint[key]
	if !ok {
		t.Fatalf("missing orchard action for note %s", key)
	}

	const expiryOffset = uint32(40)
	expiryHeight := anchorHeight + expiryOffset

	const feeZat = uint64(5_000 * 2)
	if n.AmountZat <= feeZat {
		t.Fatalf("insufficient note value")
	}
	amountZat := n.AmountZat - feeZat

	w, err := witness.OrchardWitness(orch.CMXHex, []uint32{act.Position})
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if len(w.Paths) != 1 || w.Paths[0].Position != act.Position {
		t.Fatalf("witness mismatch")
	}
	if len(w.Paths[0].AuthPath) != 32 {
		t.Fatalf("witness path length mismatch")
	}

	plan := types.TxPlan{
		Version:      types.V0,
		Kind:         types.TxPlanKindSweep,
		WalletID:     "test-wallet",
		CoinType:     coinTypeForChain(info.Chain),
		Account:      0,
		Chain:        info.Chain,
		BranchID:     info.BranchID,
		AnchorHeight: anchorHeight,
		Anchor:       w.Root,
		ExpiryHeight: expiryHeight,
		Outputs: []types.TxOutput{
			{ToAddress: toAddr, AmountZat: strconv.FormatUint(amountZat, 10)},
		},
		ChangeAddress: changeAddr,
		FeeZat:        strconv.FormatUint(feeZat, 10),
		Notes: []types.OrchardSpendNote{
			{
				NoteID:          key,
				ActionNullifier: act.Nullifier,
				CMX:             act.CMX,
				Position:        act.Position,
				Path:            w.Paths[0].AuthPath,
				EphemeralKey:    act.EphemeralKey,
				EncCiphertext:   act.EncCiphertext,
			},
		},
	}

	if err := validatePlanBasics(plan); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
	return plan
}

func validatePlanBasics(plan types.TxPlan) error {
	if plan.Version != types.V0 {
		return errors.New("version")
	}
	if strings.TrimSpace(string(plan.Kind)) == "" {
		return errors.New("kind")
	}
	if strings.TrimSpace(plan.WalletID) == "" {
		return errors.New("wallet_id")
	}
	if strings.TrimSpace(plan.Chain) == "" {
		return errors.New("chain")
	}
	if plan.BranchID == 0 {
		return errors.New("branch_id")
	}
	if plan.AnchorHeight == 0 {
		return errors.New("anchor_height")
	}
	if len(plan.Anchor) != 64 {
		return errors.New("anchor")
	}
	if _, err := hex.DecodeString(plan.Anchor); err != nil {
		return errors.New("anchor_hex")
	}
	if plan.ExpiryHeight == 0 {
		return errors.New("expiry_height")
	}
	if len(plan.Outputs) == 0 {
		return errors.New("outputs")
	}
	for _, o := range plan.Outputs {
		if strings.TrimSpace(o.ToAddress) == "" {
			return errors.New("to_address")
		}
		if strings.TrimSpace(o.AmountZat) == "" {
			return errors.New("amount_zat")
		}
	}
	if strings.TrimSpace(plan.ChangeAddress) == "" {
		return errors.New("change_address")
	}
	if strings.TrimSpace(plan.FeeZat) == "" {
		return errors.New("fee_zat")
	}
	if len(plan.Notes) == 0 {
		return errors.New("notes")
	}
	for _, n := range plan.Notes {
		if len(n.Path) != 32 {
			return errors.New("witness_path")
		}
	}
	return nil
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func decodeJSON[T any](t *testing.T, raw []byte, out *T) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("json decode: %v", err)
	}
}
