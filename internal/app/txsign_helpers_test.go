//go:build integration || e2e

package app

import (
	"context"
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

const testCoinType = uint32(8133)

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
	ctx := context.Background()

	if err := junocashdutil.GenerateBlocks(ctx, jd, 101); err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := junocashdutil.ShieldCoinbaseTo(ctx, jd, orchardAddr); err != nil {
		t.Fatalf("shield coinbase: %v", err)
	}

	if err := junocashdutil.GenerateBlocks(ctx, jd, 1); err != nil {
		t.Fatalf("confirm: %v", err)
	}
}

func seedBase64FromNode(t *testing.T, jd *containers.Junocashd) string {
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
	seed, err := mnemonic.EntropyBase64FromMnemonic(mn)
	if err != nil {
		t.Fatalf("decode seed phrase: %v", err)
	}

	if _, err := base64.StdEncoding.DecodeString(seed); err != nil {
		t.Fatalf("seed base64 invalid: %v", err)
	}
	return seed
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

	feeZat := uint64(5_000 * 2)
	if n.AmountZat < amountZat+feeZat {
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
		Version:      types.V0,
		Kind:         types.TxPlanKindWithdrawal,
		WalletID:     "test-wallet",
		CoinType:     testCoinType,
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
	if len(plan.Outputs) != 1 {
		return errors.New("outputs")
	}
	if strings.TrimSpace(plan.Outputs[0].ToAddress) == "" {
		return errors.New("to_address")
	}
	if strings.TrimSpace(plan.Outputs[0].AmountZat) == "" {
		return errors.New("amount_zat")
	}
	if strings.TrimSpace(plan.ChangeAddress) == "" {
		return errors.New("change_address")
	}
	if strings.TrimSpace(plan.FeeZat) == "" {
		return errors.New("fee_zat")
	}
	if len(plan.Notes) != 1 {
		return errors.New("notes")
	}
	if len(plan.Notes[0].Path) != 32 {
		return errors.New("witness_path")
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

