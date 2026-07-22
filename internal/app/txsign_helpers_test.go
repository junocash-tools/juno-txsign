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

const testNU62BranchID = uint32(0x5437f330)

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

	info, err := chain.GetChainInfo(ctx, junocashd.New(jd.RPCURL, jd.RPCUser, jd.RPCPassword))
	if err != nil {
		t.Fatalf("chain info after funding: %v", err)
	}
	if info.BranchID != testNU62BranchID {
		t.Fatalf("regtest chaintip branch: got %08x want %08x", info.BranchID, testNU62BranchID)
	}
}

func mineOne(ctx context.Context, jd *containers.Junocashd) error {
	_, err := jd.ExecCLI(ctx, "generate", "1")
	return err
}

func waitWalletTx(t *testing.T, jd *containers.Junocashd, txid string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		if _, err := jd.ExecCLI(ctx, "gettransaction", txid); err == nil {
			return
		}
		if _, err := jd.ExecCLI(ctx, "getrawtransaction", txid); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("tx not seen by wallet or node")
		case <-ticker.C:
		}
	}
}

func mineUntilTxConfirmed(t *testing.T, rpc *junocashd.Client, jd *containers.Junocashd, txid string) string {
	t.Helper()

	waitWalletTx(t, jd, txid)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var prioritized any
	_ = rpc.Call(ctx, "prioritisetransaction", []any{txid, 0, 100000000}, &prioritized)

	for attempt := 0; attempt < 6; attempt++ {
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
		for _, got := range blk.Tx {
			if strings.EqualFold(got, txid) {
				return hash
			}
		}
	}

	t.Fatalf("tx not mined")
	return ""
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

type unifiedAccountAddress struct {
	Account uint32
	Address string
}

func newUnifiedAddressForDifferentAccount(t *testing.T, jd *containers.Junocashd, sourceAccount uint32) unifiedAccountAddress {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := jd.ExecCLI(ctx, "z_getnewaccount")
	if err != nil {
		t.Fatalf("z_getnewaccount: %v", err)
	}
	var created struct {
		Account *uint32 `json:"account"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("z_getnewaccount: invalid json: %v", err)
	}
	if created.Account == nil {
		t.Fatal("z_getnewaccount: missing account")
	}
	if *created.Account == sourceAccount {
		t.Fatalf("z_getnewaccount: returned source account %d", sourceAccount)
	}

	addr, err := junocashdutil.GetUnifiedAddressForAccount(ctx, jd, *created.Account)
	if err != nil {
		t.Fatalf("z_getaddressforaccount(%d): %v", *created.Account, err)
	}
	return unifiedAccountAddress{
		Account: *created.Account,
		Address: addr,
	}
}

type expectedAccountNote struct {
	action   uint32
	valueZat uint64
	address  string
	role     string
}

func normalizedNoteID(t *testing.T, noteID string) string {
	t.Helper()
	noteID = strings.TrimSpace(noteID)
	sep := strings.LastIndexByte(noteID, ':')
	if sep <= 0 || sep == len(noteID)-1 {
		t.Fatalf("note_id = %q, want txid:action", noteID)
	}
	txid := strings.ToLower(noteID[:sep])
	if len(txid) != 64 {
		t.Fatalf("note_id txid length = %d, want 64", len(txid))
	}
	if _, err := hex.DecodeString(txid); err != nil {
		t.Fatalf("note_id txid invalid: %v", err)
	}
	action, err := strconv.ParseUint(noteID[sep+1:], 10, 32)
	if err != nil {
		t.Fatalf("note_id action invalid: %v", err)
	}
	return fmt.Sprintf("%s:%d", txid, action)
}

func orchardPlanInputValue(t *testing.T, ctx context.Context, jd *containers.Junocashd, sourceAccount uint32, plan types.TxPlan) uint64 {
	t.Helper()
	notes, err := junocashdutil.ListUnspentOrchard(ctx, jd, 1, sourceAccount)
	if err != nil {
		t.Fatalf("z_listunspent source account %d: %v", sourceAccount, err)
	}
	available := make(map[string]uint64, len(notes))
	for _, note := range notes {
		available[fmt.Sprintf("%s:%d", strings.ToLower(note.TxID), note.OutIndex)] = note.AmountZat
	}

	var total uint64
	seen := make(map[string]struct{}, len(plan.Notes))
	for i, note := range plan.Notes {
		id := normalizedNoteID(t, note.NoteID)
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate plan note %s", id)
		}
		value, ok := available[id]
		if !ok {
			t.Fatalf("notes[%d] %s not spendable in source account %d before broadcast", i, id, sourceAccount)
		}
		if ^uint64(0)-total < value {
			t.Fatal("plan input value overflow")
		}
		total += value
		seen[id] = struct{}{}
	}
	return total
}

func assertDecodedOrchardTransaction(t *testing.T, ctx context.Context, rpc *junocashd.Client, rawTxHex, txid string, plan types.TxPlan, outputActionIndices []uint32, changeActionIndex *uint32) {
	t.Helper()
	var decoded struct {
		TxID         string `json:"txid"`
		ExpiryHeight int64  `json:"expiryheight"`
		Vin          []any  `json:"vin"`
		Vout         []any  `json:"vout"`
		VJoinSplit   []any  `json:"vjoinsplit"`
		SaplingSpend []any  `json:"vShieldedSpend"`
		SaplingOut   []any  `json:"vShieldedOutput"`
		Orchard      struct {
			ValueBalanceZat int64 `json:"valueBalanceZat"`
			Actions         []struct {
				Nullifier string `json:"nullifier"`
			} `json:"actions"`
		} `json:"orchard"`
	}
	if err := rpc.Call(ctx, "decoderawtransaction", []any{rawTxHex}, &decoded); err != nil {
		t.Fatalf("decoderawtransaction: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(decoded.TxID), strings.TrimSpace(txid)) {
		t.Fatalf("decoded txid = %q, want %q", decoded.TxID, txid)
	}
	if decoded.ExpiryHeight != int64(plan.ExpiryHeight) {
		t.Fatalf("decoded expiryheight = %d, want %d", decoded.ExpiryHeight, plan.ExpiryHeight)
	}
	if len(decoded.Vin) != 0 || len(decoded.Vout) != 0 || len(decoded.VJoinSplit) != 0 || len(decoded.SaplingSpend) != 0 || len(decoded.SaplingOut) != 0 {
		t.Fatalf("transaction is not pure Orchard: vin=%d vout=%d joinsplit=%d sapling_spends=%d sapling_outputs=%d", len(decoded.Vin), len(decoded.Vout), len(decoded.VJoinSplit), len(decoded.SaplingSpend), len(decoded.SaplingOut))
	}

	outputCount := len(plan.Outputs)
	if changeActionIndex != nil {
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
		t.Fatalf("decoded Orchard actions = %d, want %d", len(decoded.Orchard.Actions), wantActions)
	}
	for i, action := range outputActionIndices {
		if int(action) >= len(decoded.Orchard.Actions) {
			t.Fatalf("output action index %d = %d outside %d decoded actions", i, action, len(decoded.Orchard.Actions))
		}
	}
	if changeActionIndex != nil && int(*changeActionIndex) >= len(decoded.Orchard.Actions) {
		t.Fatalf("change action index %d outside %d decoded actions", *changeActionIndex, len(decoded.Orchard.Actions))
	}

	// TxPlan action_nullifier identifies the action that created an input note;
	// it is not the nullifier derived when this transaction spends that note.
	seenNullifiers := make(map[string]struct{}, len(decoded.Orchard.Actions))
	for i, action := range decoded.Orchard.Actions {
		nullifier := strings.ToLower(strings.TrimSpace(action.Nullifier))
		if len(nullifier) != 64 {
			t.Fatalf("decoded Orchard action %d nullifier length = %d, want 64", i, len(nullifier))
		}
		if _, err := hex.DecodeString(nullifier); err != nil {
			t.Fatalf("decoded Orchard action %d nullifier is not canonical hex: %v", i, err)
		}
		if _, duplicate := seenNullifiers[nullifier]; duplicate {
			t.Fatalf("decoded Orchard action %d repeats nullifier %s", i, nullifier)
		}
		seenNullifiers[nullifier] = struct{}{}
	}

	fee, err := strconv.ParseInt(strings.TrimSpace(plan.FeeZat), 10, 64)
	if err != nil || fee < 0 {
		t.Fatalf("fee_zat invalid: %q", plan.FeeZat)
	}
	if decoded.Orchard.ValueBalanceZat != fee {
		t.Fatalf("decoded Orchard valueBalanceZat = %d, want fee %d", decoded.Orchard.ValueBalanceZat, fee)
	}
}

func waitForOrchardPlanEffects(t *testing.T, parent context.Context, jd *containers.Junocashd, txid string, sourceAccount uint32, totalInput uint64, plan types.TxPlan, outputActionIndices []uint32, outputAccounts []uint32, changeActionIndex *uint32, changeAccount uint32) {
	t.Helper()
	if len(outputActionIndices) != len(plan.Outputs) {
		t.Fatalf("Orchard output action indices = %d, want %d", len(outputActionIndices), len(plan.Outputs))
	}
	if len(outputAccounts) != len(plan.Outputs) {
		t.Fatalf("output accounts = %d, want %d", len(outputAccounts), len(plan.Outputs))
	}

	expectedByAccount := make(map[uint32][]expectedAccountNote)
	accounts := make([]uint32, 0, len(outputAccounts)+2)
	addAccount := func(account uint32) {
		if _, exists := expectedByAccount[account]; !exists {
			expectedByAccount[account] = nil
			accounts = append(accounts, account)
		}
	}
	addAccount(sourceAccount)

	var totalOutput uint64
	seenActions := make(map[uint32]struct{}, len(plan.Outputs)+1)
	for i, output := range plan.Outputs {
		value, err := strconv.ParseUint(strings.TrimSpace(output.AmountZat), 10, 64)
		if err != nil || value == 0 {
			t.Fatalf("outputs[%d].amount_zat invalid", i)
		}
		if ^uint64(0)-totalOutput < value {
			t.Fatal("plan output value overflow")
		}
		totalOutput += value

		action := outputActionIndices[i]
		if _, duplicate := seenActions[action]; duplicate {
			t.Fatalf("duplicate Orchard output action index %d", action)
		}
		seenActions[action] = struct{}{}
		account := outputAccounts[i]
		addAccount(account)
		expectedByAccount[account] = append(expectedByAccount[account], expectedAccountNote{
			action:   action,
			valueZat: value,
			address:  output.ToAddress,
			role:     fmt.Sprintf("outputs[%d]", i),
		})
	}

	fee, err := strconv.ParseUint(strings.TrimSpace(plan.FeeZat), 10, 64)
	if err != nil {
		t.Fatalf("fee_zat invalid: %v", err)
	}
	if ^uint64(0)-totalOutput < fee {
		t.Fatal("outputs plus fee overflow")
	}
	needed := totalOutput + fee
	if totalInput < needed {
		t.Fatalf("input value %d below outputs plus fee %d", totalInput, needed)
	}
	wantChange := totalInput - needed
	if changeActionIndex == nil {
		if wantChange != 0 {
			t.Fatalf("missing change action index for %d zat change", wantChange)
		}
	} else {
		if wantChange == 0 {
			t.Fatal("change action index present for zero change")
		}
		if _, duplicate := seenActions[*changeActionIndex]; duplicate {
			t.Fatalf("change action index %d collides with explicit output", *changeActionIndex)
		}
		seenActions[*changeActionIndex] = struct{}{}
		addAccount(changeAccount)
		expectedByAccount[changeAccount] = append(expectedByAccount[changeAccount], expectedAccountNote{
			action:   *changeActionIndex,
			valueZat: wantChange,
			address:  plan.ChangeAddress,
			role:     "change",
		})
	}
	expectedWalletNotes := len(plan.Outputs)
	if changeActionIndex != nil {
		expectedWalletNotes++
	}

	selectedNoteIDs := make(map[string]struct{}, len(plan.Notes))
	for _, note := range plan.Notes {
		selectedNoteIDs[normalizedNoteID(t, note.NoteID)] = struct{}{}
	}

	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	lastState := "wallet effects not observed"

	for {
		ready := true
		notes, err := junocashdutil.ListAllUnspentOrchard(ctx, jd, 1)
		if err != nil {
			lastState = fmt.Sprintf("z_listunspent wallet: %v", err)
			ready = false
		}
		if ready {
			for _, note := range notes {
				id := fmt.Sprintf("%s:%d", strings.ToLower(note.TxID), note.OutIndex)
				if _, selected := selectedNoteIDs[id]; selected {
					lastState = fmt.Sprintf("selected source note %s still unspent", id)
					ready = false
					break
				}
			}
		}

		var walletTxNotes []junocashdutil.UnspentOrchardNote
		if ready {
			for _, note := range notes {
				if strings.EqualFold(note.TxID, txid) {
					walletTxNotes = append(walletTxNotes, note)
				}
			}
			if len(walletTxNotes) != expectedWalletNotes {
				lastState = fmt.Sprintf("wallet tx notes = %d, want %d", len(walletTxNotes), expectedWalletNotes)
				ready = false
			}
		}

		for _, account := range accounts {
			if !ready {
				break
			}

			var txNotes []junocashdutil.UnspentOrchardNote
			for _, note := range walletTxNotes {
				if note.Account == account {
					txNotes = append(txNotes, note)
				}
			}
			expected := expectedByAccount[account]
			if len(txNotes) != len(expected) {
				lastState = fmt.Sprintf("account %d tx notes = %d, want %d", account, len(txNotes), len(expected))
				ready = false
				break
			}
			for _, want := range expected {
				matches := 0
				for _, note := range txNotes {
					if note.OutIndex == want.action && note.AmountZat == want.valueZat && note.Address == want.address {
						matches++
					}
				}
				if matches != 1 {
					lastState = fmt.Sprintf("account %d %s action %d value %d address %q matches = %d, want 1", account, want.role, want.action, want.valueZat, want.address, matches)
					ready = false
					break
				}
			}
			if !ready {
				break
			}
		}
		if ready {
			return
		}

		select {
		case <-ctx.Done():
			t.Fatalf("Orchard wallet effects: %s: %v", lastState, ctx.Err())
		case <-ticker.C:
		}
	}
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

	pickNote := func(need uint64, strict bool) (junocashdutil.UnspentOrchardNote, bool) {
		var best junocashdutil.UnspentOrchardNote
		var ok bool
		for _, note := range notes {
			if strict {
				if note.AmountZat <= need {
					continue
				}
			} else {
				if note.AmountZat < need {
					continue
				}
			}
			if !ok || note.AmountZat > best.AmountZat {
				best = note
				ok = true
			}
		}
		return best, ok
	}

	requiredFee := func(spends, outputs int) uint64 {
		actions := outputs
		if spends > actions {
			actions = spends
		}
		if actions < 2 {
			actions = 2
		}
		return 5_000 * uint64(actions)
	}

	feeWithChange := requiredFee(1, len(outputs)+1)
	needWithChange := totalOut + feeWithChange
	n, ok := pickNote(needWithChange, true)
	feeZat := feeWithChange
	if !ok {
		feeNoChange := requiredFee(1, len(outputs))
		needNoChange := totalOut + feeNoChange
		n, ok = pickNote(needNoChange, false)
		feeZat = feeNoChange
	}
	if !ok {
		t.Fatalf("insufficient note value")
	}

	key := fmt.Sprintf("%s:%d", n.TxID, n.OutIndex)
	act, ok := orch.ByOutpoint[key]
	if !ok {
		t.Fatalf("missing orchard action for note %s", key)
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
	if strings.EqualFold(strings.TrimSpace(plan.Chain), "regtest") && plan.BranchID != testNU62BranchID {
		return fmt.Errorf("regtest_branch_id: got %08x want %08x", plan.BranchID, testNU62BranchID)
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
