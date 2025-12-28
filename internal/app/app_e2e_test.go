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

	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
)

func TestE2E_SignThenBroadcastAndMine(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

	seedBase64 := seedBase64FromNode(t, jd)
	plan := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)

	tmp := t.TempDir()
	txplanPath := filepath.Join(tmp, "txplan.json")
	seedPath := filepath.Join(tmp, "seed.base64")

	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal txplan: %v", err)
	}
	if err := os.WriteFile(txplanPath, append(planJSON, '\n'), 0o600); err != nil {
		t.Fatalf("write txplan: %v", err)
	}
	if err := os.WriteFile(seedPath, []byte(seedBase64+"\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	bin := filepath.Join(repoRoot(), "bin", "juno-txsign")
	cmd := exec.CommandContext(ctx, bin, "sign", "--txplan", txplanPath, "--seed-file", seedPath, "--json")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("juno-txsign: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		t.Fatalf("juno-txsign: %v", err)
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

	var acceptedTxID string
	if err := rpc.Call(ctx, "sendrawtransaction", []any{resp.Data.RawTxHex}, &acceptedTxID); err != nil {
		t.Fatalf("sendrawtransaction: %v", err)
	}
	if !strings.EqualFold(acceptedTxID, resp.Data.TxID) {
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
	for _, txid := range blk.Tx {
		if strings.EqualFold(txid, resp.Data.TxID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tx not mined")
	}
}

func mineOne(ctx context.Context, jd *containers.Junocashd) error {
	_, err := jd.ExecCLI(ctx, "generate", "1")
	return err
}
