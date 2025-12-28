//go:build integration

package app

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestIntegration_SignAndBuildRawTx(t *testing.T) {
	jd, rpc := startJunocashd(t)

	changeAddr := unifiedAddress(t, jd, 0)
	mineAndShieldOnce(t, jd, changeAddr)
	toAddr := unifiedAddress(t, jd, 0)

	seedBase64 := seedBase64FromNode(t, jd)
	plan := buildSingleNoteWithdrawalPlan(t, rpc, jd, toAddr, changeAddr, 1_000_000)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := txsign.Sign(ctx, plan, seedBase64)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if res.TxID == "" || len(res.TxID) != 64 {
		t.Fatalf("txid invalid")
	}
	if res.RawTxHex == "" {
		t.Fatalf("raw tx empty")
	}
	if _, err := hex.DecodeString(res.RawTxHex); err != nil {
		t.Fatalf("raw tx hex invalid")
	}
}
