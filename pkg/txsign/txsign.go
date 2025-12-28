package txsign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/ffi"
	"github.com/Abdullah1738/juno-txsign/internal/plan"
)

type Result struct {
	TxID     string
	RawTxHex string
	FeeZat   string
}

func Sign(ctx context.Context, txplan types.TxPlan, seedBase64 string) (Result, error) {
	_ = ctx // reserved for future (ffi call is synchronous)

	req, err := plan.BuildSendRequestJSON(txplan, seedBase64)
	if err != nil {
		return Result{}, err
	}

	raw, err := ffi.BuildTxJSON(req)
	if err != nil {
		return Result{}, err
	}

	var resp struct {
		Status   string `json:"status"`
		TxID     string `json:"txid,omitempty"`
		RawTxHex string `json:"raw_tx_hex,omitempty"`
		FeeZat   string `json:"fee_zat,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return Result{}, errors.New("txsign: invalid response")
	}

	switch resp.Status {
	case "ok":
		txid := strings.ToLower(strings.TrimSpace(resp.TxID))
		rawTx := strings.TrimSpace(resp.RawTxHex)
		fee := strings.TrimSpace(resp.FeeZat)
		if txid == "" || rawTx == "" || fee == "" {
			return Result{}, errors.New("txsign: invalid response")
		}
		return Result{
			TxID:     txid,
			RawTxHex: rawTx,
			FeeZat:   fee,
		}, nil
	case "err":
		if strings.TrimSpace(resp.Error) == "" {
			return Result{}, errors.New("txsign: failed")
		}
		return Result{}, fmt.Errorf("txsign: %s", strings.TrimSpace(resp.Error))
	default:
		return Result{}, errors.New("txsign: invalid response")
	}
}
