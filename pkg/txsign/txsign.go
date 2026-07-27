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

	OrchardOutputActionIndices []uint32
	OrchardChangeActionIndex   *uint32
}

type ExtFinalizeResult struct {
	TxID     string
	RawTxHex string
	FeeZat   string
}

type SigningRequest struct {
	Sighash     string `json:"sighash"`
	ActionIndex uint32 `json:"action_index"`
	Alpha       string `json:"alpha"`
	RK          string `json:"rk"`
}

type SigningRequests struct {
	Version  string           `json:"version"`
	Requests []SigningRequest `json:"requests"`
}

type PreparedTx = json.RawMessage

type ExtPrepareResult struct {
	PreparedTx      PreparedTx
	SigningRequests SigningRequests
}

type SpendAuthSig struct {
	ActionIndex  uint32 `json:"action_index"`
	SpendAuthSig string `json:"spend_auth_sig"`
}

type SpendAuthSigSubmission struct {
	Version    string         `json:"version"`
	Signatures []SpendAuthSig `json:"signatures"`
}

func parseTxResponse(raw string) (Result, error) {
	var resp struct {
		Status                     string   `json:"status"`
		TxID                       string   `json:"txid,omitempty"`
		RawTxHex                   string   `json:"raw_tx_hex,omitempty"`
		FeeZat                     string   `json:"fee_zat,omitempty"`
		OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices,omitempty"`
		OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index,omitempty"`
		Error                      string   `json:"error,omitempty"`
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
			TxID:                       txid,
			RawTxHex:                   rawTx,
			FeeZat:                     fee,
			OrchardOutputActionIndices: resp.OrchardOutputActionIndices,
			OrchardChangeActionIndex:   resp.OrchardChangeActionIndex,
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

func parseExtFinalizeResponse(raw string) (ExtFinalizeResult, error) {
	var resp struct {
		Status                     string          `json:"status"`
		TxID                       string          `json:"txid,omitempty"`
		RawTxHex                   string          `json:"raw_tx_hex,omitempty"`
		FeeZat                     string          `json:"fee_zat,omitempty"`
		OrchardOutputActionIndices json.RawMessage `json:"orchard_output_action_indices,omitempty"`
		OrchardChangeActionIndex   json.RawMessage `json:"orchard_change_action_index,omitempty"`
		Error                      string          `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return ExtFinalizeResult{}, errors.New("txsign: invalid response")
	}
	if len(resp.OrchardOutputActionIndices) != 0 || len(resp.OrchardChangeActionIndex) != 0 {
		return ExtFinalizeResult{}, errors.New("txsign: invalid response")
	}

	switch resp.Status {
	case "ok":
		txid := strings.ToLower(strings.TrimSpace(resp.TxID))
		rawTx := strings.TrimSpace(resp.RawTxHex)
		fee := strings.TrimSpace(resp.FeeZat)
		if txid == "" || rawTx == "" || fee == "" {
			return ExtFinalizeResult{}, errors.New("txsign: invalid response")
		}
		return ExtFinalizeResult{
			TxID:     txid,
			RawTxHex: rawTx,
			FeeZat:   fee,
		}, nil
	case "err":
		if strings.TrimSpace(resp.Error) == "" {
			return ExtFinalizeResult{}, errors.New("txsign: failed")
		}
		return ExtFinalizeResult{}, fmt.Errorf("txsign: %s", strings.TrimSpace(resp.Error))
	default:
		return ExtFinalizeResult{}, errors.New("txsign: invalid response")
	}
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

	return parseTxResponse(raw)
}

// DeriveUFVK derives the Orchard-only unified full viewing key used to bind a
// private signer seed to one network/account at startup.
func DeriveUFVK(ctx context.Context, seedBase64 string, coinType, account uint32) (string, error) {
	_ = ctx // the local FFI call is synchronous
	request, err := json.Marshal(struct {
		SeedBase64 string `json:"seed_base64"`
		CoinType   uint32 `json:"coin_type"`
		Account    uint32 `json:"account"`
	}{
		SeedBase64: strings.TrimSpace(seedBase64),
		CoinType:   coinType,
		Account:    account,
	})
	if err != nil {
		return "", errors.New("txsign: marshal UFVK derivation request")
	}
	raw, err := ffi.DeriveUFVKJSON(string(request))
	if err != nil {
		return "", err
	}
	var response struct {
		Status string `json:"status"`
		UFVK   string `json:"ufvk,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return "", errors.New("txsign: invalid UFVK derivation response")
	}
	switch response.Status {
	case "ok":
		if strings.TrimSpace(response.UFVK) == "" {
			return "", errors.New("txsign: invalid UFVK derivation response")
		}
		return strings.TrimSpace(response.UFVK), nil
	case "err":
		if strings.TrimSpace(response.Error) == "" {
			return "", errors.New("txsign: UFVK derivation failed")
		}
		return "", fmt.Errorf("txsign: %s", strings.TrimSpace(response.Error))
	default:
		return "", errors.New("txsign: invalid UFVK derivation response")
	}
}

func ExtPrepare(ctx context.Context, txplan types.TxPlan, ufvk string) (ExtPrepareResult, error) {
	_ = ctx // reserved for future (ffi call is synchronous)

	req, err := plan.BuildExtPrepareRequestJSON(txplan, ufvk)
	if err != nil {
		return ExtPrepareResult{}, err
	}

	raw, err := ffi.ExtPrepareJSON(req)
	if err != nil {
		return ExtPrepareResult{}, err
	}

	var resp struct {
		Status          string          `json:"status"`
		PreparedTx      json.RawMessage `json:"prepared_tx,omitempty"`
		SigningRequests SigningRequests `json:"signing_requests,omitempty"`
		Error           string          `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return ExtPrepareResult{}, errors.New("txsign: invalid response")
	}

	switch resp.Status {
	case "ok":
		if len(resp.PreparedTx) == 0 || len(resp.SigningRequests.Requests) == 0 {
			return ExtPrepareResult{}, errors.New("txsign: invalid response")
		}
		return ExtPrepareResult{
			PreparedTx:      resp.PreparedTx,
			SigningRequests: resp.SigningRequests,
		}, nil
	case "err":
		if strings.TrimSpace(resp.Error) == "" {
			return ExtPrepareResult{}, errors.New("txsign: failed")
		}
		return ExtPrepareResult{}, fmt.Errorf("txsign: %s", strings.TrimSpace(resp.Error))
	default:
		return ExtPrepareResult{}, errors.New("txsign: invalid response")
	}
}

func ExtFinalize(ctx context.Context, preparedTx PreparedTx, sigs SpendAuthSigSubmission) (ExtFinalizeResult, error) {
	_ = ctx // reserved for future (ffi call is synchronous)

	if len(preparedTx) == 0 {
		return ExtFinalizeResult{}, errors.New("txsign: prepared_tx is required")
	}

	req := struct {
		PreparedTx    json.RawMessage        `json:"prepared_tx"`
		SpendAuthSigs SpendAuthSigSubmission `json:"spend_auth_sigs"`
	}{
		PreparedTx:    preparedTx,
		SpendAuthSigs: sigs,
	}

	b, err := json.Marshal(req)
	if err != nil {
		return ExtFinalizeResult{}, errors.New("txsign: marshal request")
	}

	raw, err := ffi.ExtFinalizeJSON(string(b))
	if err != nil {
		return ExtFinalizeResult{}, err
	}

	return parseExtFinalizeResponse(raw)
}
