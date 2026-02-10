package plan

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Abdullah1738/juno-sdk-go/types"
)

var (
	ErrInvalidPlan = errors.New("invalid txplan")
)

type SendRequest struct {
	Type          string           `json:"type"`
	SeedBase64    string           `json:"seed_base64"`
	CoinType      uint32           `json:"coin_type"`
	Account       uint32           `json:"account"`
	BranchID      uint32           `json:"branch_id"`
	ExpiryHeight  uint32           `json:"expiry_height"`
	Anchor        string           `json:"anchor"`
	Outputs       []types.TxOutput `json:"outputs"`
	FeeZat        string           `json:"fee_zat"`
	ChangeAddress string           `json:"change_address"`
	Notes         []Note           `json:"notes"`
}

type ExtPrepareRequest struct {
	Ufvk          string           `json:"ufvk"`
	CoinType      uint32           `json:"coin_type"`
	Account       uint32           `json:"account"`
	BranchID      uint32           `json:"branch_id"`
	ExpiryHeight  uint32           `json:"expiry_height"`
	Anchor        string           `json:"anchor"`
	Outputs       []types.TxOutput `json:"outputs"`
	FeeZat        string           `json:"fee_zat"`
	ChangeAddress string           `json:"change_address"`
	Notes         []Note           `json:"notes"`
}

type Note struct {
	NoteID          string   `json:"note_id,omitempty"`
	ActionNullifier string   `json:"action_nullifier"`
	CMX             string   `json:"cmx"`
	Position        uint32   `json:"position"`
	Path            []string `json:"path"`
	EphemeralKey    string   `json:"ephemeral_key"`
	EncCiphertext   string   `json:"enc_ciphertext"`
}

func BuildSendRequestJSON(txplan types.TxPlan, seedBase64 string) (string, error) {
	if err := ValidateTxPlanV0(txplan); err != nil {
		return "", err
	}
	seedBase64 = strings.TrimSpace(seedBase64)
	if seedBase64 == "" {
		return "", fmt.Errorf("%w: seed_base64 required", ErrInvalidPlan)
	}
	if _, err := base64.StdEncoding.DecodeString(seedBase64); err != nil {
		return "", fmt.Errorf("%w: seed_base64 invalid", ErrInvalidPlan)
	}

	if len(txplan.Outputs) == 0 {
		return "", fmt.Errorf("%w: outputs required", ErrInvalidPlan)
	}
	if len(txplan.Outputs) > 200 {
		return "", fmt.Errorf("%w: outputs too large", ErrInvalidPlan)
	}
	for i, out := range txplan.Outputs {
		if strings.TrimSpace(out.ToAddress) == "" {
			return "", fmt.Errorf("%w: outputs[%d].to_address required", ErrInvalidPlan, i)
		}
		if strings.TrimSpace(out.AmountZat) == "" {
			return "", fmt.Errorf("%w: outputs[%d].amount_zat required", ErrInvalidPlan, i)
		}
	}

	if strings.TrimSpace(txplan.FeeZat) == "" {
		return "", fmt.Errorf("%w: fee_zat required", ErrInvalidPlan)
	}

	req := SendRequest{
		Type:          "send",
		SeedBase64:    seedBase64,
		CoinType:      txplan.CoinType,
		Account:       txplan.Account,
		BranchID:      txplan.BranchID,
		ExpiryHeight:  txplan.ExpiryHeight,
		Anchor:        txplan.Anchor,
		FeeZat:        txplan.FeeZat,
		Outputs:       txplan.Outputs,
		ChangeAddress: txplan.ChangeAddress,
		Notes:         make([]Note, 0, len(txplan.Notes)),
	}

	for _, n := range txplan.Notes {
		req.Notes = append(req.Notes, Note{
			NoteID:          strings.TrimSpace(n.NoteID),
			ActionNullifier: strings.TrimSpace(n.ActionNullifier),
			CMX:             strings.TrimSpace(n.CMX),
			Position:        n.Position,
			Path:            n.Path,
			EphemeralKey:    strings.TrimSpace(n.EphemeralKey),
			EncCiphertext:   strings.TrimSpace(n.EncCiphertext),
		})
	}

	b, err := json.Marshal(req)
	if err != nil {
		return "", errors.New("marshal tx request")
	}
	return string(b), nil
}

func BuildExtPrepareRequestJSON(txplan types.TxPlan, ufvk string) (string, error) {
	if err := ValidateTxPlanV0(txplan); err != nil {
		return "", err
	}
	ufvk = strings.TrimSpace(ufvk)
	if ufvk == "" {
		return "", fmt.Errorf("%w: ufvk required", ErrInvalidPlan)
	}

	if len(txplan.Outputs) == 0 {
		return "", fmt.Errorf("%w: outputs required", ErrInvalidPlan)
	}
	if len(txplan.Outputs) > 200 {
		return "", fmt.Errorf("%w: outputs too large", ErrInvalidPlan)
	}
	for i, out := range txplan.Outputs {
		if strings.TrimSpace(out.ToAddress) == "" {
			return "", fmt.Errorf("%w: outputs[%d].to_address required", ErrInvalidPlan, i)
		}
		if strings.TrimSpace(out.AmountZat) == "" {
			return "", fmt.Errorf("%w: outputs[%d].amount_zat required", ErrInvalidPlan, i)
		}
	}

	if strings.TrimSpace(txplan.FeeZat) == "" {
		return "", fmt.Errorf("%w: fee_zat required", ErrInvalidPlan)
	}

	req := ExtPrepareRequest{
		Ufvk:          ufvk,
		CoinType:      txplan.CoinType,
		Account:       txplan.Account,
		BranchID:      txplan.BranchID,
		ExpiryHeight:  txplan.ExpiryHeight,
		Anchor:        txplan.Anchor,
		FeeZat:        txplan.FeeZat,
		Outputs:       txplan.Outputs,
		ChangeAddress: txplan.ChangeAddress,
		Notes:         make([]Note, 0, len(txplan.Notes)),
	}

	for _, n := range txplan.Notes {
		req.Notes = append(req.Notes, Note{
			NoteID:          strings.TrimSpace(n.NoteID),
			ActionNullifier: strings.TrimSpace(n.ActionNullifier),
			CMX:             strings.TrimSpace(n.CMX),
			Position:        n.Position,
			Path:            n.Path,
			EphemeralKey:    strings.TrimSpace(n.EphemeralKey),
			EncCiphertext:   strings.TrimSpace(n.EncCiphertext),
		})
	}

	b, err := json.Marshal(req)
	if err != nil {
		return "", errors.New("marshal tx request")
	}
	return string(b), nil
}

func ValidateTxPlanV0(txplan types.TxPlan) error {
	if txplan.Version != types.V0 {
		return fmt.Errorf("%w: unsupported version %q", ErrInvalidPlan, txplan.Version)
	}
	switch txplan.Kind {
	case types.TxPlanKindWithdrawal, types.TxPlanKindSweep, types.TxPlanKindRebalance:
	default:
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidPlan, txplan.Kind)
	}
	if strings.TrimSpace(txplan.WalletID) == "" {
		return fmt.Errorf("%w: wallet_id required", ErrInvalidPlan)
	}
	if strings.TrimSpace(txplan.Chain) == "" {
		return fmt.Errorf("%w: chain required", ErrInvalidPlan)
	}
	if txplan.CoinType == 0 {
		return fmt.Errorf("%w: coin_type required", ErrInvalidPlan)
	}
	switch strings.ToLower(strings.TrimSpace(txplan.Chain)) {
	case "main":
		if txplan.CoinType != 8133 {
			return fmt.Errorf("%w: coin_type must be 8133 on main", ErrInvalidPlan)
		}
	case "test", "testnet":
		if txplan.CoinType != 8134 {
			return fmt.Errorf("%w: coin_type must be 8134 on testnet", ErrInvalidPlan)
		}
	case "regtest":
		if txplan.CoinType != 8135 {
			return fmt.Errorf("%w: coin_type must be 8135 on regtest", ErrInvalidPlan)
		}
	default:
		return fmt.Errorf("%w: unsupported chain %q", ErrInvalidPlan, txplan.Chain)
	}
	if txplan.BranchID == 0 {
		return fmt.Errorf("%w: branch_id required", ErrInvalidPlan)
	}
	if txplan.AnchorHeight == 0 {
		return fmt.Errorf("%w: anchor_height required", ErrInvalidPlan)
	}
	if strings.TrimSpace(txplan.Anchor) == "" {
		return fmt.Errorf("%w: anchor required", ErrInvalidPlan)
	}
	if len(strings.TrimSpace(txplan.Anchor)) != 64 {
		return fmt.Errorf("%w: anchor must be 32-byte hex", ErrInvalidPlan)
	}
	if _, err := hex.DecodeString(strings.TrimSpace(txplan.Anchor)); err != nil {
		return fmt.Errorf("%w: anchor must be hex", ErrInvalidPlan)
	}
	if txplan.ExpiryHeight == 0 {
		return fmt.Errorf("%w: expiry_height required", ErrInvalidPlan)
	}
	if strings.TrimSpace(txplan.ChangeAddress) == "" {
		return fmt.Errorf("%w: change_address required", ErrInvalidPlan)
	}
	if len(txplan.Outputs) == 0 {
		return fmt.Errorf("%w: outputs required", ErrInvalidPlan)
	}
	if len(txplan.Outputs) > 200 {
		return fmt.Errorf("%w: outputs too large", ErrInvalidPlan)
	}
	for i, out := range txplan.Outputs {
		if strings.TrimSpace(out.ToAddress) == "" {
			return fmt.Errorf("%w: outputs[%d].to_address required", ErrInvalidPlan, i)
		}
		if strings.TrimSpace(out.AmountZat) == "" {
			return fmt.Errorf("%w: outputs[%d].amount_zat required", ErrInvalidPlan, i)
		}
		memoHex := strings.TrimSpace(out.MemoHex)
		if memoHex == "" {
			continue
		}
		if len(memoHex)%2 != 0 {
			return fmt.Errorf("%w: outputs[%d].memo_hex must be even-length hex", ErrInvalidPlan, i)
		}
		b, err := hex.DecodeString(memoHex)
		if err != nil {
			return fmt.Errorf("%w: outputs[%d].memo_hex must be hex", ErrInvalidPlan, i)
		}
		if len(b) > 512 {
			return fmt.Errorf("%w: outputs[%d].memo_hex must be <=512 bytes", ErrInvalidPlan, i)
		}
	}
	if len(txplan.Notes) == 0 {
		return fmt.Errorf("%w: notes required", ErrInvalidPlan)
	}
	for i, n := range txplan.Notes {
		if strings.TrimSpace(n.ActionNullifier) == "" {
			return fmt.Errorf("%w: notes[%d].action_nullifier required", ErrInvalidPlan, i)
		}
		if len(strings.TrimSpace(n.ActionNullifier)) != 64 {
			return fmt.Errorf("%w: notes[%d].action_nullifier must be 32-byte hex", ErrInvalidPlan, i)
		}
		if _, err := hex.DecodeString(strings.TrimSpace(n.ActionNullifier)); err != nil {
			return fmt.Errorf("%w: notes[%d].action_nullifier must be hex", ErrInvalidPlan, i)
		}
		if strings.TrimSpace(n.CMX) == "" {
			return fmt.Errorf("%w: notes[%d].cmx required", ErrInvalidPlan, i)
		}
		if len(strings.TrimSpace(n.CMX)) != 64 {
			return fmt.Errorf("%w: notes[%d].cmx must be 32-byte hex", ErrInvalidPlan, i)
		}
		if _, err := hex.DecodeString(strings.TrimSpace(n.CMX)); err != nil {
			return fmt.Errorf("%w: notes[%d].cmx must be hex", ErrInvalidPlan, i)
		}
		if len(n.Path) != 32 {
			return fmt.Errorf("%w: notes[%d].path must have 32 elements", ErrInvalidPlan, i)
		}
		for j, p := range n.Path {
			if len(strings.TrimSpace(p)) != 64 {
				return fmt.Errorf("%w: notes[%d].path[%d] must be 32-byte hex", ErrInvalidPlan, i, j)
			}
			if _, err := hex.DecodeString(strings.TrimSpace(p)); err != nil {
				return fmt.Errorf("%w: notes[%d].path[%d] must be hex", ErrInvalidPlan, i, j)
			}
		}
		if strings.TrimSpace(n.EphemeralKey) == "" {
			return fmt.Errorf("%w: notes[%d].ephemeral_key required", ErrInvalidPlan, i)
		}
		if len(strings.TrimSpace(n.EphemeralKey)) != 64 {
			return fmt.Errorf("%w: notes[%d].ephemeral_key must be 32-byte hex", ErrInvalidPlan, i)
		}
		if _, err := hex.DecodeString(strings.TrimSpace(n.EphemeralKey)); err != nil {
			return fmt.Errorf("%w: notes[%d].ephemeral_key must be hex", ErrInvalidPlan, i)
		}
		if strings.TrimSpace(n.EncCiphertext) == "" {
			return fmt.Errorf("%w: notes[%d].enc_ciphertext required", ErrInvalidPlan, i)
		}
		if len(strings.TrimSpace(n.EncCiphertext)) != 104 {
			return fmt.Errorf("%w: notes[%d].enc_ciphertext must be 52-byte hex", ErrInvalidPlan, i)
		}
		if _, err := hex.DecodeString(strings.TrimSpace(n.EncCiphertext)); err != nil {
			return fmt.Errorf("%w: notes[%d].enc_ciphertext must be hex", ErrInvalidPlan, i)
		}
	}
	return nil
}
