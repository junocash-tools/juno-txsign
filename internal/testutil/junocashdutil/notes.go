package junocashdutil

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
)

type UnspentOrchardNote struct {
	TxID      string
	OutIndex  uint32
	AmountZat uint64
	Account   uint32
	Address   string
}

func ListUnspentOrchard(ctx context.Context, jd *containers.Junocashd, minConf int64, account uint32) ([]UnspentOrchardNote, error) {
	notes, err := ListAllUnspentOrchard(ctx, jd, minConf)
	if err != nil {
		return nil, err
	}

	out := make([]UnspentOrchardNote, 0, len(notes))
	for _, note := range notes {
		if note.Account == account {
			out = append(out, note)
		}
	}
	return out, nil
}

func ListAllUnspentOrchard(ctx context.Context, jd *containers.Junocashd, minConf int64) ([]UnspentOrchardNote, error) {
	if jd == nil {
		return nil, errors.New("junocashd: nil container")
	}

	raw, err := jd.ExecCLI(ctx, "z_listunspent", strconv.FormatInt(minConf, 10), "9999999", "true")
	if err != nil {
		return nil, err
	}
	return parseUnspentOrchard(raw)
}

func parseUnspentOrchard(raw []byte) ([]UnspentOrchardNote, error) {
	var notes []struct {
		TxID      string      `json:"txid"`
		Pool      string      `json:"pool"`
		OutIndex  uint32      `json:"outindex"`
		Spendable bool        `json:"spendable"`
		Account   *uint32     `json:"account,omitempty"`
		Address   string      `json:"address"`
		Amount    json.Number `json:"amount"`
	}
	if err := json.Unmarshal(raw, &notes); err != nil {
		return nil, errors.New("z_listunspent: invalid json")
	}

	out := make([]UnspentOrchardNote, 0, len(notes))
	for _, n := range notes {
		if strings.ToLower(strings.TrimSpace(n.Pool)) != "orchard" {
			continue
		}
		if !n.Spendable {
			continue
		}
		if n.Account == nil {
			return nil, errors.New("z_listunspent: spendable Orchard note missing account")
		}
		txid := strings.ToLower(strings.TrimSpace(n.TxID))
		if txid == "" {
			return nil, errors.New("z_listunspent: spendable Orchard note missing txid")
		}
		address := strings.TrimSpace(n.Address)

		zat, err := parseZECToZat(n.Amount.String())
		if err != nil {
			return nil, err
		}

		out = append(out, UnspentOrchardNote{
			TxID:      txid,
			OutIndex:  n.OutIndex,
			AmountZat: zat,
			Account:   *n.Account,
			Address:   address,
		})
	}

	return out, nil
}
