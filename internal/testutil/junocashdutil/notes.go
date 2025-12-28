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
}

func ListUnspentOrchard(ctx context.Context, jd *containers.Junocashd, minConf int64, account uint32) ([]UnspentOrchardNote, error) {
	if jd == nil {
		return nil, errors.New("junocashd: nil container")
	}

	raw, err := jd.ExecCLI(ctx, "z_listunspent", strconv.FormatInt(minConf, 10), "9999999", "true")
	if err != nil {
		return nil, err
	}

	var notes []struct {
		TxID      string      `json:"txid"`
		Pool      string      `json:"pool"`
		OutIndex  uint32      `json:"outindex"`
		Spendable bool        `json:"spendable"`
		Account   *uint32     `json:"account,omitempty"`
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
		if n.Account != nil && *n.Account != account {
			continue
		}
		txid := strings.ToLower(strings.TrimSpace(n.TxID))
		if txid == "" {
			continue
		}

		zat, err := parseZECToZat(n.Amount.String())
		if err != nil {
			return nil, err
		}

		out = append(out, UnspentOrchardNote{
			TxID:      txid,
			OutIndex:  n.OutIndex,
			AmountZat: zat,
		})
	}

	return out, nil
}
