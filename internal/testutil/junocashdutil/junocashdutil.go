package junocashdutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
)

func GenerateBlocks(ctx context.Context, jd *containers.Junocashd, count int) error {
	if jd == nil {
		return errors.New("junocashd: nil container")
	}
	if count <= 0 {
		return nil
	}
	_, err := jd.ExecCLI(ctx, "generate", strconv.Itoa(count))
	return err
}

type UnifiedAddress struct {
	Account         uint32 `json:"account"`
	Address         string `json:"address"`
	Diversifier     uint32 `json:"diversifier_index"`
	ReceiverTypes   []string
	ReceiverTypesIn json.RawMessage `json:"receiver_types"`
}

func GetUnifiedAddressForAccount(ctx context.Context, jd *containers.Junocashd, account uint32) (string, error) {
	if jd == nil {
		return "", errors.New("junocashd: nil container")
	}
	raw, err := jd.ExecCLI(ctx, "z_getaddressforaccount", strconv.FormatUint(uint64(account), 10))
	if err != nil {
		return "", err
	}
	var resp struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", errors.New("z_getaddressforaccount: invalid json")
	}
	addr := strings.TrimSpace(resp.Address)
	if addr == "" {
		return "", errors.New("z_getaddressforaccount: missing address")
	}
	return addr, nil
}

func ShieldCoinbaseTo(ctx context.Context, jd *containers.Junocashd, toAddress string) (string, error) {
	if jd == nil {
		return "", errors.New("junocashd: nil container")
	}
	toAddress = strings.TrimSpace(toAddress)
	if toAddress == "" {
		return "", errors.New("to address required")
	}

	raw, err := jd.ExecCLI(ctx, "z_shieldcoinbase", "*", toAddress)
	if err != nil {
		return "", err
	}

	var resp struct {
		OpID string `json:"opid"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", errors.New("z_shieldcoinbase: invalid json")
	}
	opid := strings.TrimSpace(resp.OpID)
	if opid == "" {
		return "", errors.New("z_shieldcoinbase: missing opid")
	}

	return waitOperationTxID(ctx, jd, opid)
}

func waitOperationTxID(ctx context.Context, jd *containers.Junocashd, opid string) (string, error) {
	opid = strings.TrimSpace(opid)
	if opid == "" {
		return "", errors.New("opid required")
	}

	type op struct {
		Status string `json:"status"`
		Result struct {
			TxID string `json:"txid"`
		} `json:"result,omitempty"`
		Error struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		raw, err := jd.ExecCLI(ctx, "z_getoperationstatus", fmt.Sprintf("[\"%s\"]", opid))
		if err != nil {
			return "", err
		}

		var ops []op
		if err := json.Unmarshal(raw, &ops); err != nil {
			return "", errors.New("z_getoperationstatus: invalid json")
		}
		if len(ops) != 1 {
			return "", errors.New("z_getoperationstatus: unexpected response")
		}

		switch strings.ToLower(strings.TrimSpace(ops[0].Status)) {
		case "success":
			txid := strings.TrimSpace(ops[0].Result.TxID)
			if txid == "" {
				return "", errors.New("operation missing txid")
			}
			return txid, nil
		case "failed":
			msg := strings.TrimSpace(ops[0].Error.Message)
			if msg == "" {
				msg = "operation failed"
			}
			return "", errors.New(msg)
		default:
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}
