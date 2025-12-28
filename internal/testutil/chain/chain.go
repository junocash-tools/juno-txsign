package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Abdullah1738/juno-sdk-go/junocashd"
)

type RPC interface {
	Call(ctx context.Context, method string, params any, out any) error
}

type ChainInfo struct {
	Chain    string
	Height   int64
	BranchID uint32
}

func GetChainInfo(ctx context.Context, rpc RPC) (ChainInfo, error) {
	if rpc == nil {
		return ChainInfo{}, errors.New("chain: rpc is nil")
	}

	var resp struct {
		Chain     string `json:"chain"`
		Blocks    int64  `json:"blocks"`
		Consensus struct {
			Chaintip string `json:"chaintip"`
		} `json:"consensus"`
	}
	if err := rpc.Call(ctx, "getblockchaininfo", nil, &resp); err != nil {
		return ChainInfo{}, err
	}

	chain := strings.TrimSpace(resp.Chain)
	if chain == "" {
		return ChainInfo{}, errors.New("chain: missing chain")
	}

	chaintip := strings.TrimSpace(resp.Consensus.Chaintip)
	if chaintip == "" {
		return ChainInfo{}, errors.New("chain: missing consensus.chaintip")
	}
	branchU64, err := strconv.ParseUint(chaintip, 16, 32)
	if err != nil {
		return ChainInfo{}, errors.New("chain: invalid consensus.chaintip")
	}

	return ChainInfo{
		Chain:    chain,
		Height:   resp.Blocks,
		BranchID: uint32(branchU64),
	}, nil
}

type OrchardAction struct {
	TxID          string
	ActionIndex   uint32
	Position      uint32
	Nullifier     string
	CMX           string
	EphemeralKey  string
	EncCiphertext string
}

type OrchardIndex struct {
	CMXHex     []string
	ByOutpoint map[string]OrchardAction // key: txid:action_index
}

func BuildOrchardIndex(ctx context.Context, rpc *junocashd.Client, upToHeight int64) (OrchardIndex, error) {
	if rpc == nil {
		return OrchardIndex{}, errors.New("chain: rpc is nil")
	}
	if upToHeight < 0 {
		return OrchardIndex{}, errors.New("chain: height must be >= 0")
	}

	type action struct {
		Nullifier     string `json:"nullifier"`
		CMX           string `json:"cmx"`
		EphemeralKey  string `json:"ephemeralKey"`
		EncCiphertext string `json:"encCiphertext"`
	}
	type tx struct {
		TxID    string `json:"txid"`
		Orchard struct {
			Actions []action `json:"actions"`
		} `json:"orchard"`
	}
	type block struct {
		Tx []tx `json:"tx"`
	}

	out := OrchardIndex{
		CMXHex:     nil,
		ByOutpoint: make(map[string]OrchardAction),
	}

	var pos uint32
	for height := int64(0); height <= upToHeight; height++ {
		blockHash, err := rpc.GetBlockHash(ctx, height)
		if err != nil {
			return OrchardIndex{}, err
		}
		var blk block
		if err := rpc.Call(ctx, "getblock", []any{blockHash, 2}, &blk); err != nil {
			return OrchardIndex{}, err
		}
		for _, t := range blk.Tx {
			txid := strings.ToLower(strings.TrimSpace(t.TxID))
			if txid == "" {
				return OrchardIndex{}, errors.New("chain: missing txid")
			}
			for i, a := range t.Orchard.Actions {
				key := fmt.Sprintf("%s:%d", txid, i)
				act := OrchardAction{
					TxID:          txid,
					ActionIndex:   uint32(i),
					Position:      pos,
					Nullifier:     strings.ToLower(strings.TrimSpace(a.Nullifier)),
					CMX:           strings.ToLower(strings.TrimSpace(a.CMX)),
					EphemeralKey:  strings.ToLower(strings.TrimSpace(a.EphemeralKey)),
					EncCiphertext: strings.ToLower(strings.TrimSpace(a.EncCiphertext)),
				}

				if !is32ByteHex(act.CMX) || !is32ByteHex(act.Nullifier) || !is32ByteHex(act.EphemeralKey) {
					return OrchardIndex{}, errors.New("chain: invalid orchard action encoding")
				}
				if len(act.EncCiphertext) < 104 {
					return OrchardIndex{}, errors.New("chain: invalid orchard action encoding")
				}
				act.EncCiphertext = act.EncCiphertext[:104]
				if _, err := hex.DecodeString(act.EncCiphertext); err != nil {
					return OrchardIndex{}, errors.New("chain: invalid orchard action encoding")
				}

				out.CMXHex = append(out.CMXHex, act.CMX)
				out.ByOutpoint[key] = act
				pos++
			}
		}
	}

	return out, nil
}

func is32ByteHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
