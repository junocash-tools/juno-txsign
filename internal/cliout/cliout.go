package cliout

type SignOutput struct {
	TxID     string
	RawTxHex string
	FeeZat   string

	OrchardOutputActionIndices []uint32
	OrchardChangeActionIndex   *uint32
}

func SignJSONData(out SignOutput, includeActionIndices bool) map[string]any {
	data := map[string]any{
		"txid":       out.TxID,
		"raw_tx_hex": out.RawTxHex,
		"fee_zat":    out.FeeZat,
	}
	if includeActionIndices {
		data["orchard_output_action_indices"] = out.OrchardOutputActionIndices
		data["orchard_change_action_index"] = out.OrchardChangeActionIndex
	}
	return data
}
