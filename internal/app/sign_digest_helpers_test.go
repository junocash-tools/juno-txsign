//go:build integration || e2e

package app

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

func evmAddressHexForTest(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}
