package txplansignservice

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const EnvSeedBase64 = "JUNO_TXSIGN_SEED_BASE64"

func LoadSeed(seedFile, seedEnv string) (string, error) {
	seedFile = strings.TrimSpace(seedFile)
	seedEnv = strings.TrimSpace(seedEnv)
	if (seedFile == "") == (seedEnv == "") {
		return "", errors.New("txplan signer: configure exactly one of --seed-file or JUNO_TXSIGN_SEED_BASE64")
	}
	seed := seedEnv
	if seedFile != "" {
		f, err := os.Open(seedFile)
		if err != nil {
			return "", fmt.Errorf("txplan signer: open seed file %s: %w", filepath.Base(seedFile), err)
		}
		defer f.Close()
		if err := checkPrivateRegularFile(f, seedFile); err != nil {
			return "", fmt.Errorf("txplan signer: seed file %s: %w", filepath.Base(seedFile), err)
		}
		payload, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil {
			return "", fmt.Errorf("txplan signer: read seed file %s: %w", filepath.Base(seedFile), err)
		}
		if len(payload) > 4096 {
			return "", errors.New("txplan signer: seed file exceeds 4096 bytes")
		}
		seed = strings.TrimSpace(string(payload))
	}
	decoded, err := base64.StdEncoding.DecodeString(seed)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != seed || len(decoded) < 32 || len(decoded) > 252 {
		clear(decoded)
		return "", errors.New("txplan signer: seed must be canonical base64 encoding 32-252 bytes")
	}
	clear(decoded)
	return seed, nil
}
