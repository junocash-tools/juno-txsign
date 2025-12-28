package mnemonic

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

func Extract24Words(s string) (string, error) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "===") {
			continue
		}
		words := strings.Fields(line)
		if len(words) == 24 {
			return strings.Join(words, " "), nil
		}
	}
	return "", errors.New("mnemonic not found")
}

func EntropyBase64FromMnemonic(mnemonic string) (string, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(entropy), nil
}

func SeedBase64FromMnemonic(mnemonic string) (string, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}
