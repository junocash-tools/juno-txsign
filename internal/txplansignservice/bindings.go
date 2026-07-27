package txplansignservice

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const maxBindingsFileBytes = 1 << 20

type Binding struct {
	WalletID string `json:"wallet_id"`
	Account  uint32 `json:"account"`
	Network  string `json:"network"`
	UFVK     string `json:"ufvk"`
}

type bindingsFile struct {
	Version  string    `json:"version"`
	Bindings []Binding `json:"bindings"`
}

type bindingKey struct {
	walletID string
	account  uint32
	network  string
}

type derivationKey struct {
	account uint32
	network string
}

func LoadBindings(path string) ([]Binding, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("txplan signer: bindings file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("txplan signer: open bindings file %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	if err := checkPrivateRegularFile(f, path); err != nil {
		return nil, fmt.Errorf("txplan signer: bindings file %s: %w", filepath.Base(path), err)
	}
	payload, err := io.ReadAll(io.LimitReader(f, maxBindingsFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("txplan signer: read bindings file %s: %w", filepath.Base(path), err)
	}
	if len(payload) > maxBindingsFileBytes {
		return nil, errors.New("txplan signer: bindings file exceeds 1048576 bytes")
	}
	if err := rejectDuplicateJSONNames(payload); err != nil {
		return nil, errors.New("txplan signer: bindings file contains invalid or duplicate JSON fields")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var file bindingsFile
	if err := decoder.Decode(&file); err != nil {
		return nil, errors.New("txplan signer: bindings file JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("txplan signer: bindings file must contain one JSON object")
	}
	if file.Version != JSONVersionV1 {
		return nil, errors.New("txplan signer: bindings file version must be v1")
	}
	if len(file.Bindings) == 0 || len(file.Bindings) > 256 {
		return nil, errors.New("txplan signer: bindings file must contain 1-256 bindings")
	}
	seen := make(map[bindingKey]struct{}, len(file.Bindings))
	for _, binding := range file.Bindings {
		if err := validateBinding(binding); err != nil {
			return nil, err
		}
		key := bindingKey{walletID: binding.WalletID, account: binding.Account, network: binding.Network}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("txplan signer: duplicate wallet/account/network binding")
		}
		seen[key] = struct{}{}
	}
	return append([]Binding(nil), file.Bindings...), nil
}

func VerifySeedBindings(ctx context.Context, seedBase64 string, bindings []Binding) error {
	if len(bindings) == 0 {
		return errors.New("txplan signer: at least one binding is required")
	}
	derived := make(map[derivationKey]string)
	for _, binding := range bindings {
		if err := validateBinding(binding); err != nil {
			return err
		}
		key := derivationKey{account: binding.Account, network: binding.Network}
		actual, exists := derived[key]
		if !exists {
			coinType, ok := coinTypeForNetwork(binding.Network)
			if !ok {
				return errors.New("txplan signer: binding network is invalid")
			}
			var err error
			actual, err = txsign.DeriveUFVK(ctx, seedBase64, coinType, binding.Account)
			if err != nil {
				return errors.New("txplan signer: could not derive UFVK for configured binding")
			}
			derived[key] = actual
		}
		if subtle.ConstantTimeCompare([]byte(actual), []byte(binding.UFVK)) != 1 {
			return fmt.Errorf("txplan signer: seed does not match UFVK binding for wallet %q", binding.WalletID)
		}
	}
	return nil
}

func validateBinding(binding Binding) error {
	if binding.WalletID == "" || binding.WalletID != strings.TrimSpace(binding.WalletID) ||
		len(binding.WalletID) > 128 || strings.ContainsAny(binding.WalletID, "\r\n\x00") {
		return errors.New("txplan signer: binding contains an invalid wallet_id")
	}
	if binding.Account > 1<<31-1 {
		return errors.New("txplan signer: binding contains an invalid account")
	}
	network, ok := normalizeNetwork(binding.Network)
	if !ok || network != binding.Network {
		return errors.New("txplan signer: binding network must be mainnet, testnet, or regtest")
	}
	if binding.UFVK == "" || binding.UFVK != strings.TrimSpace(binding.UFVK) || len(binding.UFVK) > 1024 {
		return errors.New("txplan signer: binding contains an invalid UFVK")
	}
	prefix := map[string]string{
		"mainnet": "jview1",
		"testnet": "jviewtest1",
		"regtest": "jviewregtest1",
	}[network]
	if !strings.HasPrefix(binding.UFVK, prefix) {
		return errors.New("txplan signer: binding UFVK does not match its network")
	}
	return nil
}

func coinTypeForNetwork(network string) (uint32, bool) {
	switch network {
	case "mainnet":
		return 8133, true
	case "testnet":
		return 8134, true
	case "regtest":
		return 8135, true
	default:
		return 0, false
	}
}
