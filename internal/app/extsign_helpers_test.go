//go:build integration || e2e

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/testutil/containers"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func exportUFVK(t *testing.T, jd *containers.Junocashd, ua string) string {
	t.Helper()
	raw, err := jd.ExecCLI(context.Background(), "z_exportviewingkey", strings.TrimSpace(ua))
	if err != nil {
		t.Fatalf("z_exportviewingkey: %v", err)
	}
	ufvk := strings.TrimSpace(string(raw))
	if ufvk == "" {
		t.Fatalf("ufvk empty")
	}
	return ufvk
}

var (
	txbuildOnce    sync.Once
	txbuildBinPath string
	txbuildBinErr  error
)

func txbuildBin(t *testing.T) string {
	t.Helper()

	txbuildOnce.Do(func() {
		txbuildRepo := filepath.Clean(filepath.Join(repoRoot(), "..", "juno-txbuild"))
		if _, err := os.Stat(filepath.Join(txbuildRepo, "go.mod")); err != nil {
			txbuildBinErr = errors.New("juno-txbuild repo not found")
			return
		}

		out := filepath.Join(txbuildRepo, "bin", "juno-txbuild")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cmd := exec.CommandContext(ctx, "make", "build")
		cmd.Dir = txbuildRepo
		cmd.Env = os.Environ()
		b, err := cmd.CombinedOutput()
		if err != nil {
			txbuildBinErr = errors.New(strings.TrimSpace(string(b)))
			return
		}

		if _, err := os.Stat(out); err != nil {
			txbuildBinErr = err
			return
		}
		txbuildBinPath = out
	})

	if txbuildBinErr != nil {
		t.Fatalf("txbuild binary: %v", txbuildBinErr)
	}
	return txbuildBinPath
}

func writeTxPlanSendViaTxbuild(t *testing.T, ctx context.Context, txbuild string, jd *containers.Junocashd, outPath string, toAddr, amountZat, changeAddr string) types.TxPlan {
	t.Helper()

	cmd := exec.CommandContext(ctx, txbuild,
		"send",
		"--rpc-url", jd.RPCURL,
		"--rpc-user", jd.RPCUser,
		"--rpc-pass", jd.RPCPassword,
		"--wallet-id", "test-wallet",
		"--coin-type", strconv.FormatUint(uint64(coinTypeForChain("regtest")), 10),
		"--account", "0",
		"--to", toAddr,
		"--amount-zat", amountZat,
		"--change-address", changeAddr,
		"--out", outPath,
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("juno-txbuild: %v: %s", err, strings.TrimSpace(string(b)))
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read txplan: %v", err)
	}
	var plan types.TxPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("txplan json invalid: %v", err)
	}
	return plan
}

func spendAuthSignerBin(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(repoRoot(), "rust", "juno-tx", "target", "release", "juno_orchard_spendauth_sign")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if _, err := os.Stat(bin); err == nil {
		return bin
	}

	// Fallback: build if tests are run without `make rust-build`.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cargo", "build", "--release", "--manifest-path", filepath.Join(repoRoot(), "rust", "juno-tx", "Cargo.toml"))
	cmd.Dir = repoRoot()
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cargo build juno-tx: %v: %s", err, strings.TrimSpace(string(b)))
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("spend-auth signer binary not found: %v", err)
	}
	return bin
}

func writeSigningRequests(t *testing.T, outPath string, reqs txsign.SigningRequests) {
	t.Helper()
	b, err := json.Marshal(reqs)
	if err != nil {
		t.Fatalf("marshal signing requests: %v", err)
	}
	if err := os.WriteFile(outPath, append(b, '\n'), 0o600); err != nil {
		t.Fatalf("write signing requests: %v", err)
	}
}

func runSpendAuthSigner(t *testing.T, ctx context.Context, signerBin, requestsPath, seedPath, outPath string, coinType, account uint32) error {
	t.Helper()
	cmd := exec.CommandContext(ctx, signerBin,
		"--requests", requestsPath,
		"--coin-type", strconv.FormatUint(uint64(coinType), 10),
		"--account", strconv.FormatUint(uint64(account), 10),
		"--seed-file", seedPath,
		"--out", outPath,
	)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(b)))
	}
	return nil
}
