package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/cliout"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const jsonVersionV1 = "v1"

func Run(args []string) int {
	return RunWithIO(args, os.Stdout, os.Stderr)
}

func RunWithIO(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		writeUsage(stdout)
		return 0
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "ext-prepare":
		return runExtPrepare(args[1:], stdout, stderr)
	case "ext-finalize":
		return runExtFinalize(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "juno-txsign")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Offline signer for TxPlan v0 packages.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  juno-txsign sign --txplan <path|-> --seed-base64 <b64> [--out <path>] [--json] [--action-indices]")
	fmt.Fprintln(w, "  juno-txsign ext-prepare --txplan <path|-> --ufvk <jview...> [--out-prepared <path>] [--out-requests <path>]")
	fmt.Fprintln(w, "  juno-txsign ext-finalize --prepared-tx <path> --sigs <path> [--out <path>] [--json] [--action-indices]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - This command performs no network calls.")
	fmt.Fprintln(w, "  - Do not log or store seeds/spending keys.")
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var txplanPath string
	var seedBase64 string
	var seedFile string
	var outPath string
	var jsonOut bool
	var actionIndices bool

	fs.StringVar(&txplanPath, "txplan", "", "path to TxPlan JSON (or - for stdin)")
	fs.StringVar(&seedBase64, "seed-base64", "", "seed in base64")
	fs.StringVar(&seedFile, "seed-file", "", "path to file containing base64 seed")
	fs.StringVar(&outPath, "out", "", "optional path to write raw tx hex")
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.BoolVar(&actionIndices, "action-indices", false, "include Orchard output action indices (requires --json)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	txplanPath = strings.TrimSpace(txplanPath)
	if txplanPath == "" {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "txplan is required")
	}

	seedBase64, err := loadSeed(seedBase64, seedFile)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}

	plan, err := loadTxPlan(txplanPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := txsign.Sign(ctx, plan, seedBase64)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "sign_failed", err.Error())
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(res.RawTxHex+"\n"), 0o600); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}

	if jsonOut {
		data := cliout.SignJSONData(
			cliout.SignOutput{
				TxID:                       res.TxID,
				RawTxHex:                   res.RawTxHex,
				FeeZat:                     res.FeeZat,
				OrchardOutputActionIndices: res.OrchardOutputActionIndices,
				OrchardChangeActionIndex:   res.OrchardChangeActionIndex,
			},
			actionIndices,
		)

		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"version": jsonVersionV1,
			"status":  "ok",
			"data":    data,
		})
		return 0
	}

	fmt.Fprintln(stdout, res.RawTxHex)
	return 0
}

func loadSeed(seedBase64, seedFile string) (string, error) {
	var sources int
	if strings.TrimSpace(seedBase64) != "" {
		sources++
	}
	if strings.TrimSpace(seedFile) != "" {
		sources++
	}
	if sources == 0 {
		return "", errors.New("seed-base64 is required (or use --seed-file)")
	}
	if sources > 1 {
		return "", errors.New("input source conflict (use only one of --seed-base64, --seed-file)")
	}
	if strings.TrimSpace(seedBase64) != "" {
		return strings.TrimSpace(seedBase64), nil
	}

	b, err := os.ReadFile(strings.TrimSpace(seedFile))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Base(seedFile), err)
	}
	return strings.TrimSpace(string(b)), nil
}

func loadUFVK(ufvk, ufvkFile string) (string, error) {
	var sources int
	if strings.TrimSpace(ufvk) != "" {
		sources++
	}
	if strings.TrimSpace(ufvkFile) != "" {
		sources++
	}
	if sources == 0 {
		return "", errors.New("ufvk is required (or use --ufvk-file)")
	}
	if sources > 1 {
		return "", errors.New("input source conflict (use only one of --ufvk, --ufvk-file)")
	}
	if strings.TrimSpace(ufvk) != "" {
		return strings.TrimSpace(ufvk), nil
	}

	b, err := os.ReadFile(strings.TrimSpace(ufvkFile))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Base(ufvkFile), err)
	}
	return strings.TrimSpace(string(b)), nil
}

func loadTxPlan(path string) (types.TxPlan, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return types.TxPlan{}, fmt.Errorf("open txplan: %w", err)
		}
		defer f.Close()
		r = f
	}

	var plan types.TxPlan
	dec := json.NewDecoder(r)
	if err := dec.Decode(&plan); err != nil {
		return types.TxPlan{}, errors.New("invalid txplan json")
	}
	return plan, nil
}

func writeErr(stdout, stderr io.Writer, jsonOut bool, code, msg string) int {
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"version": jsonVersionV1,
			"status":  "err",
			"error": map[string]any{
				"code":    code,
				"message": msg,
			},
		})
		return 1
	}
	if msg == "" {
		msg = code
	}
	fmt.Fprintln(stderr, msg)
	return 1
}

func runExtPrepare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ext-prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var txplanPath string
	var ufvk string
	var ufvkFile string
	var outPrepared string
	var outRequests string

	fs.StringVar(&txplanPath, "txplan", "", "path to TxPlan JSON (or - for stdin)")
	fs.StringVar(&ufvk, "ufvk", "", "unified full viewing key (jview...)")
	fs.StringVar(&ufvkFile, "ufvk-file", "", "path to file containing UFVK")
	fs.StringVar(&outPrepared, "out-prepared", "", "optional path to write prepared tx JSON")
	fs.StringVar(&outRequests, "out-requests", "", "optional path to write signing requests JSON")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	txplanPath = strings.TrimSpace(txplanPath)
	if txplanPath == "" {
		return writeErr(stdout, stderr, true, "invalid_request", "txplan is required")
	}

	ufvk, err := loadUFVK(ufvk, ufvkFile)
	if err != nil {
		return writeErr(stdout, stderr, true, "invalid_request", err.Error())
	}

	plan, err := loadTxPlan(txplanPath)
	if err != nil {
		return writeErr(stdout, stderr, true, "invalid_request", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := txsign.ExtPrepare(ctx, plan, ufvk)
	if err != nil {
		return writeErr(stdout, stderr, true, "prepare_failed", err.Error())
	}

	if outPrepared != "" {
		if err := os.WriteFile(outPrepared, append(res.PreparedTx, '\n'), 0o600); err != nil {
			return writeErr(stdout, stderr, true, "io_error", err.Error())
		}
	}
	if outRequests != "" {
		b, err := json.Marshal(res.SigningRequests)
		if err != nil {
			return writeErr(stdout, stderr, true, "io_error", "marshal signing requests")
		}
		if err := os.WriteFile(outRequests, append(b, '\n'), 0o600); err != nil {
			return writeErr(stdout, stderr, true, "io_error", err.Error())
		}
	}

	var preparedAny any
	if err := json.Unmarshal(res.PreparedTx, &preparedAny); err != nil {
		return writeErr(stdout, stderr, true, "prepare_failed", "invalid prepared tx")
	}

	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"version": jsonVersionV1,
		"status":  "ok",
		"data": map[string]any{
			"prepared_tx":      preparedAny,
			"signing_requests": res.SigningRequests,
		},
	})
	return 0
}

func runExtFinalize(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ext-finalize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var preparedPath string
	var sigsPath string
	var outPath string
	var jsonOut bool
	var actionIndices bool

	fs.StringVar(&preparedPath, "prepared-tx", "", "path to prepared tx JSON")
	fs.StringVar(&sigsPath, "sigs", "", "path to spend-auth signature submission JSON")
	fs.StringVar(&outPath, "out", "", "optional path to write raw tx hex")
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.BoolVar(&actionIndices, "action-indices", false, "include Orchard output action indices (requires --json)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	preparedPath = strings.TrimSpace(preparedPath)
	if preparedPath == "" {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "prepared-tx is required")
	}
	sigsPath = strings.TrimSpace(sigsPath)
	if sigsPath == "" {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "sigs is required")
	}

	preparedRaw, err := os.ReadFile(preparedPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}
	preparedRaw = []byte(strings.TrimSpace(string(preparedRaw)))
	if len(preparedRaw) == 0 {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "prepared-tx is empty")
	}

	sigsRaw, err := os.ReadFile(sigsPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}
	var sigs txsign.SpendAuthSigSubmission
	if err := json.Unmarshal(sigsRaw, &sigs); err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "invalid sigs json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := txsign.ExtFinalize(ctx, preparedRaw, sigs)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "finalize_failed", err.Error())
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(res.RawTxHex+"\n"), 0o600); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}

	if jsonOut {
		data := cliout.SignJSONData(
			cliout.SignOutput{
				TxID:                       res.TxID,
				RawTxHex:                   res.RawTxHex,
				FeeZat:                     res.FeeZat,
				OrchardOutputActionIndices: res.OrchardOutputActionIndices,
				OrchardChangeActionIndex:   res.OrchardChangeActionIndex,
			},
			actionIndices,
		)

		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"version": jsonVersionV1,
			"status":  "ok",
			"data":    data,
		})
		return 0
	}

	fmt.Fprintln(stdout, res.RawTxHex)
	return 0
}
