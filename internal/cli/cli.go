package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/cliout"
	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
	"github.com/Abdullah1738/juno-txsign/internal/digestsignhttp"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const jsonVersionV1 = "v1"

var newHTTPClient = func() *http.Client {
	return &http.Client{}
}

var (
	signTransaction         = txsign.Sign
	prepareExternalSigning  = txsign.ExtPrepare
	finalizeExternalSigning = txsign.ExtFinalize
)

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
	case "sign-digest":
		return runSignDigest(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
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
	fmt.Fprintln(w, "  juno-txsign sign --txplan <path|-> --seed-base64 <b64> [--out <path>] [--out-result <path>] [--json] [--action-indices]")
	fmt.Fprintln(w, "  juno-txsign sign-digest --digest <0x32-byte-hex> [--operator-endpoint <url> ...] --json")
	fmt.Fprintln(w, "  juno-txsign serve --listen <addr>")
	fmt.Fprintln(w, "  juno-txsign ext-prepare --txplan <path|-> --ufvk <jview...> [--out-prepared <path>] [--out-requests <path>] [--out-result <path>]")
	fmt.Fprintln(w, "  juno-txsign ext-finalize --prepared-tx <path> --sigs <path> [--out <path>] [--out-result <path>] [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - Do not log or store seeds/spending keys.")
	fmt.Fprintln(w, "  - sign-digest reads signer keys from JUNO_TXSIGN_SIGNER_KEYS (comma-separated 32-byte hex keys).")
	fmt.Fprintln(w, "  - sign and ext-* remain offline; sign-digest can also query remote operator endpoints.")
	fmt.Fprintln(w, "  - serve exposes POST /v1/sign-digest and GET /healthz on the listen address.")
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var txplanPath string
	var seedBase64 string
	var seedFile string
	var outPath string
	var outResultPath string
	var jsonOut bool
	var actionIndices bool

	fs.StringVar(&txplanPath, "txplan", "", "path to TxPlan JSON (or - for stdin)")
	fs.StringVar(&seedBase64, "seed-base64", "", "seed in base64")
	fs.StringVar(&seedFile, "seed-file", "", "path to file containing base64 seed")
	fs.StringVar(&outPath, "out", "", "optional path to write raw tx hex")
	fs.StringVar(&outResultPath, "out-result", "", "optional path to write the JSON result")
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
	artifacts, err := prepareExclusiveArtifacts(outPath, outResultPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
	}
	defer abortExclusiveArtifacts(artifacts)

	seedBase64, err = loadSeed(seedBase64, seedFile)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}

	plan, err := loadTxPlan(txplanPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := signTransaction(ctx, plan, seedBase64)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "sign_failed", err.Error())
	}

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
	resultJSON, err := marshalJSONLine(map[string]any{
		"version": jsonVersionV1,
		"status":  "ok",
		"data":    data,
	})
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "io_error", "marshal signing result")
	}
	rawTxLine := []byte(res.RawTxHex + "\n")
	sealExclusiveArtifacts(artifacts)
	if artifacts[1] != nil {
		if err := artifacts[1].commit(resultJSON); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}
	if artifacts[0] != nil {
		if err := artifacts[0].commit(rawTxLine); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}

	if jsonOut {
		return writeSuccess(stdout, stderr, resultJSON)
	}
	return writeSuccess(stdout, stderr, rawTxLine)
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
		payload, err := marshalJSONLine(map[string]any{
			"version": jsonVersionV1,
			"status":  "err",
			"error": map[string]any{
				"code":    code,
				"message": msg,
			},
		})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "marshal error response:", err)
			return 1
		}
		if err := writeAll(stdout, payload); err != nil {
			_, _ = fmt.Fprintln(stderr, "write stdout:", err)
		}
		return 1
	}
	if msg == "" {
		msg = code
	}
	fmt.Fprintln(stderr, msg)
	return 1
}

func marshalJSONLine(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func writeSuccess(stdout, stderr io.Writer, payload []byte) int {
	if err := writeAll(stdout, payload); err != nil {
		_, _ = fmt.Fprintln(stderr, "write stdout:", err)
		return 1
	}
	return 0
}

func runExtPrepare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ext-prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var txplanPath string
	var ufvk string
	var ufvkFile string
	var outPrepared string
	var outRequests string
	var outResultPath string

	fs.StringVar(&txplanPath, "txplan", "", "path to TxPlan JSON (or - for stdin)")
	fs.StringVar(&ufvk, "ufvk", "", "unified full viewing key (jview...)")
	fs.StringVar(&ufvkFile, "ufvk-file", "", "path to file containing UFVK")
	fs.StringVar(&outPrepared, "out-prepared", "", "optional path to write prepared tx JSON")
	fs.StringVar(&outRequests, "out-requests", "", "optional path to write signing requests JSON")
	fs.StringVar(&outResultPath, "out-result", "", "optional path to write the JSON result")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	txplanPath = strings.TrimSpace(txplanPath)
	if txplanPath == "" {
		return writeErr(stdout, stderr, true, "invalid_request", "txplan is required")
	}
	artifacts, err := prepareExclusiveArtifacts(outPrepared, outRequests, outResultPath)
	if err != nil {
		return writeErr(stdout, stderr, true, "io_error", err.Error())
	}
	defer abortExclusiveArtifacts(artifacts)

	ufvk, err = loadUFVK(ufvk, ufvkFile)
	if err != nil {
		return writeErr(stdout, stderr, true, "invalid_request", err.Error())
	}

	plan, err := loadTxPlan(txplanPath)
	if err != nil {
		return writeErr(stdout, stderr, true, "invalid_request", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := prepareExternalSigning(ctx, plan, ufvk)
	if err != nil {
		return writeErr(stdout, stderr, true, "prepare_failed", err.Error())
	}

	var preparedAny any
	if err := json.Unmarshal(res.PreparedTx, &preparedAny); err != nil {
		return writeErr(stdout, stderr, true, "prepare_failed", "invalid prepared tx")
	}
	requestsJSON, err := marshalJSONLine(res.SigningRequests)
	if err != nil {
		return writeErr(stdout, stderr, true, "io_error", "marshal signing requests")
	}
	resultJSON, err := marshalJSONLine(map[string]any{
		"version": jsonVersionV1,
		"status":  "ok",
		"data": map[string]any{
			"prepared_tx":      preparedAny,
			"signing_requests": res.SigningRequests,
		},
	})
	if err != nil {
		return writeErr(stdout, stderr, true, "io_error", "marshal prepare result")
	}
	preparedJSON := append(append([]byte(nil), res.PreparedTx...), '\n')
	sealExclusiveArtifacts(artifacts)
	for i, payload := range [][]byte{preparedJSON, requestsJSON, resultJSON} {
		if artifacts[i] != nil {
			if err := artifacts[i].commit(payload); err != nil {
				return writeErr(stdout, stderr, true, "io_error", err.Error())
			}
		}
	}
	return writeSuccess(stdout, stderr, resultJSON)
}

func runSignDigest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign-digest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var digestHex string
	var operatorEndpoints stringListFlag
	var jsonOut bool

	fs.StringVar(&digestHex, "digest", "", "final EIP-712 digest (0x-prefixed 32-byte hex)")
	fs.Var(&operatorEndpoints, "operator-endpoint", "operator base URL (repeatable)")
	fs.BoolVar(&jsonOut, "json", false, "JSON output (required)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeSignDigestUsage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	if !jsonOut {
		fmt.Fprintln(stderr, "--json is required")
		return 2
	}

	digestHex = strings.TrimSpace(digestHex)
	if digestHex == "" {
		return writeSignDigestErr(stdout, stderr, "invalid_request", "digest is required", 2)
	}

	digest, err := digestsign.ParseDigestHex(digestHex)
	if err != nil {
		return writeSignDigestErr(stdout, stderr, "invalid_request", err.Error(), 1)
	}

	keys, err := digestsign.LoadSignerKeysFromEnv()
	if err != nil {
		return writeSignDigestErr(stdout, stderr, "sign_failed", err.Error(), 1)
	}

	sigs, err := digestsign.SignDigest(digest, keys)
	if err != nil {
		return writeSignDigestErr(stdout, stderr, "sign_failed", err.Error(), 1)
	}

	for i, endpoint := range operatorEndpoints {
		if _, err := digestsign.ParseOperatorEndpoint(endpoint); err != nil {
			return writeSignDigestErr(stdout, stderr, "invalid_request", fmt.Sprintf("operator endpoint %d: %s", i+1, err.Error()), 1)
		}
	}

	remoteSigSets, err := digestsign.CollectRemoteSignatures(context.Background(), digest, operatorEndpoints, newHTTPClient())
	if err != nil {
		return writeSignDigestErr(stdout, stderr, "sign_failed", err.Error(), 1)
	}
	if len(remoteSigSets) > 0 {
		signatureSets := make([][]string, 0, len(remoteSigSets)+1)
		signatureSets = append(signatureSets, sigs)
		signatureSets = append(signatureSets, remoteSigSets...)
		sigs, err = digestsign.MergeSignatureSets(digest, signatureSets...)
		if err != nil {
			return writeSignDigestErr(stdout, stderr, "sign_failed", err.Error(), 1)
		}
	}

	type signDigestData struct {
		Signatures []string `json:"signatures"`
	}
	type signDigestOK struct {
		Version string         `json:"version"`
		Status  string         `json:"status"`
		Data    signDigestData `json:"data"`
	}
	payload, err := marshalJSONLine(signDigestOK{
		Version: jsonVersionV1,
		Status:  "ok",
		Data: signDigestData{
			Signatures: sigs,
		},
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "marshal signing result:", err)
		return 1
	}
	return writeSuccess(stdout, stderr, payload)
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var listen string
	var maxBodyBytes int64

	fs.StringVar(&listen, "listen", "127.0.0.1:8080", "listen address (host:port)")
	fs.Int64Var(&maxBodyBytes, "max-body-bytes", 1<<20, "max request body bytes")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeServeUsage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	listen = strings.TrimSpace(listen)
	if listen == "" {
		fmt.Fprintln(stderr, "listen is required")
		return 1
	}

	keys, err := digestsign.LoadSignerKeysFromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	api, err := digestsignhttp.New(keys, digestsignhttp.WithMaxBodyBytes(maxBodyBytes))
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		fmt.Fprintln(stderr, err.Error())
		return 1
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return 0
	}
}

func writeSignDigestUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  juno-txsign sign-digest --digest <0x32-byte-hex> [--operator-endpoint <url> ...] --json")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --digest              final EIP-712 digest (0x-prefixed 32-byte hex)")
	fmt.Fprintln(w, "  --operator-endpoint   operator base URL; repeat to collect remote signatures")
	fmt.Fprintln(w, "  --json                JSON output (required)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - Local signing via JUNO_TXSIGN_SIGNER_KEYS is always required.")
	fmt.Fprintln(w, "  - Each operator endpoint must be an http(s) origin/base URL; juno-txsign calls /v1/sign-digest.")
}

func writeServeUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  juno-txsign serve [--listen <addr>] [--max-body-bytes <n>]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --listen          listen address (host:port)")
	fmt.Fprintln(w, "  --max-body-bytes  max request body bytes")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - serve requires JUNO_TXSIGN_SIGNER_KEYS at startup.")
	fmt.Fprintln(w, "  - Endpoints: GET /healthz, POST /v1/sign-digest")
}

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func writeSignDigestErr(stdout, stderr io.Writer, code, msg string, exitCode int) int {
	type errBody struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type signDigestErr struct {
		Version string  `json:"version"`
		Status  string  `json:"status"`
		Error   errBody `json:"error"`
	}
	payload, err := marshalJSONLine(signDigestErr{
		Version: jsonVersionV1,
		Status:  "err",
		Error: errBody{
			Code:    code,
			Message: msg,
		},
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "marshal error response:", err)
		return exitCode
	}
	if err := writeAll(stdout, payload); err != nil {
		_, _ = fmt.Fprintln(stderr, "write stdout:", err)
	}
	return exitCode
}

func runExtFinalize(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ext-finalize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var preparedPath string
	var sigsPath string
	var outPath string
	var outResultPath string
	var jsonOut bool
	var actionIndices bool

	fs.StringVar(&preparedPath, "prepared-tx", "", "path to prepared tx JSON")
	fs.StringVar(&sigsPath, "sigs", "", "path to spend-auth signature submission JSON")
	fs.StringVar(&outPath, "out", "", "optional path to write raw tx hex")
	fs.StringVar(&outResultPath, "out-result", "", "optional path to write the JSON result")
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.BoolVar(&actionIndices, "action-indices", false, "unsupported legacy flag")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if actionIndices {
		return writeErr(
			stdout,
			stderr,
			jsonOut,
			"invalid_request",
			"--action-indices is not supported by ext-finalize; use the integrity-bound ext-prepare artifact",
		)
	}

	preparedPath = strings.TrimSpace(preparedPath)
	if preparedPath == "" {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "prepared-tx is required")
	}
	sigsPath = strings.TrimSpace(sigsPath)
	if sigsPath == "" {
		return writeErr(stdout, stderr, jsonOut, "invalid_request", "sigs is required")
	}
	artifacts, err := prepareExclusiveArtifacts(outPath, outResultPath)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
	}
	defer abortExclusiveArtifacts(artifacts)

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

	res, err := finalizeExternalSigning(ctx, preparedRaw, sigs)
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "finalize_failed", err.Error())
	}

	resultJSON, err := marshalJSONLine(map[string]any{
		"version": jsonVersionV1,
		"status":  "ok",
		"data": map[string]any{
			"txid":       res.TxID,
			"raw_tx_hex": res.RawTxHex,
			"fee_zat":    res.FeeZat,
		},
	})
	if err != nil {
		return writeErr(stdout, stderr, jsonOut, "io_error", "marshal finalize result")
	}
	rawTxLine := []byte(res.RawTxHex + "\n")
	sealExclusiveArtifacts(artifacts)
	if artifacts[1] != nil {
		if err := artifacts[1].commit(resultJSON); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}
	if artifacts[0] != nil {
		if err := artifacts[0].commit(rawTxLine); err != nil {
			return writeErr(stdout, stderr, jsonOut, "io_error", err.Error())
		}
	}

	if jsonOut {
		return writeSuccess(stdout, stderr, resultJSON)
	}
	return writeSuccess(stdout, stderr, rawTxLine)
}
