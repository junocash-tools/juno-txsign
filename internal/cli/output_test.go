package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

type failedOutputWriter struct{}

func (failedOutputWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestExclusiveArtifactCommitIsOwnerOnlyAndNonOverwriting(t *testing.T) {
	target := filepath.Join(t.TempDir(), "result.json")
	artifacts, err := prepareExclusiveArtifacts(target)
	if err != nil {
		t.Fatal(err)
	}
	defer abortExclusiveArtifacts(artifacts)
	sealExclusiveArtifacts(artifacts)
	if err := artifacts[0].commit([]byte("result\n")); err != nil {
		t.Fatal(err)
	}

	assertFile(t, target, "result\n")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%04o want=0600", got)
	}
	if _, err := os.Lstat(target + pendingArtifactSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending reservation remains after commit: %v", err)
	}
	if _, err := prepareExclusiveArtifacts(target); err == nil || !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("expected existing-output rejection, got %v", err)
	}
}

func TestExclusiveArtifactWriteFailureRetainsReservation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "rawtx.hex")
	artifacts, err := prepareExclusiveArtifacts(target)
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifacts[0]
	sealExclusiveArtifacts(artifacts)
	if err := artifact.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := artifact.commit([]byte("signed\n")); err == nil || !strings.Contains(err.Error(), "do not retry") {
		t.Fatalf("expected fail-closed commit error, got %v", err)
	}
	abortExclusiveArtifacts(artifacts)

	if _, err := os.Stat(target + pendingArtifactSuffix); err != nil {
		t.Fatalf("pending reservation not retained: %v", err)
	}
	if _, err := prepareExclusiveArtifacts(target); err == nil || !strings.Contains(err.Error(), "reservation already exists") {
		t.Fatalf("expected pending-reservation rejection, got %v", err)
	}
	_ = os.Remove(artifact.tempPath)
	_ = os.Remove(artifact.pendingPath)
}

func TestRunSignWritesOneShotArtifactsAndPropagatesStdoutFailure(t *testing.T) {
	original := signTransaction
	t.Cleanup(func() { signTransaction = original })
	calls := 0
	changeIndex := uint32(1)
	signTransaction = func(context.Context, types.TxPlan, string) (txsign.Result, error) {
		calls++
		return txsign.Result{
			TxID:                       strings.Repeat("a", 64),
			RawTxHex:                   "deadbeef",
			FeeZat:                     "200000",
			OrchardOutputActionIndices: []uint32{0},
			OrchardChangeActionIndex:   &changeIndex,
		}, nil
	}

	dir := t.TempDir()
	planPath := writeCLIFile(t, dir, "plan.json", "{}\n")
	rawPath := filepath.Join(dir, "rawtx.hex")
	resultPath := filepath.Join(dir, "signed.json")
	var stderr bytes.Buffer
	args := []string{
		"sign", "--txplan", planPath, "--seed-base64", "dGVzdA==",
		"--out", rawPath, "--out-result", resultPath, "--json", "--action-indices",
	}
	if code := RunWithIO(args, failedOutputWriter{}, &stderr); code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if !strings.Contains(stderr.String(), "write stdout") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if calls != 1 {
		t.Fatalf("sign calls=%d want=1", calls)
	}
	assertFile(t, rawPath, "deadbeef\n")
	assertSuccessResult(t, resultPath, strings.Repeat("a", 64))

	var stdout bytes.Buffer
	stderr.Reset()
	if code := RunWithIO(args, &stdout, &stderr); code != 1 {
		t.Fatalf("repeat code=%d want=1", code)
	}
	if calls != 1 {
		t.Fatalf("existing output invoked signer: calls=%d", calls)
	}
	if !strings.Contains(stdout.String(), `"code":"io_error"`) {
		t.Fatalf("repeat response=%q", stdout.String())
	}
	assertFile(t, rawPath, "deadbeef\n")
}

func TestRunExtPrepareWritesOneShotArtifactsAndPropagatesStdoutFailure(t *testing.T) {
	original := prepareExternalSigning
	t.Cleanup(func() { prepareExternalSigning = original })
	calls := 0
	prepareExternalSigning = func(context.Context, types.TxPlan, string) (txsign.ExtPrepareResult, error) {
		calls++
		return txsign.ExtPrepareResult{
			PreparedTx: json.RawMessage(`{"version":"v0","payload":"prepared"}`),
			SigningRequests: txsign.SigningRequests{
				Version: "v0",
				Requests: []txsign.SigningRequest{{
					Sighash: strings.Repeat("1", 64), Alpha: strings.Repeat("2", 64), RK: strings.Repeat("3", 64),
				}},
			},
		}, nil
	}

	dir := t.TempDir()
	planPath := writeCLIFile(t, dir, "plan.json", "{}\n")
	preparedPath := filepath.Join(dir, "prepared.json")
	requestsPath := filepath.Join(dir, "requests.json")
	resultPath := filepath.Join(dir, "prepare-result.json")
	var stderr bytes.Buffer
	args := []string{
		"ext-prepare", "--txplan", planPath, "--ufvk", "jview1test",
		"--out-prepared", preparedPath, "--out-requests", requestsPath, "--out-result", resultPath,
	}
	if code := RunWithIO(args, failedOutputWriter{}, &stderr); code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if !strings.Contains(stderr.String(), "write stdout") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if calls != 1 {
		t.Fatalf("prepare calls=%d want=1", calls)
	}
	assertFile(t, preparedPath, "{\"version\":\"v0\",\"payload\":\"prepared\"}\n")
	assertJSONFile(t, requestsPath)
	assertJSONFile(t, resultPath)

	var stdout bytes.Buffer
	stderr.Reset()
	if code := RunWithIO(args, &stdout, &stderr); code != 1 {
		t.Fatalf("repeat code=%d want=1", code)
	}
	if calls != 1 {
		t.Fatalf("existing output invoked prepare: calls=%d", calls)
	}
	if !strings.Contains(stdout.String(), `"code":"io_error"`) {
		t.Fatalf("repeat response=%q", stdout.String())
	}
}

func TestRunExtFinalizeWritesOneShotArtifactsAndPropagatesStdoutFailure(t *testing.T) {
	original := finalizeExternalSigning
	t.Cleanup(func() { finalizeExternalSigning = original })
	calls := 0
	finalizeExternalSigning = func(context.Context, txsign.PreparedTx, txsign.SpendAuthSigSubmission) (txsign.ExtFinalizeResult, error) {
		calls++
		return txsign.ExtFinalizeResult{
			TxID: strings.Repeat("b", 64), RawTxHex: "cafebabe", FeeZat: "200000",
		}, nil
	}

	dir := t.TempDir()
	preparedPath := writeCLIFile(t, dir, "prepared.json", "{\"version\":\"v0\"}\n")
	sigsPath := writeCLIFile(t, dir, "sigs.json", "{\"version\":\"v0\",\"signatures\":[]}\n")
	rawPath := filepath.Join(dir, "rawtx.hex")
	resultPath := filepath.Join(dir, "signed.json")
	var stderr bytes.Buffer
	args := []string{
		"ext-finalize", "--prepared-tx", preparedPath, "--sigs", sigsPath,
		"--out", rawPath, "--out-result", resultPath, "--json",
	}
	if code := RunWithIO(args, failedOutputWriter{}, &stderr); code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if !strings.Contains(stderr.String(), "write stdout") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if calls != 1 {
		t.Fatalf("finalize calls=%d want=1", calls)
	}
	assertFile(t, rawPath, "cafebabe\n")
	assertSuccessResult(t, resultPath, strings.Repeat("b", 64))

	var stdout bytes.Buffer
	stderr.Reset()
	if code := RunWithIO(args, &stdout, &stderr); code != 1 {
		t.Fatalf("repeat code=%d want=1", code)
	}
	if calls != 1 {
		t.Fatalf("existing output invoked finalize: calls=%d", calls)
	}
	if !strings.Contains(stdout.String(), `"code":"io_error"`) {
		t.Fatalf("repeat response=%q", stdout.String())
	}
}

func TestRunSignDigestPropagatesStdoutFailure(t *testing.T) {
	t.Setenv("JUNO_TXSIGN_SIGNER_KEYS", "4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a")
	var stderr bytes.Buffer
	code := RunWithIO([]string{
		"sign-digest",
		"--digest", "0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1",
		"--json",
	}, failedOutputWriter{}, &stderr)
	if code != 1 {
		t.Fatalf("code=%d want=1", code)
	}
	if !strings.Contains(stderr.String(), "write stdout") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func writeCLIFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertFile(t *testing.T, path, expected string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expected {
		t.Fatalf("%s=%q want=%q", filepath.Base(path), string(body), expected)
	}
}

func assertJSONFile(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) {
		t.Fatalf("%s is not valid JSON: %q", filepath.Base(path), string(body))
	}
}

func assertSuccessResult(t *testing.T, path, txid string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Data    struct {
			TxID string `json:"txid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != "v1" || result.Status != "ok" || result.Data.TxID != txid {
		t.Fatalf("unexpected result: %+v", result)
	}
}
