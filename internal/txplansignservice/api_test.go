package txplansignservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestAPIReplayConflictAndRestart(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	signer := func(context.Context, types.TxPlan) (txsign.Result, error) {
		calls.Add(1)
		return testResult(), nil
	}
	api := newTestAPI(t, journal, signer, 1)
	req := testSignRequest(t, "withdrawal-1", testPlan(t, "hot", 0, "regtest"))

	first := callSign(t, api, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	firstBody := decodeSignResponse(t, first)
	if firstBody.Data == nil || firstBody.Data.Replayed {
		t.Fatalf("first response should not be replay: %+v", firstBody)
	}

	replay := callSign(t, api, req)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	replayBody := decodeSignResponse(t, replay)
	if replayBody.Data == nil || !replayBody.Data.Replayed {
		t.Fatalf("replay response missing replay flag: %+v", replayBody)
	}
	if firstBody.Data.RawTxHex != replayBody.Data.RawTxHex || firstBody.Data.TxID != replayBody.Data.TxID {
		t.Fatal("replay changed signed transaction bytes")
	}
	if calls.Load() != 1 {
		t.Fatalf("signer calls=%d want=1", calls.Load())
	}

	conflicting := testSignRequest(t, req.AttemptID, testPlanWithAmount(t, "2"))
	conflict := callSign(t, api, conflicting)
	if conflict.Code != http.StatusConflict || decodeSignResponse(t, conflict).Error.Code != "attempt_digest_conflict" {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartAPI := newTestAPI(t, restarted, func(context.Context, types.TxPlan) (txsign.Result, error) {
		t.Fatal("replay after restart called signer")
		return txsign.Result{}, nil
	}, 1)
	afterRestart := callSign(t, restartAPI, req)
	if afterRestart.Code != http.StatusOK || !decodeSignResponse(t, afterRestart).Data.Replayed {
		t.Fatalf("restart replay status=%d body=%s", afterRestart.Code, afterRestart.Body.String())
	}
}

func TestAPIBindsDigestToExactTxPlanBytes(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	var called atomic.Bool
	api := newTestAPI(t, journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
		called.Store(true)
		return testResult(), nil
	}, 1)
	req := testSignRequest(t, "digest-test", testPlan(t, "hot", 0, "regtest"))
	req.PlanDigest = "sha256:" + strings.Repeat("0", 64)

	response := callSign(t, api, req)
	if response.Code != http.StatusBadRequest || decodeSignResponse(t, response).Error.Code != "invalid_request" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if called.Load() {
		t.Fatal("digest mismatch reached signer")
	}
}

func TestAPIStrictPlanAndPolicyValidation(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	api := newTestAPI(t, journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
		return testResult(), nil
	}, 1)

	for _, tc := range []struct {
		attempt string
		wallet  string
		account uint32
		network string
	}{
		{attempt: "wrong-wallet", wallet: "cold", account: 0, network: "regtest"},
		{attempt: "wrong-account", wallet: "hot", account: 1, network: "regtest"},
		{attempt: "wrong-network", wallet: "hot", account: 0, network: "mainnet"},
	} {
		disallowed := testSignRequest(t, tc.attempt, testPlan(t, tc.wallet, tc.account, tc.network))
		response := callSign(t, api, disallowed)
		if response.Code != http.StatusForbidden || decodeSignResponse(t, response).Error.Code != "plan_not_allowed" {
			t.Fatalf("%s status=%d body=%s", tc.attempt, response.Code, response.Body.String())
		}
	}

	planBytes := testPlan(t, "hot", 0, "regtest")
	planBytes = bytes.Replace(planBytes, []byte(`"wallet_id":"hot"`), []byte(`"wallet_id":"hot","unknown":true`), 1)
	unknown := requestForBytes("unknown-field", planBytes)
	response := callSign(t, api, unknown)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "unknown fields") {
		t.Fatalf("unknown field status=%d body=%s", response.Code, response.Body.String())
	}

	duplicatePlanBytes := bytes.Replace(
		testPlan(t, "hot", 0, "regtest"),
		[]byte(`"wallet_id":"hot"`),
		[]byte(`"wallet_id":"hot","wallet_id":"hot"`),
		1,
	)
	duplicatePlan := callSign(t, api, requestForBytes("duplicate-plan", duplicatePlanBytes))
	if duplicatePlan.Code != http.StatusBadRequest || !strings.Contains(duplicatePlan.Body.String(), "duplicate object fields") {
		t.Fatalf("duplicate plan status=%d body=%s", duplicatePlan.Code, duplicatePlan.Body.String())
	}
}

func TestAPIRejectsDuplicateRequestFields(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	api := newTestAPI(t, journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
		return testResult(), nil
	}, 1)
	request := testSignRequest(t, "duplicate-request", testPlan(t, "hot", 0, "regtest"))
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"version":"v1"`), []byte(`"version":"v1","version":"v1"`), 1)
	httpRequest := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(payload))
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httpRequest)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "duplicate object fields") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAPIUnknownSigningOutcomeFailsClosedAcrossRestart(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	api := newTestAPI(t, journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
		return txsign.Result{}, context.Canceled
	}, 1)
	req := testSignRequest(t, "unknown-outcome", testPlan(t, "hot", 0, "regtest"))

	first := callSign(t, api, req)
	if first.Code != http.StatusInternalServerError || decodeSignResponse(t, first).Error.Code != "signing_outcome_unknown" {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	var called atomic.Bool
	restartAPI := newTestAPI(t, restarted, func(context.Context, types.TxPlan) (txsign.Result, error) {
		called.Store(true)
		return testResult(), nil
	}, 1)
	retry := callSign(t, restartAPI, req)
	if retry.Code != http.StatusConflict || decodeSignResponse(t, retry).Error.Code != "attempt_outcome_unknown" {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	if called.Load() {
		t.Fatal("unknown outcome was signed again")
	}
}

func TestAPIBoundsConcurrencyAndReplaysConcurrentSameAttempt(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	signer := func(context.Context, types.TxPlan) (txsign.Result, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return testResult(), nil
	}
	api := newTestAPI(t, journal, signer, 1)
	firstReq := testSignRequest(t, "concurrent-1", testPlan(t, "hot", 0, "regtest"))
	secondReq := testSignRequest(t, "concurrent-2", testPlan(t, "hot", 0, "regtest"))

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- callSign(t, api, firstReq) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first signing did not start")
	}
	busy := callSign(t, api, secondReq)
	if busy.Code != http.StatusTooManyRequests || decodeSignResponse(t, busy).Error.Code != "signer_busy" {
		t.Fatalf("busy status=%d body=%s", busy.Code, busy.Body.String())
	}

	replayDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { replayDone <- callSign(t, api, firstReq) }()
	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	if replay := <-replayDone; replay.Code != http.StatusOK || !decodeSignResponse(t, replay).Data.Replayed {
		t.Fatalf("concurrent replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("signer calls=%d want=1", calls.Load())
	}
}

func TestAPIBodyLimitAndHealth(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	api, err := New(
		journal,
		func(context.Context, types.TxPlan) (txsign.Result, error) { return testResult(), nil },
		testPolicy(),
		1,
		WithMaxBodyBytes(1280),
		WithMaxPlanBytes(128),
	)
	if err != nil {
		t.Fatal(err)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	health := httptest.NewRecorder()
	api.Handler().ServeHTTP(health, healthRequest)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"journal":"ready"`) ||
		!strings.Contains(health.Body.String(), `"binding_count":1`) {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, SignPath, strings.NewReader(strings.Repeat(" ", 2048)+"{}"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAPISigningContinuesAfterClientCancellation(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	api := newTestAPI(t, journal, func(ctx context.Context, _ types.TxPlan) (txsign.Result, error) {
		if ctx.Err() != nil || ctx.Done() != nil {
			return txsign.Result{}, errors.New("signing context was canceled by client")
		}
		return testResult(), nil
	}, 1)
	requestBody := testSignRequest(t, "canceled-client", testPlan(t, "hot", 0, "regtest"))
	payload, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpRequest := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(payload)).WithContext(ctx)
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAPIRejectsSignerResultInconsistentWithPlan(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	badResult := testResult()
	badResult.FeeZat = "99999"
	api := newTestAPI(t, journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
		return badResult, nil
	}, 1)
	request := testSignRequest(t, "bad-result", testPlan(t, "hot", 0, "regtest"))
	response := callSign(t, api, request)
	if response.Code != http.StatusInternalServerError || decodeSignResponse(t, response).Error.Code != "signing_outcome_unknown" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	state, _, err := journal.Lookup(request.AttemptID, request.PlanDigest)
	if err != nil || state != journalPending {
		t.Fatalf("state=%v err=%v; inconsistent result must remain pending", state, err)
	}
}

func TestAPIRejectsNonpositiveConfiguredLimits(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	policy := testPolicy()
	for _, option := range []Option{WithMaxBodyBytes(0), WithMaxBodyBytes(-1), WithMaxPlanBytes(0), WithMaxPlanBytes(-1)} {
		if _, err := New(journal, func(context.Context, types.TxPlan) (txsign.Result, error) {
			return testResult(), nil
		}, policy, 1, option); err == nil {
			t.Fatal("expected invalid configured limit error")
		}
	}
}

func newTestAPI(t *testing.T, journal *Journal, signer Signer, concurrency int) *API {
	t.Helper()
	api, err := New(
		journal,
		signer,
		testPolicy(),
		concurrency,
	)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func testPolicy() Policy {
	return Policy{Bindings: []Binding{{
		WalletID: "hot",
		Account:  0,
		Network:  "regtest",
		UFVK:     "jviewregtest1test-binding",
	}}}
}

func callSign(t *testing.T, api *API, request SignRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(payload))
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httpRequest)
	return response
}

func decodeSignResponse(t *testing.T, response *httptest.ResponseRecorder) SignResponse {
	t.Helper()
	var decoded SignResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v (%s)", err, response.Body.String())
	}
	return decoded
}

func testSignRequest(t *testing.T, attemptID string, planBytes []byte) SignRequest {
	t.Helper()
	return requestForBytes(attemptID, planBytes)
}

func requestForBytes(attemptID string, planBytes []byte) SignRequest {
	digest := sha256.Sum256(planBytes)
	return SignRequest{
		Version:      JSONVersionV1,
		AttemptID:    attemptID,
		PlanDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		TxPlanBase64: base64.StdEncoding.EncodeToString(planBytes),
	}
}

func testPlan(t *testing.T, walletID string, account uint32, network string) []byte {
	t.Helper()
	coinType := uint32(8135)
	if network == "mainnet" {
		coinType = 8133
	} else if network == "testnet" {
		coinType = 8134
	}
	path := make([]string, 32)
	for i := range path {
		path[i] = strings.Repeat("4", 64)
	}
	plan := types.TxPlan{
		Version:       types.V0,
		Kind:          types.TxPlanKindWithdrawal,
		WalletID:      walletID,
		CoinType:      coinType,
		Account:       account,
		Chain:         network,
		BranchID:      0x5437f330,
		AnchorHeight:  100,
		Anchor:        strings.Repeat("1", 64),
		ExpiryHeight:  120,
		Outputs:       []types.TxOutput{{ToAddress: "jregtest1destination", AmountZat: "1"}},
		ChangeAddress: "jregtest1change",
		FeeZat:        "10000",
		Notes: []types.OrchardSpendNote{{
			NoteID:          strings.Repeat("2", 64) + ":0",
			ActionNullifier: strings.Repeat("3", 64),
			CMX:             strings.Repeat("4", 64),
			Position:        1,
			Path:            path,
			EphemeralKey:    strings.Repeat("5", 64),
			EncCiphertext:   strings.Repeat("6", 104),
		}},
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func testPlanWithAmount(t *testing.T, amount string) []byte {
	t.Helper()
	payload := testPlan(t, "hot", 0, "regtest")
	return bytes.Replace(payload, []byte(`"amount_zat":"1"`), []byte(`"amount_zat":"`+amount+`"`), 1)
}

func testResult() txsign.Result {
	change := uint32(1)
	return txsign.Result{
		TxID:                       strings.Repeat("a", 64),
		RawTxHex:                   "01020304",
		FeeZat:                     "10000",
		OrchardOutputActionIndices: []uint32{0},
		OrchardChangeActionIndex:   &change,
	}
}

func privateTestPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestAttemptLockBookkeepingUnderContention(t *testing.T) {
	// The API's keyed lock must not leak one map entry per exchange attempt.
	api := &API{attempts: make(map[string]*attemptLock)}
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock := api.acquireAttempt("same")
			api.releaseAttempt("same", lock)
		}()
	}
	wg.Wait()
	if len(api.attempts) != 0 {
		t.Fatalf("attempt locks leaked: %d", len(api.attempts))
	}
}
