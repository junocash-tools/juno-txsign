package txplansignservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/internal/plan"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const (
	defaultMaxBodyBytes = int64(5 << 20)
	defaultMaxPlanBytes = int64(3 << 20)
)

var (
	attemptIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Policy struct {
	Bindings []Binding
}

type Option func(*API)

func WithMaxBodyBytes(n int64) Option {
	return func(a *API) {
		a.maxBodyBytes = n
	}
}

func WithMaxPlanBytes(n int64) Option {
	return func(a *API) {
		a.maxPlanBytes = n
	}
}

type attemptLock struct {
	mu   sync.Mutex
	refs int
}

type API struct {
	journal *Journal
	signer  Signer

	bindings map[bindingKey]Binding

	maxBodyBytes   int64
	maxPlanBytes   int64
	maxConcurrency int
	semaphore      chan struct{}
	inFlight       atomic.Int64

	attemptsMu sync.Mutex
	attempts   map[string]*attemptLock
}

func New(journal *Journal, signer Signer, policy Policy, maxConcurrency int, opts ...Option) (*API, error) {
	if journal == nil {
		return nil, errors.New("txplan signer: journal is required")
	}
	if signer == nil {
		return nil, errors.New("txplan signer: signer is required")
	}
	if maxConcurrency < 1 || maxConcurrency > 16 {
		return nil, errors.New("txplan signer: max concurrency must be between 1 and 16")
	}
	a := &API{
		journal:        journal,
		signer:         signer,
		bindings:       make(map[bindingKey]Binding, len(policy.Bindings)),
		maxBodyBytes:   defaultMaxBodyBytes,
		maxPlanBytes:   defaultMaxPlanBytes,
		maxConcurrency: maxConcurrency,
		semaphore:      make(chan struct{}, maxConcurrency),
		attempts:       make(map[string]*attemptLock),
	}
	for _, option := range opts {
		if option != nil {
			option(a)
		}
	}
	if a.maxBodyBytes < 1 || a.maxBodyBytes > 64<<20 {
		return nil, errors.New("txplan signer: max body bytes must be between 1 and 67108864")
	}
	if a.maxPlanBytes < 1 || a.maxPlanBytes > a.maxBodyBytes {
		return nil, errors.New("txplan signer: max plan bytes must be positive and no greater than max body bytes")
	}
	if int64(base64.StdEncoding.EncodedLen(int(a.maxPlanBytes)))+1024 > a.maxBodyBytes {
		return nil, errors.New("txplan signer: max body bytes must allow base64 expansion of max plan bytes plus request metadata")
	}
	if err := a.loadPolicy(policy); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *API) loadPolicy(policy Policy) error {
	if len(policy.Bindings) == 0 {
		return errors.New("txplan signer: at least one verified wallet binding is required")
	}
	for _, binding := range policy.Bindings {
		if err := validateBinding(binding); err != nil {
			return err
		}
		key := bindingKey{walletID: binding.WalletID, account: binding.Account, network: binding.Network}
		if _, duplicate := a.bindings[key]; duplicate {
			return errors.New("txplan signer: duplicate wallet/account/network binding")
		}
		a.bindings[key] = binding
	}
	return nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("POST "+SignPath, a.handleSign)
	return noStore(mux)
}

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Version: JSONVersionV1,
		Status:  "ok",
		Data: HealthData{
			Service:        "txplan-signer",
			Journal:        "ready",
			BindingCount:   len(a.bindings),
			MaxConcurrency: a.maxConcurrency,
			InFlight:       a.inFlight.Load(),
		},
	})
}

func (a *API) handleSign(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "content-type must be application/json")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBodyBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds configured limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if err := rejectDuplicateJSONNames(body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request JSON contains duplicate object fields")
		return
	}

	var req SignRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request JSON")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return
	}

	validated, err := a.validateRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !a.allowed(validated.plan) {
		writeError(w, http.StatusForbidden, "plan_not_allowed", "wallet, account, or network is not allowed")
		return
	}

	lock := a.acquireAttempt(req.AttemptID)
	defer a.releaseAttempt(req.AttemptID, lock)

	state, result, err := a.journal.Lookup(req.AttemptID, req.PlanDigest)
	if err != nil {
		switch {
		case errors.Is(err, ErrAttemptDigestConflict):
			writeError(w, http.StatusConflict, "attempt_digest_conflict", "attempt_id is already bound to another plan_digest")
		case errors.Is(err, ErrJournalUnsafe):
			writeError(w, http.StatusInternalServerError, "journal_unsafe", "journal recovery is unsafe; operator review is required")
		default:
			writeError(w, http.StatusInternalServerError, "journal_unavailable", "journal lookup failed")
		}
		return
	}
	switch state {
	case journalComplete:
		writeJSON(w, http.StatusOK, responseFromRecord(result, true))
		return
	case journalPending:
		writeError(w, http.StatusConflict, "attempt_outcome_unknown", "signing may have occurred; keep notes reserved and perform operator recovery")
		return
	}

	select {
	case a.semaphore <- struct{}{}:
		defer func() { <-a.semaphore }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "signer_busy", "signer concurrency limit reached")
		return
	}

	if err := a.journal.Begin(
		req.AttemptID,
		req.PlanDigest,
		validated.plan.WalletID,
		validated.plan.Account,
		validated.network,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "journal_write_failed", "could not durably reserve signing attempt; operator review is required")
		return
	}

	// Once the durable pending marker exists, client disconnects must not
	// cancel key use or result publication. Graceful server shutdown waits for
	// this handler; a forced process stop leaves the pending record fail-closed.
	signingContext := context.WithoutCancel(r.Context())
	resultValue, err := a.callSigner(signingContext, validated.plan)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing_outcome_unknown", "signing failed after durable reservation; keep notes reserved and perform operator recovery")
		return
	}
	if err := validateSigningResult(validated.plan, resultValue); err != nil {
		writeError(w, http.StatusInternalServerError, "signing_outcome_unknown", "signer returned a result inconsistent with the approved plan; keep notes reserved and perform operator recovery")
		return
	}

	result, err = a.journal.Complete(
		req.AttemptID,
		req.PlanDigest,
		validated.plan.WalletID,
		validated.plan.Account,
		validated.network,
		resultValue,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing_outcome_unknown", "signed result could not be durably published; keep notes reserved and perform operator recovery")
		return
	}
	writeJSON(w, http.StatusOK, responseFromRecord(result, false))
}

func validateSigningResult(txplan types.TxPlan, result txsign.Result) error {
	if strings.TrimSpace(result.FeeZat) != strings.TrimSpace(txplan.FeeZat) {
		return errors.New("fee does not match approved plan")
	}
	if len(result.OrchardOutputActionIndices) != len(txplan.Outputs) {
		return errors.New("output action mapping does not match approved plan")
	}
	core := resultRecordCore{
		TxID:                       strings.ToLower(strings.TrimSpace(result.TxID)),
		RawTxHex:                   strings.ToLower(strings.TrimSpace(result.RawTxHex)),
		FeeZat:                     strings.TrimSpace(result.FeeZat),
		OrchardOutputActionIndices: result.OrchardOutputActionIndices,
		OrchardChangeActionIndex:   result.OrchardChangeActionIndex,
	}
	return validateResultCore(core)
}

func (a *API) callSigner(ctx context.Context, txplan types.TxPlan) (result txsign.Result, err error) {
	a.inFlight.Add(1)
	defer a.inFlight.Add(-1)
	defer func() {
		if recover() != nil {
			result = txsign.Result{}
			err = errors.New("signer failed")
		}
	}()
	return a.signer(ctx, txplan)
}

type validatedRequest struct {
	plan    types.TxPlan
	network string
}

func (a *API) validateRequest(req SignRequest) (validatedRequest, error) {
	if req.Version != JSONVersionV1 {
		return validatedRequest{}, errors.New("version must be v1")
	}
	if !attemptIDPattern.MatchString(req.AttemptID) {
		return validatedRequest{}, errors.New("attempt_id must be 1-128 safe ASCII characters")
	}
	if !digestPattern.MatchString(req.PlanDigest) {
		return validatedRequest{}, errors.New("plan_digest must use sha256:<64 lowercase hex>")
	}
	planBytes, err := base64.StdEncoding.DecodeString(req.TxPlanBase64)
	if err != nil || base64.StdEncoding.EncodeToString(planBytes) != req.TxPlanBase64 {
		return validatedRequest{}, errors.New("txplan_base64 must be canonical standard base64")
	}
	if len(planBytes) == 0 || int64(len(planBytes)) > a.maxPlanBytes {
		return validatedRequest{}, errors.New("decoded TxPlan is empty or exceeds configured limit")
	}
	sum := sha256.Sum256(planBytes)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(want), []byte(req.PlanDigest)) != 1 {
		return validatedRequest{}, errors.New("plan_digest does not match the exact decoded TxPlan bytes")
	}
	if err := rejectDuplicateJSONNames(planBytes); err != nil {
		return validatedRequest{}, errors.New("decoded TxPlan JSON contains duplicate object fields")
	}

	decoder := json.NewDecoder(bytes.NewReader(planBytes))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var txplan types.TxPlan
	if err := decoder.Decode(&txplan); err != nil {
		return validatedRequest{}, errors.New("decoded TxPlan JSON is invalid or contains unknown fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return validatedRequest{}, errors.New("decoded TxPlan must contain one JSON object")
	}
	if err := plan.ValidateTxPlanV0(txplan); err != nil {
		return validatedRequest{}, fmt.Errorf("decoded TxPlan failed validation: %v", err)
	}
	network, ok := normalizeNetwork(txplan.Chain)
	if !ok {
		return validatedRequest{}, errors.New("decoded TxPlan network is invalid")
	}
	return validatedRequest{plan: txplan, network: network}, nil
}

func rejectDuplicateJSONNames(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func (a *API) allowed(txplan types.TxPlan) bool {
	network, ok := normalizeNetwork(txplan.Chain)
	if !ok {
		return false
	}
	_, ok = a.bindings[bindingKey{walletID: txplan.WalletID, account: txplan.Account, network: network}]
	return ok
}

func normalizeNetwork(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "main", "mainnet":
		return "mainnet", true
	case "test", "testnet":
		return "testnet", true
	case "regtest":
		return "regtest", true
	default:
		return "", false
	}
}

func (a *API) acquireAttempt(attemptID string) *attemptLock {
	a.attemptsMu.Lock()
	lock := a.attempts[attemptID]
	if lock == nil {
		lock = &attemptLock{}
		a.attempts[attemptID] = lock
	}
	lock.refs++
	a.attemptsMu.Unlock()
	lock.mu.Lock()
	return lock
}

func (a *API) releaseAttempt(attemptID string, lock *attemptLock) {
	lock.mu.Unlock()
	a.attemptsMu.Lock()
	lock.refs--
	if lock.refs == 0 && a.attempts[attemptID] == lock {
		delete(a.attempts, attemptID)
	}
	a.attemptsMu.Unlock()
}

func responseFromRecord(record resultRecord, replayed bool) SignResponse {
	return SignResponse{
		Version: JSONVersionV1,
		Status:  "ok",
		Data: &SignData{
			AttemptID:                  record.AttemptID,
			PlanDigest:                 record.PlanDigest,
			Replayed:                   replayed,
			TxID:                       record.TxID,
			RawTxHex:                   record.RawTxHex,
			FeeZat:                     record.FeeZat,
			OrchardOutputActionIndices: append([]uint32(nil), record.OrchardOutputActionIndices...),
			OrchardChangeActionIndex:   cloneUint32(record.OrchardChangeActionIndex),
		},
	}
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, SignResponse{
		Version: JSONVersionV1,
		Status:  "err",
		Error:   &ErrorData{Code: code, Message: message},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// NewSeedSigner keeps seed ownership inside the service and deliberately does
// not expose the seed through request or journal types.
func NewSeedSigner(seedBase64 string) Signer {
	return func(ctx context.Context, txplan types.TxPlan) (result txsign.Result, err error) {
		return txsign.Sign(ctx, txplan, seedBase64)
	}
}
