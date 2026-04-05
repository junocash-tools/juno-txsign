package digestsignhttp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
)

type API struct {
	signerKeys   []string
	maxBodyBytes int64
}

type Option func(*API)

func WithMaxBodyBytes(n int64) Option {
	return func(a *API) {
		if n > 0 {
			a.maxBodyBytes = n
		}
	}
}

func New(signerKeys []string, opts ...Option) (*API, error) {
	if len(signerKeys) == 0 {
		return nil, errors.New("digestsignhttp: signer keys are required")
	}

	a := &API{
		signerKeys:   append([]string(nil), signerKeys...),
		maxBodyBytes: 1 << 20,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}
	return a, nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("POST "+digestsign.SignDigestPath, a.handleSignDigest)
	return mux
}

func (a *API) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleSignDigest(w http.ResponseWriter, r *http.Request) {
	var req digestsign.SignDigestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBodyBytes)).Decode(&req); err != nil {
		writeSignDigestError(w, http.StatusBadRequest, "invalid_request", "invalid json")
		return
	}
	if req.Version != digestsign.JSONVersionV1 {
		writeSignDigestError(w, http.StatusBadRequest, "invalid_request", "version must be v1")
		return
	}

	digest, err := digestsign.ParseDigestHex(req.Digest)
	if err != nil {
		writeSignDigestError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	signatures, err := digestsign.SignDigest(digest, a.signerKeys)
	if err != nil {
		writeSignDigestError(w, http.StatusInternalServerError, "sign_failed", err.Error())
		return
	}

	var resp digestsign.SignDigestResponse
	resp.Version = digestsign.JSONVersionV1
	resp.Status = "ok"
	resp.Data.Signatures = signatures
	writeJSON(w, http.StatusOK, resp)
}

func writeSignDigestError(w http.ResponseWriter, status int, code, message string) {
	var resp digestsign.SignDigestResponse
	resp.Version = digestsign.JSONVersionV1
	resp.Status = "err"
	resp.Error.Code = code
	resp.Error.Message = message
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
