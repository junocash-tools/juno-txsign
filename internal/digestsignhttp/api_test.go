package digestsignhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-txsign/internal/digestsign"
)

func TestAPI_Healthz(t *testing.T) {
	t.Parallel()

	api := mustAPI(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	api.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusOK)
	}
	if strings.TrimSpace(rr.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestAPI_SignDigest_InvalidRequest(t *testing.T) {
	t.Parallel()

	api := mustAPI(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, digestsign.SignDigestPath, strings.NewReader(`{"version":"v1","digest":"0x1234"}`))
	api.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusBadRequest)
	}

	var resp digestsign.SignDigestResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if resp.Version != digestsign.JSONVersionV1 || resp.Status != "err" || resp.Error.Code != "invalid_request" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAPI_SignDigest_OK(t *testing.T) {
	t.Parallel()

	api := mustAPI(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, digestsign.SignDigestPath, strings.NewReader(`{"version":"v1","digest":"0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1"}`))
	api.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp digestsign.SignDigestResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if resp.Version != digestsign.JSONVersionV1 || resp.Status != "ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Data.Signatures) != 1 {
		t.Fatalf("signature count=%d want=1", len(resp.Data.Signatures))
	}
}

func mustAPI(t *testing.T) *API {
	t.Helper()

	api, err := New([]string{"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return api
}
