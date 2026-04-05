package digestsign

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseOperatorEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "https origin", in: "https://example.com", want: "https://example.com/v1/sign-digest"},
		{name: "http origin slash", in: "http://127.0.0.1:8080/", want: "http://127.0.0.1:8080/v1/sign-digest"},
		{name: "missing scheme", in: "example.com", wantErr: "http or https"},
		{name: "query", in: "https://example.com?x=1", wantErr: "query string"},
		{name: "fragment", in: "https://example.com#frag", wantErr: "fragment"},
		{name: "path", in: "https://example.com/api", wantErr: "path must be empty or /"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOperatorEndpoint(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOperatorEndpoint: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestFetchOperatorSignatures_RejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	digest, err := ParseDigestHex("0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1")
	if err != nil {
		t.Fatalf("ParseDigestHex: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SignDigestPath {
			t.Fatalf("path=%q want %q", r.URL.Path, SignDigestPath)
		}
		var resp SignDigestResponse
		resp.Version = JSONVersionV1
		resp.Status = "ok"
		resp.Data.Signatures = []string{"0x1234"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, err = FetchOperatorSignatures(context.Background(), srv.Client(), srv.URL+SignDigestPath, digest)
	if err == nil || !strings.Contains(err.Error(), "invalid operator signatures") {
		t.Fatalf("err=%v want invalid operator signatures", err)
	}
}

func TestMergeSignatureSets_RejectsDuplicateSignerAcrossSources(t *testing.T) {
	t.Parallel()

	digest, err := ParseDigestHex("0x6f4e9b6c0f2e4bd2fa44b3bc1f2c0989e5da0dc89f2e4c6d90c1f8b84eb5fcd1")
	if err != nil {
		t.Fatalf("ParseDigestHex: %v", err)
	}

	local, err := SignDigest(digest, []string{"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"})
	if err != nil {
		t.Fatalf("SignDigest local: %v", err)
	}
	remote, err := SignDigest(digest, []string{"4c0883a69102937d6231471b5dbb6204fe512961708279f3136f8f5d7f7f5f5a"})
	if err != nil {
		t.Fatalf("SignDigest remote: %v", err)
	}

	_, err = MergeSignatureSets(digest, local, remote)
	if err == nil || !strings.Contains(err.Error(), "duplicate signer address") {
		t.Fatalf("err=%v want duplicate signer address", err)
	}
}
