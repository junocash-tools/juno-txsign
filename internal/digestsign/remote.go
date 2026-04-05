package digestsign

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type SignDigestRequest struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type SignDigestResponse struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Data    struct {
		Signatures []string `json:"signatures"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func ParseOperatorEndpoint(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("operator endpoint is required")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid operator endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("operator endpoint must use http or https")
	}
	if u.Host == "" {
		return "", fmt.Errorf("operator endpoint host is required")
	}
	if u.User != nil {
		return "", fmt.Errorf("operator endpoint must not include user info")
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("operator endpoint must not include a query string")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("operator endpoint must not include a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("operator endpoint path must be empty or /")
	}

	u.Path = SignDigestPath
	u.RawPath = ""
	return u.String(), nil
}

func CollectRemoteSignatures(ctx context.Context, digest []byte, operatorEndpoints []string, client *http.Client) ([][]string, error) {
	if len(operatorEndpoints) == 0 {
		return nil, nil
	}
	if client == nil {
		client = &http.Client{}
	}

	results := make([][]string, len(operatorEndpoints))
	errs := make([]error, len(operatorEndpoints))

	var wg sync.WaitGroup
	for i, endpoint := range operatorEndpoints {
		wg.Add(1)
		go func(i int, endpoint string) {
			defer wg.Done()

			signURL, err := ParseOperatorEndpoint(endpoint)
			if err != nil {
				errs[i] = fmt.Errorf("operator endpoint %d: %w", i+1, err)
				return
			}

			requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			signatures, err := FetchOperatorSignatures(requestCtx, client, signURL, digest)
			if err != nil {
				errs[i] = fmt.Errorf("operator endpoint %d (%s): %w", i+1, signURL, err)
				return
			}
			results[i] = signatures
		}(i, endpoint)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func FetchOperatorSignatures(ctx context.Context, client *http.Client, signURL string, digest []byte) ([]string, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	if client == nil {
		client = &http.Client{}
	}

	body, err := json.Marshal(SignDigestRequest{
		Version: JSONVersionV1,
		Digest:  "0x" + hex.EncodeToString(digest),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	limitedBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var parsed SignDigestResponse
	if err := json.Unmarshal(limitedBody, &parsed); err != nil {
		return nil, fmt.Errorf("invalid response json")
	}

	if resp.StatusCode != http.StatusOK {
		if parsed.Error.Code != "" || parsed.Error.Message != "" {
			return nil, fmt.Errorf("operator error: %s: %s", parsed.Error.Code, parsed.Error.Message)
		}
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
	if parsed.Version != JSONVersionV1 {
		return nil, fmt.Errorf("unexpected response version: %q", parsed.Version)
	}
	if parsed.Status != "ok" {
		if parsed.Error.Code != "" || parsed.Error.Message != "" {
			return nil, fmt.Errorf("operator returned error: %s: %s", parsed.Error.Code, parsed.Error.Message)
		}
		return nil, fmt.Errorf("operator returned status %q", parsed.Status)
	}
	if len(parsed.Data.Signatures) == 0 {
		return nil, fmt.Errorf("operator returned no signatures")
	}

	signatures, err := NormalizeSignatures(digest, parsed.Data.Signatures)
	if err != nil {
		return nil, fmt.Errorf("invalid operator signatures: %w", err)
	}
	return signatures, nil
}
