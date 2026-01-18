package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRunSign_JSONErrorIncludesVersion(t *testing.T) {
	var out, errBuf bytes.Buffer

	code := RunWithIO([]string{"sign", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}

	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, out.String())
	}
	if v["version"] != "v1" || v["status"] != "err" {
		t.Fatalf("unexpected json: %v", v)
	}
}
