package txplansignservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

func TestBindingsFileAndSeedVerification(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(bytesOf(64, 11))
	ufvk, err := txsign.DeriveUFVK(context.Background(), seed, 8135, 0)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{WalletID: "hot", Account: 0, Network: "regtest", UFVK: ufvk}
	path := filepath.Join(t.TempDir(), "bindings.json")
	payload, err := json.Marshal(bindingsFile{Version: JSONVersionV1, Bindings: []Binding{binding}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	bindings, err := LoadBindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySeedBindings(context.Background(), seed, bindings); err != nil {
		t.Fatal(err)
	}

	wrongSeed := base64.StdEncoding.EncodeToString(bytesOf(64, 12))
	if err := VerifySeedBindings(context.Background(), wrongSeed, bindings); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected wrong-seed binding error, got %v", err)
	}
	wrongUFVK := append([]Binding(nil), bindings...)
	wrongUFVK[0].UFVK = ufvk[:len(ufvk)-1] + "q"
	if err := VerifySeedBindings(context.Background(), seed, wrongUFVK); err == nil {
		t.Fatal("expected wrong UFVK binding error")
	}
}

func TestBindingsFileRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings.json")
	valid := `{"version":"v1","bindings":[{"wallet_id":"hot","account":0,"network":"regtest","ufvk":"jviewregtest1placeholder"}]}`
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindings(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permissions error, got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(valid, `"version":"v1"`, `"version":"v1","version":"v1"`, 1)
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindings(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate field error, got %v", err)
	}
}
