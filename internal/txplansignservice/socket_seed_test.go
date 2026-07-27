package txplansignservice

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixListenerUsesOwnerOnlyPermissionsAndCleansUp(t *testing.T) {
	dir := shortPrivateTempDir(t)
	path := filepath.Join(dir, "signer.sock")
	listener, err := OpenUnixListener(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode=%v perm=%04o", info.Mode(), info.Mode().Perm())
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestUnixListenerRejectsUnsafeDirectory(t *testing.T) {
	dir := privateTestPath(t, "socket-dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenUnixListener(filepath.Join(dir, "signer.sock")); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected unsafe directory error, got %v", err)
	}
}

func TestLoadSeedRequiresOneSecureSource(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(bytesOf(32, 7))
	if got, err := LoadSeed("", seed); err != nil || got != seed {
		t.Fatalf("env seed got=%q err=%v", got, err)
	}
	if _, err := LoadSeed("", ""); err == nil {
		t.Fatal("expected missing seed error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "seed.b64")
	if err := os.WriteFile(path, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadSeed(path, ""); err != nil || got != seed {
		t.Fatalf("file seed got=%q err=%v", got, err)
	}
	if _, err := LoadSeed(path, seed); err == nil {
		t.Fatal("expected source conflict")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeed(path, ""); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permissions error, got %v", err)
	}
}

func TestLoadSeedRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "seed")
	seed := base64.StdEncoding.EncodeToString(bytesOf(32, 9))
	if err := os.WriteFile(target, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeed(link, ""); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func bytesOf(n int, value byte) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = value
	}
	return result
}

func shortPrivateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "jts-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
