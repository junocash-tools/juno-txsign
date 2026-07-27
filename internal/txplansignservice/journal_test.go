package txplansignservice

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalRejectsUnsafePermissionsAndCorruption(t *testing.T) {
	dir := privateTestPath(t, "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permissions error, got %v", err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Begin("corrupt-attempt", "sha256:"+strings.Repeat("1", 64), "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	pendingPath, _ := journal.paths("corrupt-attempt")
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pendingPath, []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil || !strings.Contains(err.Error(), "unsafe pending journal") {
		t.Fatalf("expected fail-closed corruption error, got %v", err)
	}
}

func TestJournalResultWriteFailureLeavesAttemptFailClosed(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Begin("write-failure", "sha256:"+strings.Repeat("2", 64), "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	journal.ops.link = func(string, string) error { return errors.New("injected publish failure") }
	if _, err := journal.Complete("write-failure", "sha256:"+strings.Repeat("2", 64), "hot", 0, "regtest", testResult()); err == nil {
		t.Fatal("expected result publication failure")
	}
	state, _, err := journal.Lookup("write-failure", "sha256:"+strings.Repeat("2", 64))
	if err != nil || state != journalPending {
		t.Fatalf("state=%v err=%v; expected durable pending outcome", state, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil || !strings.Contains(err.Error(), "unsafe incomplete writing journal") {
		t.Fatalf("expected temporary artifact to fail recovery closed, got %v", err)
	}
}

func TestJournalRecoversFsyncedReadyRecordBeforeResultLink(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("6", 64)
	if err := journal.Begin("ready-before-result", digest, "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	defaultLink := journal.ops.link
	journal.ops.link = func(from, to string) error {
		if strings.HasSuffix(to, ".result.json") {
			return errors.New("injected crash before result link")
		}
		return defaultLink(from, to)
	}
	if _, err := journal.Complete("ready-before-result", digest, "hot", 0, "regtest", testResult()); err == nil {
		t.Fatal("expected interrupted result publication")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatalf("recover ready record: %v", err)
	}
	defer restarted.Close()
	state, result, err := restarted.Lookup("ready-before-result", digest)
	if err != nil || state != journalComplete || result.RawTxHex != testResult().RawTxHex {
		t.Fatalf("state=%v result=%+v err=%v", state, result, err)
	}
}

func TestJournalRecoversWritingAndReadyHardlinks(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("7", 64)
	if err := journal.Begin("writing-and-ready", digest, "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	defaultRemove := journal.ops.remove
	journal.ops.remove = func(path string) error {
		if strings.Contains(filepath.Base(path), ".result.json.tmp-") {
			return errors.New("injected crash before writing cleanup")
		}
		return defaultRemove(path)
	}
	if _, err := journal.Complete("writing-and-ready", digest, "hot", 0, "regtest", testResult()); err == nil {
		t.Fatal("expected interrupted writing cleanup")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatalf("recover writing/ready hardlinks: %v", err)
	}
	defer restarted.Close()
	state, _, err := restarted.Lookup("writing-and-ready", digest)
	if err != nil || state != journalComplete {
		t.Fatalf("state=%v err=%v", state, err)
	}
}

func TestJournalRecoversResultBeforeReadyCleanup(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("8", 64)
	if err := journal.Begin("result-and-ready", digest, "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	defaultRemove := journal.ops.remove
	journal.ops.remove = func(path string) error {
		if strings.HasSuffix(path, ".ready.json") {
			return errors.New("injected crash before ready cleanup")
		}
		return defaultRemove(path)
	}
	if _, err := journal.Complete("result-and-ready", digest, "hot", 0, "regtest", testResult()); err == nil {
		t.Fatal("expected interrupted ready cleanup")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatalf("recover result/ready hardlinks: %v", err)
	}
	defer restarted.Close()
	state, _, err := restarted.Lookup("result-and-ready", digest)
	if err != nil || state != journalComplete {
		t.Fatalf("state=%v err=%v", state, err)
	}
}

func TestJournalPendingSyncFailureCannotBecomeSignable(t *testing.T) {
	journal, err := OpenJournal(privateTestPath(t, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	journal.ops.syncFile = func(*os.File) error { return errors.New("injected sync failure") }
	digest := "sha256:" + strings.Repeat("3", 64)
	if err := journal.Begin("pending-sync", digest, "hot", 0, "regtest"); err == nil {
		t.Fatal("expected pending sync failure")
	}
	state, _, lookupErr := journal.Lookup("pending-sync", digest)
	if lookupErr != nil || state != journalPending {
		t.Fatalf("state=%v err=%v; expected fail-closed pending", state, lookupErr)
	}
}

func TestJournalCompleteSurvivesPendingCleanupFailure(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("4", 64)
	if err := journal.Begin("cleanup-failure", digest, "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	defaultRemove := journal.ops.remove
	journal.ops.remove = func(path string) error {
		if strings.HasSuffix(path, ".pending.json") {
			return errors.New("injected pending cleanup failure")
		}
		return defaultRemove(path)
	}
	if _, err := journal.Complete("cleanup-failure", digest, "hot", 0, "regtest", testResult()); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	state, result, err := restarted.Lookup("cleanup-failure", digest)
	if err != nil || state != journalComplete || result.RawTxHex != testResult().RawTxHex {
		t.Fatalf("state=%v result=%+v err=%v", state, result, err)
	}
}

func TestJournalFilesArePrivateAndDoNotContainSeed(t *testing.T) {
	dir := privateTestPath(t, "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	seedMarker := "secret-seed-marker"
	digest := "sha256:" + strings.Repeat("5", 64)
	if err := journal.Begin("private-files", digest, "hot", 0, "regtest"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Complete("private-files", digest, "hot", 0, "regtest", testResult()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("journal file %s mode=%04o", entry.Name(), info.Mode().Perm())
		}
		if info.Mode().IsRegular() {
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), seedMarker) || strings.Contains(string(payload), "seed_base64") {
				t.Fatalf("journal file %s contains seed material", entry.Name())
			}
		}
	}
}
