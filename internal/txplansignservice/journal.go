package txplansignservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const (
	journalVersion       = "v1"
	journalLockFile      = ".lock"
	maxJournalRecordSize = 16 << 20
)

var journalArtifactName = regexp.MustCompile(`^[0-9a-f]{64}\.(pending|ready|result)\.json$`)
var journalWritingName = regexp.MustCompile(`^\.([0-9a-f]{64})\.result\.json\.tmp-.+$`)
var decimalString = regexp.MustCompile(`^[0-9]+$`)

var (
	ErrAttemptDigestConflict = errors.New("attempt digest conflict")
	ErrJournalUnsafe         = errors.New("journal recovery is unsafe")
)

type pendingRecordCore struct {
	Version    string `json:"version"`
	State      string `json:"state"`
	AttemptID  string `json:"attempt_id"`
	PlanDigest string `json:"plan_digest"`
	WalletID   string `json:"wallet_id"`
	Account    uint32 `json:"account"`
	Network    string `json:"network"`
	CreatedAt  string `json:"created_at"`
}

type pendingRecord struct {
	pendingRecordCore
	RecordDigest string `json:"record_digest"`
}

type resultRecordCore struct {
	Version                    string   `json:"version"`
	State                      string   `json:"state"`
	AttemptID                  string   `json:"attempt_id"`
	PlanDigest                 string   `json:"plan_digest"`
	WalletID                   string   `json:"wallet_id"`
	Account                    uint32   `json:"account"`
	Network                    string   `json:"network"`
	TxID                       string   `json:"txid"`
	RawTxHex                   string   `json:"raw_tx_hex"`
	FeeZat                     string   `json:"fee_zat"`
	OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices"`
	OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index"`
	CompletedAt                string   `json:"completed_at"`
}

type resultRecord struct {
	resultRecordCore
	RecordDigest string `json:"record_digest"`
}

type journalOps struct {
	syncFile func(*os.File) error
	syncDir  func(string) error
	link     func(string, string) error
	remove   func(string) error
}

func defaultJournalOps() journalOps {
	return journalOps{
		syncFile: func(f *os.File) error { return f.Sync() },
		syncDir:  syncDirectory,
		link:     os.Link,
		remove:   os.Remove,
	}
}

// Journal is an owner-only, single-process result store. A durable pending
// marker is written before signing begins. Its presence without a valid final
// result means the outcome is unknown and the attempt must never be retried.
type Journal struct {
	dir      string
	lockFile *os.File
	ops      journalOps
	closeMu  sync.Mutex
	closed   bool
}

func OpenJournal(dir string) (*Journal, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("txplan signer: journal directory is required")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("txplan signer: resolve journal directory: %w", err)
	}
	dir = filepath.Clean(absolute)
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, fmt.Errorf("txplan signer: journal directory: %w", err)
	}

	lockPath := filepath.Join(dir, journalLockFile)
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("txplan signer: open journal lock: %w", err)
	}
	if err := checkPrivateRegularFile(lockFile, lockPath); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("txplan signer: journal lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return nil, errors.New("txplan signer: journal is already in use")
	}

	j := &Journal{dir: dir, lockFile: lockFile, ops: defaultJournalOps()}
	if err := j.validateExistingArtifacts(); err != nil {
		_ = j.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.closeMu.Lock()
	defer j.closeMu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if j.lockFile == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(j.lockFile.Fd()), syscall.LOCK_UN)
	closeErr := j.lockFile.Close()
	j.lockFile = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func (j *Journal) paths(attemptID string) (pendingPath, resultPath string) {
	sum := sha256.Sum256([]byte(attemptID))
	base := hex.EncodeToString(sum[:])
	return filepath.Join(j.dir, base+".pending.json"), filepath.Join(j.dir, base+".result.json")
}

type journalLookup int

const (
	journalMissing journalLookup = iota
	journalPending
	journalComplete
)

func (j *Journal) Lookup(attemptID, planDigest string) (journalLookup, resultRecord, error) {
	pendingPath, resultPath := j.paths(attemptID)

	result, resultExists, err := readResultRecord(resultPath)
	if err != nil {
		return journalMissing, resultRecord{}, fmt.Errorf("%w: %v", ErrJournalUnsafe, err)
	}
	if resultExists {
		if result.AttemptID != attemptID {
			return journalMissing, resultRecord{}, fmt.Errorf("%w: result attempt identity mismatch", ErrJournalUnsafe)
		}
		if result.PlanDigest != planDigest {
			return journalMissing, resultRecord{}, ErrAttemptDigestConflict
		}
		if pending, exists, err := readPendingRecord(pendingPath); err != nil {
			return journalMissing, resultRecord{}, fmt.Errorf("%w: %v", ErrJournalUnsafe, err)
		} else if exists && (pending.AttemptID != attemptID || pending.PlanDigest != planDigest) {
			return journalMissing, resultRecord{}, fmt.Errorf("%w: pending/result identity mismatch", ErrJournalUnsafe)
		}
		return journalComplete, result, nil
	}

	pending, exists, err := readPendingRecord(pendingPath)
	if err != nil {
		return journalMissing, resultRecord{}, fmt.Errorf("%w: %v", ErrJournalUnsafe, err)
	}
	if !exists {
		return journalMissing, resultRecord{}, nil
	}
	if pending.AttemptID != attemptID {
		return journalMissing, resultRecord{}, fmt.Errorf("%w: pending attempt identity mismatch", ErrJournalUnsafe)
	}
	if pending.PlanDigest != planDigest {
		return journalMissing, resultRecord{}, ErrAttemptDigestConflict
	}
	return journalPending, resultRecord{}, nil
}

func (j *Journal) Begin(attemptID, planDigest, walletID string, account uint32, network string) error {
	pendingPath, resultPath := j.paths(attemptID)
	if _, err := os.Lstat(resultPath); err == nil {
		return errors.New("txplan signer: result already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("txplan signer: inspect result: %w", err)
	}

	core := pendingRecordCore{
		Version:    journalVersion,
		State:      "signing",
		AttemptID:  attemptID,
		PlanDigest: planDigest,
		WalletID:   walletID,
		Account:    account,
		Network:    network,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	record := pendingRecord{pendingRecordCore: core, RecordDigest: digestJSON(core)}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("txplan signer: marshal pending journal: %w", err)
	}
	payload = append(payload, '\n')

	f, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("txplan signer: pending journal already exists")
		}
		return fmt.Errorf("txplan signer: create pending journal: %w", err)
	}
	if err := writeAll(f, payload); err != nil {
		_ = f.Close()
		return fmt.Errorf("txplan signer: write pending journal: %w", err)
	}
	if err := j.ops.syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("txplan signer: sync pending journal: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("txplan signer: close pending journal: %w", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return fmt.Errorf("txplan signer: sync pending journal directory: %w", err)
	}
	return nil
}

func (j *Journal) Complete(attemptID, planDigest, walletID string, account uint32, network string, result txsign.Result) (resultRecord, error) {
	pendingPath, resultPath := j.paths(attemptID)
	readyPath := strings.TrimSuffix(resultPath, ".result.json") + ".ready.json"
	pending, exists, err := readPendingRecord(pendingPath)
	if err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: inspect pending journal: %w", err)
	}
	if !exists || pending.AttemptID != attemptID || pending.PlanDigest != planDigest {
		return resultRecord{}, errors.New("txplan signer: pending journal identity is unsafe")
	}

	core := resultRecordCore{
		Version:                    journalVersion,
		State:                      "complete",
		AttemptID:                  attemptID,
		PlanDigest:                 planDigest,
		WalletID:                   walletID,
		Account:                    account,
		Network:                    network,
		TxID:                       strings.ToLower(strings.TrimSpace(result.TxID)),
		RawTxHex:                   strings.ToLower(strings.TrimSpace(result.RawTxHex)),
		FeeZat:                     strings.TrimSpace(result.FeeZat),
		OrchardOutputActionIndices: append([]uint32(nil), result.OrchardOutputActionIndices...),
		OrchardChangeActionIndex:   cloneUint32(result.OrchardChangeActionIndex),
		CompletedAt:                time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := validateResultCore(core); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: invalid signing result: %w", err)
	}
	record := resultRecord{resultRecordCore: core, RecordDigest: digestJSON(core)}
	payload, err := json.Marshal(record)
	if err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: marshal result journal: %w", err)
	}
	payload = append(payload, '\n')

	temp, err := os.CreateTemp(j.dir, "."+filepath.Base(resultPath)+".tmp-")
	if err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: create result journal temporary: %w", err)
	}
	tempPath := temp.Name()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = temp.Close()
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: protect result journal temporary: %w", err)
	}
	if err := writeAll(temp, payload); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: write result journal: %w", err)
	}
	if err := j.ops.syncFile(temp); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: sync result journal: %w", err)
	}
	if err := temp.Close(); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: close result journal: %w", err)
	}
	cleanupTemp = false

	// Publish a deterministic, directory-synced ready record before the final
	// name. On recovery, a ready record is known to contain fsynced bytes; a
	// lone writing temporary remains deliberately unsafe.
	if err := j.ops.link(tempPath, readyPath); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: publish durable ready journal: %w", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: sync ready journal: %w", err)
	}
	if err := j.ops.remove(tempPath); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: remove result writing temporary: %w", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: sync writing temporary cleanup: %w", err)
	}
	if err := j.ops.link(readyPath, resultPath); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: publish immutable result journal: %w", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: sync published result journal: %w", err)
	}
	if err := j.ops.remove(readyPath); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: remove ready journal: %w", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return resultRecord{}, fmt.Errorf("txplan signer: sync ready journal cleanup: %w", err)
	}

	// Once the complete record is durable, pending cleanup is best-effort. A
	// restart safely prefers and verifies the complete record.
	if err := j.ops.remove(pendingPath); err == nil {
		_ = j.ops.syncDir(j.dir)
	}
	return record, nil
}

func (j *Journal) validateExistingArtifacts() error {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return fmt.Errorf("txplan signer: read journal: %w", err)
	}
	pendingByBase := make(map[string]pendingRecord)
	resultByBase := make(map[string]resultRecord)
	readyByBase := make(map[string]resultRecord)
	readyPaths := make(map[string]string)
	writingPaths := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if name == journalLockFile {
			continue
		}
		match := journalArtifactName.FindStringSubmatch(name)
		if match == nil {
			if writing := journalWritingName.FindStringSubmatch(name); writing != nil {
				base := writing[1]
				if _, duplicate := writingPaths[base]; duplicate {
					return fmt.Errorf("txplan signer: multiple unsafe writing journals %q", base)
				}
				writingPaths[base] = filepath.Join(j.dir, name)
				continue
			}
			return fmt.Errorf("txplan signer: unsafe unknown journal artifact %q", name)
		}
		path := filepath.Join(j.dir, name)
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".json"), "."+match[1])
		switch match[1] {
		case "pending":
			record, exists, err := readPendingRecord(path)
			if err != nil || !exists {
				return fmt.Errorf("txplan signer: unsafe pending journal %q", name)
			}
			if journalBase(record.AttemptID) != base {
				return fmt.Errorf("txplan signer: pending journal identity mismatch %q", name)
			}
			pendingByBase[base] = record
		case "result":
			record, exists, err := readResultRecord(path)
			if err != nil || !exists {
				return fmt.Errorf("txplan signer: unsafe result journal %q", name)
			}
			if journalBase(record.AttemptID) != base {
				return fmt.Errorf("txplan signer: result journal identity mismatch %q", name)
			}
			resultByBase[base] = record
		case "ready":
			record, exists, err := readResultRecord(path)
			if err != nil || !exists {
				return fmt.Errorf("txplan signer: unsafe ready journal %q", name)
			}
			if journalBase(record.AttemptID) != base {
				return fmt.Errorf("txplan signer: ready journal identity mismatch %q", name)
			}
			readyByBase[base] = record
			readyPaths[base] = path
		}
	}

	// A writing temporary is safe to remove only when the directory-synced
	// ready name exists and is the exact same inode. Without that proof, its
	// fsync state is unknown and recovery fails closed.
	for base, writingPath := range writingPaths {
		readyPath, exists := readyPaths[base]
		if !exists {
			return fmt.Errorf("txplan signer: unsafe incomplete writing journal %q", filepath.Base(writingPath))
		}
		writingInfo, err := os.Stat(writingPath)
		if err != nil {
			return fmt.Errorf("txplan signer: inspect writing journal: %w", err)
		}
		readyInfo, err := os.Stat(readyPath)
		if err != nil || !os.SameFile(writingInfo, readyInfo) {
			return fmt.Errorf("txplan signer: writing/ready journal mismatch %q", base)
		}
		if err := j.ops.remove(writingPath); err != nil {
			return fmt.Errorf("txplan signer: remove recovered writing journal: %w", err)
		}
		if err := j.ops.syncDir(j.dir); err != nil {
			return fmt.Errorf("txplan signer: sync recovered writing cleanup: %w", err)
		}
	}

	// A valid ready record has fsynced contents and a synced directory entry.
	// Finish or verify its immutable result publication before serving.
	for base, ready := range readyByBase {
		readyPath := readyPaths[base]
		result, resultExists := resultByBase[base]
		resultPath := filepath.Join(j.dir, base+".result.json")
		if resultExists {
			if ready.RecordDigest != result.RecordDigest || ready.AttemptID != result.AttemptID || ready.PlanDigest != result.PlanDigest {
				return fmt.Errorf("txplan signer: ready/result journal mismatch %q", base)
			}
			readyInfo, readyErr := os.Stat(readyPath)
			resultInfo, resultErr := os.Stat(resultPath)
			if readyErr != nil || resultErr != nil || !os.SameFile(readyInfo, resultInfo) {
				return fmt.Errorf("txplan signer: ready/result inode mismatch %q", base)
			}
		} else {
			pending, pendingExists := pendingByBase[base]
			if !pendingExists || pending.AttemptID != ready.AttemptID || pending.PlanDigest != ready.PlanDigest {
				return fmt.Errorf("txplan signer: ready journal lacks matching pending record %q", base)
			}
			if err := j.ops.link(readyPath, resultPath); err != nil {
				return fmt.Errorf("txplan signer: recover immutable result journal: %w", err)
			}
			if err := j.ops.syncDir(j.dir); err != nil {
				return fmt.Errorf("txplan signer: sync recovered result journal: %w", err)
			}
			resultByBase[base] = ready
		}
		if err := j.ops.remove(readyPath); err != nil {
			return fmt.Errorf("txplan signer: remove recovered ready journal: %w", err)
		}
		if err := j.ops.syncDir(j.dir); err != nil {
			return fmt.Errorf("txplan signer: sync recovered ready cleanup: %w", err)
		}
	}
	for base, pending := range pendingByBase {
		if result, exists := resultByBase[base]; exists &&
			(pending.AttemptID != result.AttemptID || pending.PlanDigest != result.PlanDigest) {
			return fmt.Errorf("txplan signer: pending/result journal mismatch %q", base)
		}
	}
	return nil
}

func readPendingRecord(path string) (pendingRecord, bool, error) {
	var record pendingRecord
	exists, err := readPrivateJSON(path, &record)
	if err != nil || !exists {
		return record, exists, err
	}
	if record.Version != journalVersion || record.State != "signing" ||
		record.AttemptID == "" || record.PlanDigest == "" || record.WalletID == "" || record.Network == "" {
		return record, true, errors.New("pending journal has invalid fields")
	}
	if !attemptIDPattern.MatchString(record.AttemptID) || !digestPattern.MatchString(record.PlanDigest) ||
		record.Account > 1<<31-1 {
		return record, true, errors.New("pending journal identity invalid")
	}
	if normalized, ok := normalizeNetwork(record.Network); !ok || normalized != record.Network {
		return record, true, errors.New("pending journal network invalid")
	}
	if record.RecordDigest != digestJSON(record.pendingRecordCore) {
		return record, true, errors.New("pending journal digest mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return record, true, errors.New("pending journal timestamp invalid")
	}
	return record, true, nil
}

func readResultRecord(path string) (resultRecord, bool, error) {
	var record resultRecord
	exists, err := readPrivateJSON(path, &record)
	if err != nil || !exists {
		return record, exists, err
	}
	if record.Version != journalVersion || record.State != "complete" ||
		record.AttemptID == "" || record.PlanDigest == "" || record.WalletID == "" || record.Network == "" {
		return record, true, errors.New("result journal has invalid fields")
	}
	if !attemptIDPattern.MatchString(record.AttemptID) || !digestPattern.MatchString(record.PlanDigest) ||
		record.Account > 1<<31-1 {
		return record, true, errors.New("result journal identity invalid")
	}
	if normalized, ok := normalizeNetwork(record.Network); !ok || normalized != record.Network {
		return record, true, errors.New("result journal network invalid")
	}
	if record.RecordDigest != digestJSON(record.resultRecordCore) {
		return record, true, errors.New("result journal digest mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CompletedAt); err != nil {
		return record, true, errors.New("result journal timestamp invalid")
	}
	if err := validateResultCore(record.resultRecordCore); err != nil {
		return record, true, err
	}
	return record, true, nil
}

func readPrivateJSON(path string, dst any) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := checkPrivateRegularFile(f, path); err != nil {
		return true, err
	}
	info, err := f.Stat()
	if err != nil {
		return true, err
	}
	if info.Size() > maxJournalRecordSize {
		return true, errors.New("journal record exceeds size limit")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxJournalRecordSize+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return true, errors.New("journal JSON invalid")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return true, errors.New("journal has trailing data")
	}
	return true, nil
}

func validateResultCore(record resultRecordCore) error {
	if len(record.TxID) != 64 || record.TxID != strings.ToLower(record.TxID) {
		return errors.New("result txid invalid")
	}
	if _, err := hex.DecodeString(record.TxID); err != nil {
		return errors.New("result txid invalid")
	}
	if record.RawTxHex == "" || len(record.RawTxHex)%2 != 0 || record.RawTxHex != strings.ToLower(record.RawTxHex) {
		return errors.New("result raw transaction invalid")
	}
	if _, err := hex.DecodeString(record.RawTxHex); err != nil {
		return errors.New("result raw transaction invalid")
	}
	if !decimalString.MatchString(record.FeeZat) {
		return errors.New("result fee invalid")
	}
	if _, err := strconv.ParseUint(record.FeeZat, 10, 64); err != nil {
		return errors.New("result fee invalid")
	}
	if len(record.OrchardOutputActionIndices) == 0 || len(record.OrchardOutputActionIndices) > 200 {
		return errors.New("result output action indices invalid")
	}
	seen := make(map[uint32]struct{}, len(record.OrchardOutputActionIndices)+1)
	for _, index := range record.OrchardOutputActionIndices {
		if index > 199 {
			return errors.New("result output action index invalid")
		}
		if _, exists := seen[index]; exists {
			return errors.New("result output action indices duplicate")
		}
		seen[index] = struct{}{}
	}
	if record.OrchardChangeActionIndex != nil {
		if *record.OrchardChangeActionIndex > 199 {
			return errors.New("result change action index invalid")
		}
		if _, exists := seen[*record.OrchardChangeActionIndex]; exists {
			return errors.New("result change action index duplicates output")
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("permissions must not grant group/other access (got %04o)", info.Mode().Perm())
	}
	if err := checkOwner(info); err != nil {
		return err
	}
	return nil
}

func checkPrivateRegularFile(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("must be a non-symlink regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("permissions must not grant group/other access (got %04o)", info.Mode().Perm())
	}
	return checkOwner(info)
}

func checkOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("must be owned by the service user")
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func digestJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic("txplan signer: journal record cannot be marshaled")
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func journalBase(attemptID string) string {
	sum := sha256.Sum256([]byte(attemptID))
	return hex.EncodeToString(sum[:])
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
