package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const pendingArtifactSuffix = ".juno-txsign-pending"

type exclusiveArtifact struct {
	targetPath  string
	pendingPath string
	tempPath    string
	file        *os.File
	sealed      bool
	committed   bool
}

func prepareExclusiveArtifacts(paths ...string) ([]*exclusiveArtifact, error) {
	artifacts := make([]*exclusiveArtifact, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for i, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			abortExclusiveArtifacts(artifacts)
			return nil, fmt.Errorf("resolve output path: %w", err)
		}
		absolute = filepath.Clean(absolute)
		if _, duplicate := seen[absolute]; duplicate {
			abortExclusiveArtifacts(artifacts)
			return nil, fmt.Errorf("output paths must be distinct: %s", filepath.Base(path))
		}
		seen[absolute] = struct{}{}

		artifact, err := prepareExclusiveArtifact(absolute)
		if err != nil {
			abortExclusiveArtifacts(artifacts)
			return nil, err
		}
		artifacts[i] = artifact
	}
	return artifacts, nil
}

func prepareExclusiveArtifact(targetPath string) (*exclusiveArtifact, error) {
	if _, err := os.Lstat(targetPath); err == nil {
		return nil, fmt.Errorf("output already exists: %s", filepath.Base(targetPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output %s: %w", filepath.Base(targetPath), err)
	}

	pendingPath := targetPath + pendingArtifactSuffix
	pending, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("output reservation already exists: %s", filepath.Base(pendingPath))
		}
		return nil, fmt.Errorf("reserve output %s: %w", filepath.Base(targetPath), err)
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			_ = pending.Close()
			_ = os.Remove(pendingPath)
		}
	}()
	if err := writeAll(pending, []byte("juno-txsign output reserved\n")); err != nil {
		return nil, fmt.Errorf("write output reservation %s: %w", filepath.Base(pendingPath), err)
	}
	if err := pending.Sync(); err != nil {
		return nil, fmt.Errorf("sync output reservation %s: %w", filepath.Base(pendingPath), err)
	}
	if err := pending.Close(); err != nil {
		return nil, fmt.Errorf("close output reservation %s: %w", filepath.Base(pendingPath), err)
	}
	if _, err := os.Lstat(targetPath); err == nil {
		return nil, fmt.Errorf("output already exists: %s", filepath.Base(targetPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output %s: %w", filepath.Base(targetPath), err)
	}

	dir := filepath.Dir(targetPath)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+".juno-txsign-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary output %s: %w", filepath.Base(targetPath), err)
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return nil, fmt.Errorf("protect temporary output %s: %w", filepath.Base(targetPath), err)
	}
	if err := syncDirectory(dir); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return nil, fmt.Errorf("sync output reservation directory: %w", err)
	}

	cleanupPending = false
	return &exclusiveArtifact{
		targetPath:  targetPath,
		pendingPath: pendingPath,
		tempPath:    temp.Name(),
		file:        temp,
	}, nil
}

func sealExclusiveArtifacts(artifacts []*exclusiveArtifact) {
	for _, artifact := range artifacts {
		if artifact != nil {
			artifact.sealed = true
		}
	}
}

func abortExclusiveArtifacts(artifacts []*exclusiveArtifact) {
	for _, artifact := range artifacts {
		if artifact != nil {
			artifact.abort()
		}
	}
}

func (a *exclusiveArtifact) commit(data []byte) error {
	if a == nil {
		return nil
	}
	if !a.sealed {
		return errors.New("output artifact is not sealed")
	}
	if a.committed {
		return errors.New("output artifact is already committed")
	}
	if err := writeAll(a.file, data); err != nil {
		return a.commitError("write", err)
	}
	if err := a.file.Sync(); err != nil {
		return a.commitError("sync", err)
	}
	if err := a.file.Close(); err != nil {
		a.file = nil
		return a.commitError("close", err)
	}
	a.file = nil

	if err := os.Link(a.tempPath, a.targetPath); err != nil {
		return a.commitError("publish", err)
	}
	if err := os.Remove(a.tempPath); err != nil {
		return a.commitError("remove temporary", err)
	}
	a.tempPath = ""
	if err := syncDirectory(filepath.Dir(a.targetPath)); err != nil {
		return a.commitError("sync directory", err)
	}
	if err := os.Remove(a.pendingPath); err != nil {
		return a.commitError("remove reservation", err)
	}
	if err := syncDirectory(filepath.Dir(a.targetPath)); err != nil {
		return a.commitError("sync reservation removal", err)
	}
	a.committed = true
	return nil
}

func (a *exclusiveArtifact) commitError(operation string, err error) error {
	return fmt.Errorf(
		"%s output %s: %w; signing output state is uncertain; do not retry; inspect and quarantine the artifact and reservation %s",
		operation,
		filepath.Base(a.targetPath),
		err,
		filepath.Base(a.pendingPath),
	)
}

func (a *exclusiveArtifact) abort() {
	if a.file != nil {
		_ = a.file.Close()
		a.file = nil
	}
	if a.sealed || a.committed {
		return
	}
	if a.tempPath != "" {
		_ = os.Remove(a.tempPath)
		a.tempPath = ""
	}
	if a.pendingPath != "" {
		_ = os.Remove(a.pendingPath)
		a.pendingPath = ""
	}
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
