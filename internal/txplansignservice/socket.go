package txplansignservice

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UnixListener is an owner-only local transport. Closing it removes and
// fsyncs the socket entry so a graceful restart never inherits a stale path.
type UnixListener struct {
	*net.UnixListener
	path      string
	closeOnce sync.Once
	closeErr  error
}

func OpenUnixListener(path string) (*UnixListener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("txplan signer: socket path is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("txplan signer: socket path must be absolute")
	}
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	if err := ensurePrivateDirectory(parent); err != nil {
		return nil, fmt.Errorf("txplan signer: socket directory: %w", err)
	}

	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("txplan signer: socket path exists and is not a Unix socket")
		}
		if err := checkOwner(info); err != nil {
			return nil, fmt.Errorf("txplan signer: stale socket: %w", err)
		}
		conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("txplan signer: socket is already accepting connections")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("txplan signer: remove stale socket: %w", err)
		}
		if err := syncDirectory(parent); err != nil {
			return nil, fmt.Errorf("txplan signer: sync stale socket removal: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("txplan signer: inspect socket path: %w", err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("txplan signer: listen on Unix socket: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = os.Remove(path)
		}
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("txplan signer: protect Unix socket: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("txplan signer: verify Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("txplan signer: Unix socket permissions are unsafe")
	}
	if err := checkOwner(info); err != nil {
		return nil, fmt.Errorf("txplan signer: Unix socket: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return nil, fmt.Errorf("txplan signer: sync Unix socket directory: %w", err)
	}
	cleanup = false
	return &UnixListener{UnixListener: listener, path: path}, nil
}

func (l *UnixListener) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		listenerErr := l.UnixListener.Close()
		removeErr := os.Remove(l.path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		syncErr := syncDirectory(filepath.Dir(l.path))
		switch {
		case listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed):
			l.closeErr = listenerErr
		case removeErr != nil:
			l.closeErr = removeErr
		case syncErr != nil:
			l.closeErr = syncErr
		}
	})
	return l.closeErr
}
