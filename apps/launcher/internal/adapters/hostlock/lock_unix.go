//go:build darwin || linux

// Package hostlock serializes PF-001 machine-mutating operations.
package hostlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
)

const lockPollInterval = 50 * time.Millisecond

// Port owns one absolute, invoking-user-controlled lock file.
type Port struct{ path string }

// New constructs a Unix advisory-lock adapter. The parent directory must
// already be created and owner-controlled by the directory phase.
func New(path string) (*Port, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("installation lock path must be absolute and clean")
	}
	return &Port{path: path}, nil
}

// Acquire waits interruptibly for an exclusive cross-process advisory lock.
func (p *Port) Acquire(ctx context.Context) (installapp.InstallationLock, error) {
	if ctx == nil {
		return nil, errors.New("installation lock context is required")
	}
	// O_NOFOLLOW closes the final-component symlink race before flock.
	file, err := os.OpenFile(p.path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open installation lock: %w", err)
	}
	if err := verifyLockFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}

	ticker := time.NewTicker(lockPollInterval)
	defer ticker.Stop()
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return &heldLock{file: file}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire installation lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func verifyLockFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect installation lock: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("installation lock is not an owner-only regular file")
	}
	return nil
}

type heldLock struct {
	mu       sync.Mutex
	file     *os.File
	released bool
}

func (l *heldLock) Release(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true
	unlockError := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeError := l.file.Close()
	return errors.Join(unlockError, closeError)
}
