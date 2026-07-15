//go:build windows

package installplanfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	windowsReplayRetryInterval = 10 * time.Millisecond
	windowsReplayMaximumWait   = 5 * time.Second
)

type windowsStore struct{ root string }

func openPlatformStore(ctx context.Context, root string) (platformStore, error) {
	if err := windowssecurity.ValidateLocalPath(root); err != nil {
		return nil, err
	}
	if err := windowssecurity.CreatePrivateDirectory(ctx, root); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	directory, _, err := windowssecurity.OpenVerified(ctx, root, true, true, true)
	if err != nil {
		return nil, err
	}
	if err := directory.Close(); err != nil {
		return nil, err
	}
	return &windowsStore{root: root}, nil
}

func (s *windowsStore) load(ctx context.Context, name string) ([]byte, error) {
	if s == nil || filepath.Base(name) != name {
		return nil, errors.New("plan repository path is invalid")
	}
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, s.root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, filepath.Join(s.root, name), false)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
		return nil, errPlanNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumPersistedPlanBytes {
		return nil, errors.New("plan file shape is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPersistedPlanBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumPersistedPlanBytes || int64(len(raw)) != info.Size() {
		return nil, errors.New("plan file read is invalid")
	}
	if err := guard.Verify(ctx); err != nil {
		return nil, err
	}
	return raw, ctx.Err()
}

func (s *windowsStore) save(ctx context.Context, name string, raw []byte) error {
	if s == nil || filepath.Base(name) != name || len(raw) == 0 || len(raw) > maximumPersistedPlanBytes {
		return errors.New("plan publication input is invalid")
	}
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, s.root)
	if err != nil {
		return err
	}
	defer func() { _ = guard.Close() }()
	temporary, err := randomWindowsTemporaryName()
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(s.root, temporary)
	targetPath := filepath.Join(s.root, name)
	file, err := windowssecurity.CreatePrivateFile(ctx, temporaryPath)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := writeWindowsAll(file, raw); err != nil {
		return err
	}
	if err := windowssecurity.Flush(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, temporaryPath, targetPath)
	if err != nil {
		return err
	}
	if !published {
		existing, loadError := s.loadReplay(ctx, name)
		if loadError != nil || !bytes.Equal(existing, raw) {
			return errImmutableConflict
		}
		return nil
	}
	removeTemporary = false
	return guard.Verify(ctx)
}

func (s *windowsStore) close() error { return nil }

// loadReplay waits only for the narrow publication race where another valid
// writer has won the no-replace operation and is still flushing its verified
// target handle. It never retries integrity, path, content, or authority
// failures, and the caller's context plus the closed deadline bound the wait.
func (s *windowsStore) loadReplay(ctx context.Context, name string) ([]byte, error) {
	deadline := time.Now().Add(windowsReplayMaximumWait)
	for {
		raw, err := s.load(ctx, name)
		if err == nil || !windowsReplayContention(err) {
			return raw, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, err
		}
		delay := min(windowsReplayRetryInterval, remaining)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func windowsReplayContention(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func randomWindowsTemporaryName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return ".plan-" + hex.EncodeToString(value[:]) + ".tmp", nil
}

func writeWindowsAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}
