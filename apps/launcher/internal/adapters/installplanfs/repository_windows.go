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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"golang.org/x/sys/windows"
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
		existing, loadError := s.load(ctx, name)
		if loadError != nil || !bytes.Equal(existing, raw) {
			return errImmutableConflict
		}
		return nil
	}
	removeTemporary = false
	return guard.Verify(ctx)
}

func (s *windowsStore) close() error { return nil }

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
