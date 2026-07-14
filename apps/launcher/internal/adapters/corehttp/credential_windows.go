//go:build windows

package corehttp

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func readNativeCredential(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsRune(path, '\x00') {
		return nil, errCredentialIntegrity
	}
	file, identity, err := windowssecurity.OpenVerified(ctx, path, false, false, true)
	if err != nil {
		return nil, errCredentialUnavailable
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != protectedCredentialBytes {
		return nil, errCredentialIntegrity
	}
	value := make([]byte, protectedCredentialBytes)
	if _, err := io.ReadFull(file, value); err != nil {
		clear(value)
		return nil, errCredentialUnavailable
	}
	var extra [1]byte
	if count, readError := file.Read(extra[:]); count != 0 || !errors.Is(readError, io.EOF) {
		clear(value)
		return nil, errCredentialIntegrity
	}
	after, err := windowssecurity.VerifyOpened(ctx, file, false, true)
	if err != nil || after != identity || windowssecurity.VerifyPathIdentity(ctx, path, identity, true) != nil {
		clear(value)
		return nil, errCredentialIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}
