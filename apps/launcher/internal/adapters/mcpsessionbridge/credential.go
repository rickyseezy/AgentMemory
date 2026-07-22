// Package mcpsessionbridge is the least-privilege MCP server executed only in a transient container.
package mcpsessionbridge

import (
	"context"
	"errors"
	"io"
	"os"
)

const (
	credentialPath  = "/run/secrets/agentmemory-session"
	credentialBytes = 32
)

// MountedCredential reads only the fixed read-only bind supplied by the launcher.
type MountedCredential struct{}

// ReadCredential rejects path substitution, links, non-regular files, and excess bytes.
func (MountedCredential) ReadCredential(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || path != credentialPath {
		return nil, errors.New("session credential authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		(info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o444) || info.Size() != credentialBytes {
		return nil, errors.New("session credential file is invalid")
	}
	file, err := os.Open(path) // #nosec G304 -- fixed literal container secret path.
	if err != nil {
		return nil, errors.New("session credential is unavailable")
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(io.LimitReader(file, credentialBytes+1))
	if err != nil || len(value) != credentialBytes {
		clear(value)
		return nil, errors.New("session credential is invalid")
	}
	return value, nil
}
