// Package mcpsessionhost implements host identity adapters for PF-005.
package mcpsessionhost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
)

const pathIdentityKeyBytes = 32

// PathIdentityResolver canonicalizes one selected directory and emits keyed identity evidence.
type PathIdentityResolver struct{ key [pathIdentityKeyBytes]byte }

// NewPathIdentityResolver copies the installation-scoped HMAC key.
func NewPathIdentityResolver(key []byte) (*PathIdentityResolver, error) {
	if len(key) != pathIdentityKeyBytes {
		return nil, errors.New("path identity key is invalid")
	}
	resolver := &PathIdentityResolver{}
	copy(resolver.key[:], key)
	return resolver, nil
}

// Resolve records the canonical logical path, final real path, host object, and keyed fingerprint.
func (r *PathIdentityResolver) Resolve(
	ctx context.Context,
	selected string,
) (mcpsessionapp.PathIdentity, error) {
	if r == nil || ctx == nil || errContext(ctx) != nil || !safeSelectedPath(selected) {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace path is invalid")
	}
	logical := filepath.Clean(selected)
	resolved, err := filepath.EvalSymlinks(logical)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace path cannot be resolved")
	}
	file, err := os.Open(resolved) // #nosec G304 -- selected path is the purpose of this bounded adapter.
	if err != nil {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace path cannot be opened")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace must be a directory")
	}
	confirmed, err := filepath.EvalSymlinks(logical)
	confirmedInfo, statError := os.Stat(resolved)
	if err != nil || statError != nil || confirmed != resolved || !os.SameFile(info, confirmedInfo) {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace identity changed during resolution")
	}
	device, err := hostDeviceIdentity(resolved, info)
	if err != nil {
		return mcpsessionapp.PathIdentity{}, errors.New("workspace device identity is unavailable")
	}
	fingerprint := r.fingerprint(logical, resolved, device)
	return mcpsessionapp.PathIdentity{
		LogicalPath: logical, RealPath: resolved, DeviceIdentity: device,
		PathFingerprint: fingerprint,
	}, nil
}

func (r *PathIdentityResolver) fingerprint(values ...string) string {
	digest := hmac.New(sha256.New, r.key[:])
	_, _ = digest.Write(lengthFrame("agentmemory.workspace-path.v1"))
	for _, value := range values {
		_, _ = digest.Write(lengthFrame(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func lengthFrame(value string) []byte {
	frame := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint64(frame, uint64(len(value)))
	return append(frame, value...)
}

func safeSelectedPath(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func errContext(ctx context.Context) error { return ctx.Err() }

var _ mcpsessionapp.PathIdentityPort = (*PathIdentityResolver)(nil)
