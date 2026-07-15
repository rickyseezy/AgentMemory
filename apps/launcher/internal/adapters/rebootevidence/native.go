package rebootevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

type executableResolver func() (string, error)

// NativeObjectVerifier hashes retained no-follow descriptors after native
// owner, type, ACL/mode, and link/reparse verification.
type NativeObjectVerifier struct{ executable executableResolver }

// NewNativeObjectVerifier resolves the currently executing signed launcher.
func NewNativeObjectVerifier() (*NativeObjectVerifier, error) {
	return newNativeObjectVerifier(os.Executable)
}

func newNativeObjectVerifier(executable executableResolver) (*NativeObjectVerifier, error) {
	if executable == nil {
		return nil, rebootapp.ErrIntegrity
	}
	return &NativeObjectVerifier{executable: executable}, nil
}

// VerifyLauncher resolves symlinks once, then opens and verifies the resulting
// exact executable object without following a final link.
func (v *NativeObjectVerifier) VerifyLauncher(ctx context.Context) (VerifiedObject, error) {
	if v == nil || ctx == nil || v.executable == nil {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObject{}, err
	}
	path, err := v.executable()
	if err != nil {
		return VerifiedObject{}, rebootapp.ErrUnavailable
	}
	if !validAbsoluteCleanPath(path) {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !validAbsoluteCleanPath(resolved) {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	return verifyAndHashNativeObject(ctx, resolved, true)
}

// VerifyJournal rejects every path substitution and requires owner-private
// journal permissions/ACLs.
func (v *NativeObjectVerifier) VerifyJournal(ctx context.Context, path string) (VerifiedObject, error) {
	if v == nil || ctx == nil || !validAbsoluteCleanPath(path) {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObject{}, err
	}
	return verifyAndHashNativeObject(ctx, path, false)
}

func verifyAndHashNativeObject(ctx context.Context, path string, executable bool) (VerifiedObject, error) {
	file, err := platformOpenNativeObject(ctx, path, executable)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return VerifiedObject{}, err
		}
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	digest, err := install.ParseDigest(hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		return VerifiedObject{}, rebootapp.ErrIntegrity
	}
	return VerifiedObject{Path: path, Digest: digest}, nil
}

func validAbsoluteCleanPath(path string) bool {
	return path != "" && strings.IndexByte(path, 0) < 0 && filepath.IsAbs(path) && filepath.Clean(path) == path
}

var _ ObjectVerifier = (*NativeObjectVerifier)(nil)
