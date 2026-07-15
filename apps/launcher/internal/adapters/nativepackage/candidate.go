// Package nativepackage implements fixed-root native package verification and
// installation adapters for the portable first-invocation launcher.
package nativepackage

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

// ErrCandidateIntegrity is the only public package-candidate failure. It does
// not expose a host path, signer diagnostic, or filesystem detail.
var ErrCandidateIntegrity = errors.New("native package candidate integrity failed")

// PublisherVerifier applies the exact independently embedded native publisher
// authority selected by the signed publication.
type PublisherVerifier interface {
	VerifyPublisher(
		context.Context,
		string,
		releasepublication.Artifact,
	) error
}

// CandidateVerifier owns one canonical, non-writable-by-path-substitution
// release-object root and a native publisher verifier.
type CandidateVerifier struct {
	root      string
	publisher PublisherVerifier
}

// NewCandidateVerifier resolves the supplied package root once and rejects a
// partial or linked leaf composition.
func NewCandidateVerifier(root string, publisher PublisherVerifier) (*CandidateVerifier, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || nilCapability(publisher) {
		return nil, ErrCandidateIntegrity
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCandidateIntegrity
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return nil, ErrCandidateIntegrity
	}
	return &CandidateVerifier{root: canonical, publisher: publisher}, nil
}

// VerifyCandidate reopens and hashes the exact declared leaf before and after
// native publisher verification. No path, filename, digest, or policy comes
// from an MCP request or ambient configuration.
func (v *CandidateVerifier) VerifyCandidate(
	ctx context.Context,
	artifact releasepublication.Artifact,
) error {
	if v == nil || ctx == nil || v.root == "" || nilCapability(v.publisher) ||
		artifact.Kind() != releasepublication.ArtifactKindNativePackage ||
		artifact.FileName() == "" || filepath.Base(artifact.FileName()) != artifact.FileName() ||
		strings.ContainsAny(artifact.FileName(), `/\`) || artifact.Size() == 0 ||
		artifact.Digest().IsZero() {
		return ErrCandidateIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(v.root, artifact.FileName())
	if err := verifyCandidateBytes(path, artifact); err != nil {
		return ErrCandidateIntegrity
	}
	if err := v.publisher.VerifyPublisher(ctx, path, artifact); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return ErrCandidateIntegrity
	}
	if err := verifyCandidateBytes(path, artifact); err != nil {
		return ErrCandidateIntegrity
	}
	return ctx.Err()
}

func verifyCandidateBytes(path string, artifact releasepublication.Artifact) error {
	info, err := os.Lstat(path)
	// #nosec G115 -- conversion is evaluated only after the short-circuit proof that size is positive.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || uint64(info.Size()) != artifact.Size() {
		return ErrCandidateIntegrity
	}
	// #nosec G304 -- path is one domain-validated leaf below the constructor-fixed root.
	file, err := os.Open(path)
	if err != nil {
		return ErrCandidateIntegrity
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrCandidateIntegrity
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, info.Size())
	if err != nil || written != info.Size() {
		return ErrCandidateIntegrity
	}
	var trailing [1]byte
	if count, readError := file.Read(trailing[:]); count != 0 || readError != io.EOF {
		return ErrCandidateIntegrity
	}
	var digest releaseinventory.Digest
	copy(digest[:], hash.Sum(nil))
	if !digest.Equal(artifact.Digest()) {
		return ErrCandidateIntegrity
	}
	return nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
