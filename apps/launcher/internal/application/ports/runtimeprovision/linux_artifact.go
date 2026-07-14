package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

var (
	// ErrLinuxArtifactUnavailable reports that the exact package set could not
	// be acquired from its signed source policy.
	ErrLinuxArtifactUnavailable = errors.New("certified Linux runtime artifacts are unavailable")
	// ErrLinuxArtifactIntegrity rejects incomplete, substituted, or
	// unauthenticated repository/package evidence.
	ErrLinuxArtifactIntegrity = errors.New("linux runtime artifact integrity validation failed")
)

// LinuxArtifactEvidenceInput contains only aggregate digests. Implementations
// retain package paths and native metadata internally and must never return an
// ambient cache path as authority.
type LinuxArtifactEvidenceInput struct {
	AuthorityDigest         runtimeinstall.Hash
	ArtifactDigest          runtimeinstall.Hash
	RepositoryStateDigest   runtimeinstall.Hash
	PackageStateDigest      runtimeinstall.Hash
	RetainedSetDigest       runtimeinstall.Hash
	EveryPackageAcquired    bool
	RepositoryAuthenticated bool
	PackagesAuthenticated   bool
}

// LinuxArtifactEvidence binds one retained exact package set to signed Linux
// execution authority without exposing paths or package-manager diagnostics.
type LinuxArtifactEvidence struct {
	input  LinuxArtifactEvidenceInput
	digest runtimeinstall.Hash
}

// NewLinuxArtifactEvidence validates and snapshots acquisition/trust evidence.
func NewLinuxArtifactEvidence(input LinuxArtifactEvidenceInput) (LinuxArtifactEvidence, error) {
	if input.AuthorityDigest.IsZero() || input.ArtifactDigest.IsZero() ||
		input.RepositoryStateDigest.IsZero() || input.PackageStateDigest.IsZero() ||
		input.RetainedSetDigest.IsZero() || !input.EveryPackageAcquired ||
		input.PackagesAuthenticated && !input.RepositoryAuthenticated {
		return LinuxArtifactEvidence{}, ErrLinuxArtifactIntegrity
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return LinuxArtifactEvidence{}, ErrLinuxArtifactIntegrity
	}
	evidence := LinuxArtifactEvidence{input: input, digest: runtimeinstall.Sum(encoded)}
	if evidence.digest.IsZero() {
		return LinuxArtifactEvidence{}, ErrLinuxArtifactIntegrity
	}
	return evidence, nil
}

// AcquiredFor proves that all exact packages are retained and bound to the
// authority's signed aggregate, repository, and package-state projections.
func (e LinuxArtifactEvidence) AcquiredFor(authority LinuxAuthority) bool {
	repository, repositoryErr := ExpectedRepositoryStateDigest(authority)
	packages, packageErr := ExpectedPackageStateDigest(authority)
	return authority.Valid() && repositoryErr == nil && packageErr == nil && !e.digest.IsZero() &&
		e.input.AuthorityDigest == authority.Digest() && e.input.ArtifactDigest == authority.ArtifactDigest() &&
		e.input.RepositoryStateDigest == repository && e.input.PackageStateDigest == packages &&
		!e.input.RetainedSetDigest.IsZero() && e.input.EveryPackageAcquired
}

// VerifiedFor additionally proves authenticated repository metadata and every
// retained native package receipt before any privileged operation.
func (e LinuxArtifactEvidence) VerifiedFor(authority LinuxAuthority) bool {
	return e.AcquiredFor(authority) && e.input.RepositoryAuthenticated && e.input.PackagesAuthenticated
}

// Digest returns the complete immutable evidence identity.
func (e LinuxArtifactEvidence) Digest() runtimeinstall.Hash { return e.digest }

// LinuxArtifactAcquirer performs an unprivileged exact-version download-only
// transaction into a retained owner-only staging set.
type LinuxArtifactAcquirer interface {
	AcquireLinuxArtifacts(context.Context, LinuxAuthority) (LinuxArtifactEvidence, error)
}

// LinuxArtifactVerifier reopens the retained set and authenticates repository
// metadata, package checksums/signatures, exact versions, and aggregate digest.
type LinuxArtifactVerifier interface {
	VerifyLinuxArtifacts(context.Context, LinuxAuthority) (LinuxArtifactEvidence, error)
}
