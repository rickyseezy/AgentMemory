package runtimeprovision

import (
	"context"
	"errors"
	"strings"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	darwinDesktopMutationTransactionRoot  = "/Library/Application Support/AgentMemory/runtime-helper/transactions"
	windowsDesktopMutationTransactionRoot = `C:\ProgramData\AgentMemory\runtime-helper\transactions`
)

// DesktopMutationTransactionArtifact binds the untrusted user-owned handoff
// file to the internally derived, elevated-only transaction copy.
type DesktopMutationTransactionArtifact struct {
	sourcePath string
	targetPath string
	sha256     runtimeinstall.Hash
	size       uint64
}

// SourcePath returns transport data and is never executed directly.
func (a DesktopMutationTransactionArtifact) SourcePath() string { return a.sourcePath }

// TargetPath returns the privileged request-scoped installer path.
func (a DesktopMutationTransactionArtifact) TargetPath() string { return a.targetPath }

// SHA256 returns the exact signed catalog digest.
func (a DesktopMutationTransactionArtifact) SHA256() runtimeinstall.Hash { return a.sha256 }

// Size returns the exact signed catalog byte count.
func (a DesktopMutationTransactionArtifact) Size() uint64 { return a.size }

type desktopMutationArtifactCopier interface {
	CopyDesktopMutationArtifact(
		context.Context,
		runtimeport.DesktopMutationRequest,
		DesktopMutationTransactionArtifact,
	) error
}

// ProtectedDesktopMutationArtifactStore admits only a descriptor-verified,
// privileged transaction copy to the native executor.
type ProtectedDesktopMutationArtifactStore struct {
	copier desktopMutationArtifactCopier
}

// NewProtectedDesktopMutationArtifactStore constructs the production native
// copier selected for the current platform.
func NewProtectedDesktopMutationArtifactStore() (*ProtectedDesktopMutationArtifactStore, error) {
	return newProtectedDesktopMutationArtifactStore(newNativeDesktopMutationArtifactCopier())
}

func newProtectedDesktopMutationArtifactStore(
	copier desktopMutationArtifactCopier,
) (*ProtectedDesktopMutationArtifactStore, error) {
	if nilArtifactDependency(copier) {
		return nil, errors.New("protected desktop mutation artifact copier is required")
	}
	return &ProtectedDesktopMutationArtifactStore{copier: copier}, nil
}

// PrepareDesktopMutationArtifact derives the target from signed request state.
// Prerequisite-only requests admit no installer artifact.
func (s *ProtectedDesktopMutationArtifactStore) PrepareDesktopMutationArtifact(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	binding DesktopMutationArtifactBinding,
	present bool,
) (DesktopMutationArtifactSet, error) {
	if s == nil || ctx == nil || nilArtifactDependency(s.copier) || request.Digest().IsZero() ||
		!request.Authority().Valid() {
		return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return desktopMutationArtifactTransactionSet{}, err
	}
	if request.Operation() == runtimeport.DesktopMutationInstallPrerequisites ||
		request.Operation() == runtimeport.DesktopMutationRemoveRuntime {
		digestValid := request.Operation() == runtimeport.DesktopMutationInstallPrerequisites &&
			request.ArtifactDigest().IsZero() || request.Operation() == runtimeport.DesktopMutationRemoveRuntime &&
			request.ArtifactDigest() == request.Authority().ArtifactSHA256()
		if present || binding.path != "" || !binding.sha256.IsZero() || binding.size != 0 || !digestValid {
			return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
		}
		return desktopMutationArtifactTransactionSet{}, nil
	}
	authority := request.Authority()
	if request.Operation() != runtimeport.DesktopMutationInstallRuntime || !present ||
		binding.path != authority.ArtifactPath() || binding.sha256 != authority.ArtifactSHA256() ||
		binding.sha256 != request.ArtifactDigest() || binding.size != authority.ArtifactBytes() {
		return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
	}
	target, err := desktopMutationArtifactTarget(authority.Platform(), request.Digest())
	if err != nil || target == binding.path {
		return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
	}
	transaction := DesktopMutationTransactionArtifact{
		sourcePath: binding.path, targetPath: target, sha256: binding.sha256, size: binding.size,
	}
	if err := s.copier.CopyDesktopMutationArtifact(ctx, request, transaction); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return desktopMutationArtifactTransactionSet{}, contextError
		}
		return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
	}
	installer, err := NewDesktopMutationArtifactBinding(target, binding.sha256, binding.size)
	if err != nil {
		return desktopMutationArtifactTransactionSet{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return desktopMutationArtifactTransactionSet{installer: installer, present: true}, nil
}

func desktopMutationArtifactTarget(
	platform runtimeinstall.Platform,
	request runtimeinstall.Hash,
) (string, error) {
	if request.IsZero() {
		return "", runtimeport.ErrDesktopMutationIntegrity
	}
	switch platform {
	case runtimeinstall.PlatformDarwin:
		return darwinDesktopMutationTransactionRoot + "/" + request.String() + "/installer.dmg", nil
	case runtimeinstall.PlatformWindows:
		return windowsDesktopMutationTransactionRoot + `\` + request.String() + `\installer.exe`, nil
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return "", runtimeport.ErrDesktopMutationIntegrity
	}
	return "", runtimeport.ErrDesktopMutationIntegrity
}

type desktopMutationArtifactTransactionSet struct {
	installer DesktopMutationArtifactBinding
	present   bool
}

func (s desktopMutationArtifactTransactionSet) Installer() (DesktopMutationArtifactBinding, bool) {
	if !s.present || strings.TrimSpace(s.installer.path) == "" {
		return DesktopMutationArtifactBinding{}, false
	}
	return s.installer, true
}

var _ DesktopMutationArtifactPreparer = (*ProtectedDesktopMutationArtifactStore)(nil)
