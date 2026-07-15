package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const linuxPrivilegeTransactionRoot = "/var/lib/agentmemory/runtime-helper/transactions"

// PrivilegeTransactionArtifact binds an untrusted user-owned handoff file to
// its deterministic root-owned transaction copy. The native copier proves the
// source descriptor and exact bytes before the target becomes visible.
type PrivilegeTransactionArtifact struct {
	artifactID string
	sourcePath string
	targetPath string
	sha256     runtimeinstall.Hash
	size       uint64
	packageSet bool
}

// ArtifactID returns the exact signed catalog artifact identity.
func (a PrivilegeTransactionArtifact) ArtifactID() string { return a.artifactID }

// SourcePath returns the untrusted owner-private transport path.
func (a PrivilegeTransactionArtifact) SourcePath() string { return a.sourcePath }

// TargetPath returns the deterministic root-owned transaction path.
func (a PrivilegeTransactionArtifact) TargetPath() string { return a.targetPath }

// SHA256 returns the exact signed content digest.
func (a PrivilegeTransactionArtifact) SHA256() runtimeinstall.Hash { return a.sha256 }

// Size returns the exact signed byte length.
func (a PrivilegeTransactionArtifact) Size() uint64 { return a.size }

// IsPackage reports whether this artifact belongs in the exact native package
// manager argv rather than repository verification/configuration state.
func (a PrivilegeTransactionArtifact) IsPackage() bool { return a.packageSet }

// PrivilegeArtifactTransaction is the immutable set of descriptor-verified,
// root-owned files admitted to one helper request.
type PrivilegeArtifactTransaction struct {
	root      string
	artifacts []PrivilegeTransactionArtifact
}

// Root returns the request-digest transaction directory.
func (t PrivilegeArtifactTransaction) Root() string { return t.root }

// Artifacts returns a defensive copy of every exact transaction artifact.
func (t PrivilegeArtifactTransaction) Artifacts() []PrivilegeTransactionArtifact {
	return append([]PrivilegeTransactionArtifact(nil), t.artifacts...)
}

// PackagePaths returns the exact sorted local package paths for fixed argv.
func (t PrivilegeArtifactTransaction) PackagePaths() []string {
	paths := make([]string, 0, len(t.artifacts))
	for _, artifact := range t.artifacts {
		if artifact.packageSet {
			paths = append(paths, artifact.targetPath)
		}
	}
	sort.Strings(paths)
	return paths
}

// Artifact selects one exact root-owned artifact by signed identity.
func (t PrivilegeArtifactTransaction) Artifact(id string) (PrivilegeTransactionArtifact, bool) {
	for _, artifact := range t.artifacts {
		if artifact.artifactID == id {
			return artifact, true
		}
	}
	return PrivilegeTransactionArtifact{}, false
}

type privilegeArtifactCopier interface {
	CopyPrivilegeArtifacts(
		context.Context,
		string,
		uint32,
		uint32,
		[]PrivilegeTransactionArtifact,
	) error
}

// RootPrivilegeArtifactStore converts the canonical helper handoff into one
// root-owned, request-scoped transaction without broadening signed authority.
type RootPrivilegeArtifactStore struct{ copier privilegeArtifactCopier }

// NewRootPrivilegeArtifactStore constructs the production descriptor-based
// native copier for the current platform. Off Linux it fails closed.
func NewRootPrivilegeArtifactStore() (*RootPrivilegeArtifactStore, error) {
	return newRootPrivilegeArtifactStore(newNativePrivilegeArtifactCopier())
}

func newRootPrivilegeArtifactStore(copier privilegeArtifactCopier) (*RootPrivilegeArtifactStore, error) {
	if nilArtifactDependency(copier) {
		return nil, errors.New("root privilege artifact copier is required")
	}
	return &RootPrivilegeArtifactStore{copier: copier}, nil
}

// PreparePrivilegeArtifacts validates the envelope against signed authority,
// derives every target internally, and delegates only descriptor-safe copying.
func (s *RootPrivilegeArtifactStore) PreparePrivilegeArtifacts(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	bindings []PrivilegeArtifactBinding,
) (PrivilegeArtifactTransaction, error) {
	authority := request.Authority()
	if s == nil || ctx == nil || nilArtifactDependency(s.copier) || request.Digest().IsZero() ||
		!authority.Valid() || !validPrivilegeArtifactBindings(bindings, authority) {
		return PrivilegeArtifactTransaction{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	if err := ctx.Err(); err != nil {
		return PrivilegeArtifactTransaction{}, err
	}
	root := filepath.Join(linuxPrivilegeTransactionRoot, request.Digest().String())
	packages := make(map[string]struct{}, len(authority.Packages()))
	for _, pkg := range authority.Packages() {
		packages[pkg.Name()] = struct{}{}
	}
	artifacts := make([]PrivilegeTransactionArtifact, 0, len(bindings))
	for _, binding := range bindings {
		_, packageSet := packages[binding.artifactID]
		extension := ".metadata"
		if packageSet {
			extension = ".deb"
			if authority.PackageManager() == runtimeport.PackageManagerDNF {
				extension = ".rpm"
			}
		} else if !strings.HasPrefix(binding.artifactID, "repo-") {
			return PrivilegeArtifactTransaction{}, runtimeport.ErrLinuxArtifactIntegrity
		}
		artifacts = append(artifacts, PrivilegeTransactionArtifact{
			artifactID: binding.artifactID, sourcePath: binding.path,
			targetPath: filepath.Join(root, binding.artifactID+"-"+binding.sha256.String()+extension),
			sha256:     binding.sha256, size: binding.size, packageSet: packageSet,
		})
	}
	if err := s.copier.CopyPrivilegeArtifacts(
		ctx, root, authority.InvokingUID(), authority.InvokingGID(), artifacts,
	); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return PrivilegeArtifactTransaction{}, contextError
		}
		return PrivilegeArtifactTransaction{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return PrivilegeArtifactTransaction{root: root, artifacts: artifacts}, nil
}
