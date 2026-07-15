package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// PrivilegeArtifactBinding is the exact owner-private file the root helper
// must reopen, hash, and copy into a root-owned transaction directory before
// any package manager receives it.
type PrivilegeArtifactBinding struct {
	artifactID string
	path       string
	sha256     runtimeinstall.Hash
	size       uint64
}

// NewPrivilegeArtifactBinding validates one transport binding. It does not
// confer trust on the path; only the independently verified catalog and the
// helper's descriptor-based file checks can authorize its contents.
func NewPrivilegeArtifactBinding(
	artifactID string,
	path string,
	sha256 runtimeinstall.Hash,
	size uint64,
) (PrivilegeArtifactBinding, error) {
	if !validPrivilegeWireID(artifactID) || !validPrivilegeArtifactPath(path) || sha256.IsZero() ||
		size == 0 || size > 1<<53-1 {
		return PrivilegeArtifactBinding{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return PrivilegeArtifactBinding{artifactID: artifactID, path: path, sha256: sha256, size: size}, nil
}

// ArtifactID returns the signed catalog artifact identity.
func (b PrivilegeArtifactBinding) ArtifactID() string { return b.artifactID }

// Path returns the owner-private staging path. The path is transport, not
// authority: the helper must reopen it without following links and reverify it.
func (b PrivilegeArtifactBinding) Path() string { return b.path }

// SHA256 returns the exact signed artifact digest.
func (b PrivilegeArtifactBinding) SHA256() runtimeinstall.Hash { return b.sha256 }

// Size returns the exact signed artifact byte length.
func (b PrivilegeArtifactBinding) Size() uint64 { return b.size }

// PrivilegeArtifactStager materializes the already-verified CAS set into an
// owner-private, helper-readable handoff. It never grants trust to the paths.
type PrivilegeArtifactStager interface {
	StagePrivilegeArtifacts(context.Context, runtimeport.LinuxAuthority) ([]PrivilegeArtifactBinding, error)
}

// CatalogPrivilegeArtifactStager projects the same verified catalog plan used
// for acquisition and copies each exact CAS object into deterministic private
// handoff storage.
type CatalogPrivilegeArtifactStager struct {
	projector    linuxArtifactPlanProjector
	materializer artifactapp.VerifiedFinalMaterializer
	boundary     string
}

// NewCatalogPrivilegeArtifactStager constructs the production CAS-to-helper
// handoff adapter.
func NewCatalogPrivilegeArtifactStager(
	catalog runtimecatalogapp.VerifiedCatalog,
	materializer artifactapp.VerifiedFinalMaterializer,
	boundary string,
) (*CatalogPrivilegeArtifactStager, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() {
		return nil, errors.New("verified Linux artifact catalog is required")
	}
	if _, present := catalog.Manifest().LinuxExecution(); !present {
		return nil, errors.New("verified catalog has no Linux artifact projection")
	}
	return newCatalogPrivilegeArtifactStager(
		verifiedCatalogArtifactProjector{catalog: catalog}, materializer, boundary,
	)
}

func newCatalogPrivilegeArtifactStager(
	projector linuxArtifactPlanProjector,
	materializer artifactapp.VerifiedFinalMaterializer,
	boundary string,
) (*CatalogPrivilegeArtifactStager, error) {
	if nilArtifactDependency(projector) || nilArtifactDependency(materializer) || !validPrivilegeStagingBoundary(boundary) {
		return nil, errors.New("linux privilege artifact staging dependencies are invalid")
	}
	return &CatalogPrivilegeArtifactStager{
		projector: projector, materializer: materializer, boundary: boundary,
	}, nil
}

// StagePrivilegeArtifacts materializes every signed package and repository
// trust artifact. Bindings are sorted by artifact ID for canonical transport.
func (s *CatalogPrivilegeArtifactStager) StagePrivilegeArtifacts(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) ([]PrivilegeArtifactBinding, error) {
	if s == nil || ctx == nil || !authority.Valid() || nilArtifactDependency(s.projector) ||
		nilArtifactDependency(s.materializer) || !validPrivilegeStagingBoundary(s.boundary) {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := s.projector.ProjectLinuxArtifactPlan(authority)
	if err != nil || !plan.Digest().Equal(releaseinventory.Digest(authority.CatalogDigest())) {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	artifacts := plan.Artifacts()
	if len(artifacts) == 0 || len(artifacts) > 4096 {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].ID() < artifacts[right].ID() })
	packageIDs := make(map[string]struct{}, len(authority.Packages()))
	for _, pkg := range authority.Packages() {
		packageIDs[pkg.Name()] = struct{}{}
	}
	operationRoot := filepath.Join(s.boundary, authority.Digest().String())
	bindings := make([]PrivilegeArtifactBinding, 0, len(artifacts))
	for _, artifact := range artifacts {
		extension := ".metadata"
		if _, packageArtifact := packageIDs[artifact.ID()]; packageArtifact {
			extension = ".deb"
			if authority.PackageManager() == runtimeport.PackageManagerDNF {
				extension = ".rpm"
			}
		} else if !strings.HasPrefix(artifact.ID(), "repo-") {
			return nil, runtimeport.ErrLinuxArtifactIntegrity
		}
		// Include the signed ID as well as the digest. Distinct repositories may
		// deliberately publish the same signing key or metadata bytes; they still
		// require distinct canonical bindings in the helper envelope.
		target := filepath.Join(operationRoot, artifact.ID()+"-"+artifact.Digest().Hex()+extension)
		binding, bindingError := newPrivilegeArtifactBinding(s.boundary, artifact, target)
		if bindingError != nil || s.materializer.MaterializeFinal(ctx, artifact, s.boundary, target) != nil {
			if contextError := ctx.Err(); contextError != nil {
				return nil, contextError
			}
			return nil, runtimeport.ErrLinuxArtifactIntegrity
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func newPrivilegeArtifactBinding(
	boundary string,
	artifact artifactacquisition.Artifact,
	target string,
) (PrivilegeArtifactBinding, error) {
	relative, err := filepath.Rel(boundary, target)
	if artifact.ID() == "" || len(artifact.ID()) > 256 || artifact.Digest().IsZero() || artifact.Size() == 0 ||
		err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Clean(target) != target {
		return PrivilegeArtifactBinding{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return NewPrivilegeArtifactBinding(
		artifact.ID(), target, runtimeinstall.Hash(artifact.Digest()), artifact.Size(),
	)
}

func validPrivilegeStagingBoundary(value string) bool {
	return value != "" && value != string(filepath.Separator) && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

var _ PrivilegeArtifactStager = (*CatalogPrivilegeArtifactStager)(nil)
