package runtimeprovision

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type desktopArtifactPlanProjector interface {
	ProjectDesktopArtifactPlan(runtimeport.DesktopAuthority) (artifactacquisition.Plan, error)
}

type verifiedCatalogDesktopArtifactProjector struct {
	catalog runtimecatalogapp.VerifiedCatalog
}

func (p verifiedCatalogDesktopArtifactProjector) ProjectDesktopArtifactPlan(
	authority runtimeport.DesktopAuthority,
) (artifactacquisition.Plan, error) {
	return p.catalog.DesktopArtifactPlan(authority)
}

// DesktopArtifactCAS is the narrow common acquisition capability used by the
// signed Docker Desktop installer route.
type DesktopArtifactCAS interface {
	ReserveSpace(context.Context, artifactapp.Command) (artifactapp.ReserveResult, error)
	Acquire(context.Context, artifactapp.Command) (artifactapp.AcquireResult, error)
}

// CatalogDesktopArtifactAcquirer acquires exact catalog bytes into the common
// CAS and then atomically materializes them below the owner-private native
// runtime cache. Native publisher verification remains a separate boundary.
type CatalogDesktopArtifactAcquirer struct {
	projector   desktopArtifactPlanProjector
	cas         DesktopArtifactCAS
	materialize artifactapp.VerifiedFinalMaterializer
}

// NewCatalogDesktopArtifactAcquirer constructs the production catalog-to-CAS
// desktop installer adapter.
func NewCatalogDesktopArtifactAcquirer(
	catalog runtimecatalogapp.VerifiedCatalog,
	cas DesktopArtifactCAS,
	materializer artifactapp.VerifiedFinalMaterializer,
) (*CatalogDesktopArtifactAcquirer, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() {
		return nil, errors.New("verified desktop artifact catalog is required")
	}
	if _, present := catalog.Manifest().DesktopExecution(); !present {
		return nil, errors.New("verified catalog has no desktop artifact projection")
	}
	return newCatalogDesktopArtifactAcquirer(
		verifiedCatalogDesktopArtifactProjector{catalog: catalog}, cas, materializer,
	)
}

func newCatalogDesktopArtifactAcquirer(
	projector desktopArtifactPlanProjector,
	cas DesktopArtifactCAS,
	materializer artifactapp.VerifiedFinalMaterializer,
) (*CatalogDesktopArtifactAcquirer, error) {
	if nilArtifactDependency(projector) || nilArtifactDependency(cas) || nilArtifactDependency(materializer) {
		return nil, errors.New("desktop artifact acquisition dependencies are required")
	}
	return &CatalogDesktopArtifactAcquirer{projector: projector, cas: cas, materialize: materializer}, nil
}

// AcquireDesktopArtifact reserves, acquires, verifies, and privately
// materializes the exact installer selected by desktop authority.
func (a *CatalogDesktopArtifactAcquirer) AcquireDesktopArtifact(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	if a == nil || ctx == nil || !authority.Valid() || nilArtifactDependency(a.projector) ||
		nilArtifactDependency(a.cas) || nilArtifactDependency(a.materialize) {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.DesktopArtifactEvidence{}, err
	}
	plan, err := a.projector.ProjectDesktopArtifactPlan(authority)
	if err != nil || !plan.Digest().Equal(releaseinventory.Digest(authority.CatalogDigest())) {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	artifacts := plan.Artifacts()
	if len(artifacts) != 1 || !desktopArtifactMatchesAuthority(artifacts[0], authority) {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	command := artifactapp.Command{OperationID: desktopArtifactOperationID(authority), Plan: plan}
	reservation, err := a.cas.ReserveSpace(ctx, command)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, mapDesktopArtifactApplicationError(ctx, err)
	}
	if reservation.ReservedBytes != plan.Totals().DownloadBytes() || reservation.AggregateEvidence.IsZero() {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	acquired, err := a.cas.Acquire(ctx, command)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, mapDesktopArtifactApplicationError(ctx, err)
	}
	if !desktopAcquisitionMatches(acquired, artifacts[0]) {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	privateBoundary, err := desktopArtifactPrivateBoundary(authority)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	if err := a.materialize.MaterializeFinal(ctx, artifacts[0], privateBoundary, authority.ArtifactPath()); err != nil {
		return runtimeport.DesktopArtifactEvidence{}, mapDesktopArtifactApplicationError(ctx, err)
	}
	evidence, err := runtimeport.NewDesktopArtifactEvidence(runtimeport.DesktopArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), Path: authority.ArtifactPath(), SHA256: authority.ArtifactSHA256(),
		Bytes: authority.ArtifactBytes(), SourceURL: authority.ArtifactSourceURL(), TLSVerified: true,
	})
	if err != nil || !evidence.AcquiredFor(authority) {
		return runtimeport.DesktopArtifactEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	return evidence, nil
}

func desktopArtifactMatchesAuthority(
	artifact artifactacquisition.Artifact,
	authority runtimeport.DesktopAuthority,
) bool {
	return artifact.Size() == authority.ArtifactBytes() &&
		artifact.Digest().Equal(releaseinventory.Digest(authority.ArtifactSHA256())) &&
		len(artifact.Sources()) == 1 && artifact.Sources()[0] == authority.ArtifactSourceURL()
}

func desktopAcquisitionMatches(result artifactapp.AcquireResult, artifact artifactacquisition.Artifact) bool {
	if result.CompletedArtifacts != 1 || result.AggregateEvidence.IsZero() || !result.ReservationRetained ||
		len(result.VerifiedArtifacts) != 1 {
		return false
	}
	verified := result.VerifiedArtifacts[0]
	return verified.ID == artifact.ID() && verified.Digest.Equal(artifact.Digest()) &&
		verified.Size == artifact.Size() && verified.ContentKey == artifact.ContentKey()
}

func desktopArtifactPrivateBoundary(authority runtimeport.DesktopAuthority) (string, error) {
	var boundary string
	switch authority.Platform() {
	case runtimeinstall.PlatformDarwin:
		boundary = path.Join(authority.HomeDirectory(), "Library", "Caches", "AgentMemory")
		if !posixDesktopPathWithin(boundary, authority.ArtifactPath()) {
			return "", runtimeport.ErrDesktopEvidenceIntegrity
		}
	case runtimeinstall.PlatformWindows:
		boundary = strings.TrimRight(authority.HomeDirectory(), `\`) + `\AppData\Local\AgentMemory`
		if !windowsDesktopPathWithin(boundary, authority.ArtifactPath()) {
			return "", runtimeport.ErrDesktopEvidenceIntegrity
		}
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return "", runtimeport.ErrDesktopEvidenceIntegrity
	}
	return boundary, nil
}

func posixDesktopPathWithin(boundary, target string) bool {
	return boundary != "" && target != "" && path.IsAbs(boundary) && path.IsAbs(target) &&
		strings.HasPrefix(target, strings.TrimRight(boundary, "/")+"/")
}

func windowsDesktopPathWithin(boundary, target string) bool {
	if boundary == "" || target == "" || strings.ContainsRune(boundary, '/') || strings.ContainsRune(target, '/') {
		return false
	}
	prefix := strings.ToLower(boundary) + `\`
	return strings.HasPrefix(strings.ToLower(target), prefix)
}

func desktopArtifactOperationID(authority runtimeport.DesktopAuthority) string {
	return "runtime-desktop-" + authority.Digest().String()
}

func mapDesktopArtifactApplicationError(ctx context.Context, _ error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrDesktopEvidenceIntegrity
}

var _ runtimeport.DesktopArtifactAcquirer = (*CatalogDesktopArtifactAcquirer)(nil)
