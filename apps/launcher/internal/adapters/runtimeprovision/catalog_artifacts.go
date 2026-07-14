package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type linuxArtifactPlanProjector interface {
	ProjectLinuxArtifactPlan(runtimeport.LinuxAuthority) (artifactacquisition.Plan, error)
}

type verifiedCatalogArtifactProjector struct {
	catalog runtimecatalogapp.VerifiedCatalog
}

func (p verifiedCatalogArtifactProjector) ProjectLinuxArtifactPlan(
	authority runtimeport.LinuxAuthority,
) (artifactacquisition.Plan, error) {
	return p.catalog.LinuxArtifactPlan(authority)
}

// LinuxArtifactCAS is the narrow common artifact-application capability used
// by PF-006 package acquisition.
type LinuxArtifactCAS interface {
	ReserveSpace(context.Context, artifactapp.Command) (artifactapp.ReserveResult, error)
	Acquire(context.Context, artifactapp.Command) (artifactapp.AcquireResult, error)
}

// CatalogLinuxArtifactAcquirer stores every signed package through the same
// reserve-before-download, ranged HTTPS, content-addressed path as release
// artifacts. It performs no privileged operation and makes no native-signature
// claim; VerifyRuntimeArtifact supplies that later proof.
type CatalogLinuxArtifactAcquirer struct {
	projector linuxArtifactPlanProjector
	cas       LinuxArtifactCAS
}

// NewCatalogLinuxArtifactAcquirer constructs the production catalog-to-CAS adapter.
func NewCatalogLinuxArtifactAcquirer(
	catalog runtimecatalogapp.VerifiedCatalog,
	cas LinuxArtifactCAS,
) (*CatalogLinuxArtifactAcquirer, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() {
		return nil, errors.New("verified linux artifact catalog is required")
	}
	if _, present := catalog.Manifest().LinuxExecution(); !present {
		return nil, errors.New("verified catalog has no linux artifact projection")
	}
	return newCatalogLinuxArtifactAcquirer(verifiedCatalogArtifactProjector{catalog: catalog}, cas)
}

func newCatalogLinuxArtifactAcquirer(
	projector linuxArtifactPlanProjector,
	cas LinuxArtifactCAS,
) (*CatalogLinuxArtifactAcquirer, error) {
	if nilArtifactDependency(projector) || nilArtifactDependency(cas) {
		return nil, errors.New("linux artifact acquisition dependencies are required")
	}
	return &CatalogLinuxArtifactAcquirer{projector: projector, cas: cas}, nil
}

// AcquireLinuxArtifacts reserves exact local capacity and acquires every
// package into the verified CAS before elevation is possible.
func (a *CatalogLinuxArtifactAcquirer) AcquireLinuxArtifacts(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (runtimeport.LinuxArtifactEvidence, error) {
	if a == nil || ctx == nil || !authority.Valid() || nilArtifactDependency(a.projector) || nilArtifactDependency(a.cas) {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.LinuxArtifactEvidence{}, err
	}
	plan, err := a.projector.ProjectLinuxArtifactPlan(authority)
	if err != nil || !plan.Digest().Equal(releaseinventory.Digest(authority.CatalogDigest())) {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	command := artifactapp.Command{OperationID: linuxArtifactOperationID(authority), Plan: plan}
	reservation, err := a.cas.ReserveSpace(ctx, command)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, mapLinuxArtifactApplicationError(ctx, err)
	}
	if reservation.ReservedBytes != plan.Totals().DownloadBytes() || reservation.AggregateEvidence.IsZero() {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	acquired, err := a.cas.Acquire(ctx, command)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, mapLinuxArtifactApplicationError(ctx, err)
	}
	retained, err := retainedLinuxArtifactDigest(plan, acquired)
	if err != nil || acquired.AggregateEvidence.IsZero() || !acquired.ReservationRetained {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	repositoryState, err := runtimeport.ExpectedRepositoryStateDigest(authority)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	packageState, err := runtimeport.ExpectedPackageStateDigest(authority)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return runtimeport.NewLinuxArtifactEvidence(runtimeport.LinuxArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), ArtifactDigest: authority.ArtifactDigest(),
		RepositoryStateDigest: repositoryState, PackageStateDigest: packageState,
		RetainedSetDigest: retained, EveryPackageAcquired: true,
		RepositoryAuthenticated: false, PackagesAuthenticated: false,
	})
}

func retainedLinuxArtifactDigest(
	plan artifactacquisition.Plan,
	result artifactapp.AcquireResult,
) (runtimeinstall.Hash, error) {
	artifacts := plan.Artifacts()
	if uint64(result.CompletedArtifacts) != uint64(len(artifacts)) || len(result.VerifiedArtifacts) != len(artifacts) {
		return runtimeinstall.Hash{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	expected := make(map[string]artifactacquisition.Artifact, len(artifacts))
	for _, artifact := range artifacts {
		expected[artifact.ID()] = artifact
	}
	verified := append([]artifactapp.VerifiedArtifact(nil), result.VerifiedArtifacts...)
	sort.Slice(verified, func(left, right int) bool { return verified[left].ID < verified[right].ID })
	for _, item := range verified {
		artifact, present := expected[item.ID]
		if !present || !item.Digest.Equal(artifact.Digest()) || item.Size != artifact.Size() ||
			item.ContentKey != artifact.ContentKey() {
			return runtimeinstall.Hash{}, runtimeport.ErrLinuxArtifactIntegrity
		}
		delete(expected, item.ID)
	}
	if len(expected) != 0 {
		return runtimeinstall.Hash{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	canonical := make([]retainedArtifactRecord, 0, len(verified))
	for _, item := range verified {
		canonical = append(canonical, retainedArtifactRecord{
			ID: item.ID, SHA256: item.Digest.Hex(), Size: item.Size, ContentKey: item.ContentKey,
		})
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

// retainedArtifactRecord is the version-one canonical retained-set proof. It
// deliberately does not serialize artifactapp.VerifiedArtifact directly: an
// unrelated application result field must never alter PF-006 evidence.
type retainedArtifactRecord struct {
	ID         string `json:"id"`
	SHA256     string `json:"sha256"`
	Size       uint64 `json:"size"`
	ContentKey string `json:"contentKey"`
}

func linuxArtifactOperationID(authority runtimeport.LinuxAuthority) string {
	return "runtime-pkg-" + authority.Digest().String()
}

func mapLinuxArtifactApplicationError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var applicationError *artifactapp.Error
	if errors.As(err, &applicationError) &&
		(applicationError.Code == artifactapp.ErrorSource || applicationError.Code == artifactapp.ErrorReservation ||
			applicationError.Code == artifactapp.ErrorRepository || applicationError.Code == artifactapp.ErrorStore) {
		return runtimeport.ErrLinuxArtifactUnavailable
	}
	return runtimeport.ErrLinuxArtifactIntegrity
}

func nilArtifactDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	kind := reflected.Kind()
	if kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice {
		return reflected.IsNil()
	}
	return false
}

var _ runtimeport.LinuxArtifactAcquirer = (*CatalogLinuxArtifactAcquirer)(nil)
