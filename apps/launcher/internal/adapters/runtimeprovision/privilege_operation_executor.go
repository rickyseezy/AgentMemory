package runtimeprovision

import (
	"context"
	"errors"
	"math"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// PrivilegeRepositoryManager owns only deterministic official-repository
// configuration from signed authority and root-owned transaction artifacts.
type PrivilegeRepositoryManager interface {
	EnsurePrivilegeRepository(context.Context, runtimeport.PrivilegeRequest, PrivilegeArtifactSet) (bool, error)
}

// PrivilegePackageManager owns only exact local-package installation.
type PrivilegePackageManager interface {
	EnsurePrivilegePackages(context.Context, runtimeport.PrivilegeRequest, PrivilegeArtifactSet) (bool, error)
	RemovePrivilegePackages(context.Context, runtimeport.PrivilegeRequest, PrivilegeArtifactSet) (bool, error)
}

// PrivilegeSubordinateIDManager owns only collision-safe /etc/subuid and
// /etc/subgid configuration for the signed original account.
type PrivilegeSubordinateIDManager interface {
	EnsurePrivilegeSubordinateIDs(context.Context, runtimeport.PrivilegeRequest) (bool, error)
}

// PrivilegeUserServiceManager owns only linger plus the exact signed rootless
// user-service unit.
type PrivilegeUserServiceManager interface {
	EnsurePrivilegeUserService(context.Context, runtimeport.PrivilegeRequest) (bool, error)
	DisablePrivilegeUserService(context.Context, runtimeport.PrivilegeRequest) (bool, error)
}

// PrivilegeManagedStateObservation is independently re-probed post-state. It
// contains no result assertion; the executor derives that from mutation.
type PrivilegeManagedStateObservation struct {
	PackageStateDigest     runtimeinstall.Hash
	RepositoryDigest       runtimeinstall.Hash
	ServiceUnitDigest      runtimeinstall.Hash
	ServiceEnabled         bool
	ServiceActive          bool
	UserLingerEnabled      bool
	SubordinateIDs         uint32
	SubordinateUIDStart    uint32
	SubordinateGIDStart    uint32
	SubordinateStateDigest runtimeinstall.Hash
}

// PrivilegeManagedStateObserver independently re-proves all managed Linux
// state after the selected mutation.
type PrivilegeManagedStateObserver interface {
	ObservePrivilegeManagedState(
		context.Context,
		runtimeport.PrivilegeRequest,
	) (PrivilegeManagedStateObservation, error)
}

// PrivilegeOperationDependencies is the complete closed helper executor.
type PrivilegeOperationDependencies struct {
	Repository   PrivilegeRepositoryManager
	Packages     PrivilegePackageManager
	Subordinates PrivilegeSubordinateIDManager
	Service      PrivilegeUserServiceManager
	Observer     PrivilegeManagedStateObserver
}

// ClosedPrivilegeOperationExecutor dispatches no caller-controlled command,
// path, environment, or operation outside the domain's six capabilities.
type ClosedPrivilegeOperationExecutor struct {
	dependencies PrivilegeOperationDependencies
}

// NewClosedPrivilegeOperationExecutor rejects every missing capability.
func NewClosedPrivilegeOperationExecutor(
	dependencies PrivilegeOperationDependencies,
) (*ClosedPrivilegeOperationExecutor, error) {
	if nilArtifactDependency(dependencies.Repository) || nilArtifactDependency(dependencies.Packages) ||
		nilArtifactDependency(dependencies.Subordinates) || nilArtifactDependency(dependencies.Service) ||
		nilArtifactDependency(dependencies.Observer) {
		return nil, errors.New("complete closed privilege operation dependencies are required")
	}
	return &ClosedPrivilegeOperationExecutor{dependencies: dependencies}, nil
}

// ExecutePrivilegeOperation mutates one exact capability, then re-probes and
// projects only the evidence admitted for that operation.
func (e *ClosedPrivilegeOperationExecutor) ExecutePrivilegeOperation(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	artifacts PrivilegeArtifactSet,
	evidence PrivilegeAuthorityEvidence,
) (PrivilegeOperationObservationInput, error) {
	if e == nil || ctx == nil || request.Digest().IsZero() || nilArtifactDependency(artifacts) ||
		artifacts.Root() == "" || !evidence.Authority().Valid() || evidence.HelperDigest().IsZero() ||
		evidence.ReleaseManifestDigest().IsZero() || evidence.Authority().Digest() != request.Authority().Digest() {
		return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return PrivilegeOperationObservationInput{}, err
	}
	changed := false
	var err error
	switch request.Operation() {
	case runtimeport.PrivilegeConfigureRepository:
		changed, err = e.dependencies.Repository.EnsurePrivilegeRepository(ctx, request, artifacts)
	case runtimeport.PrivilegeInstallPackages:
		changed, err = e.dependencies.Packages.EnsurePrivilegePackages(ctx, request, artifacts)
	case runtimeport.PrivilegeConfigureSubordinateIDs:
		changed, err = e.dependencies.Subordinates.EnsurePrivilegeSubordinateIDs(ctx, request)
	case runtimeport.PrivilegeEnableUserService:
		changed, err = e.dependencies.Service.EnsurePrivilegeUserService(ctx, request)
	case runtimeport.PrivilegeVerifyManagedState:
	case runtimeport.PrivilegeRemoveManagedPackages:
		serviceChanged, serviceError := e.dependencies.Service.DisablePrivilegeUserService(ctx, request)
		if serviceError != nil {
			err = serviceError
			break
		}
		packageChanged, packageError := e.dependencies.Packages.RemovePrivilegePackages(ctx, request, artifacts)
		changed, err = serviceChanged || packageChanged, packageError
	default:
		return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err != nil {
		return PrivilegeOperationObservationInput{}, privilegeOperationContextOrIntegrity(ctx)
	}
	observed, err := e.dependencies.Observer.ObservePrivilegeManagedState(ctx, request)
	if err != nil {
		return PrivilegeOperationObservationInput{}, privilegeOperationContextOrIntegrity(ctx)
	}
	result := runtimeport.PrivilegeResultAlreadyApplied
	if changed {
		result = runtimeport.PrivilegeResultCompleted
	}
	projected, err := projectPrivilegeManagedObservation(request, observed, result)
	if err != nil {
		return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	return projected, nil
}

func projectPrivilegeManagedObservation(
	request runtimeport.PrivilegeRequest,
	observed PrivilegeManagedStateObservation,
	result runtimeport.PrivilegeResult,
) (PrivilegeOperationObservationInput, error) {
	authority := request.Authority()
	repository, repositoryError := runtimeport.ExpectedRepositoryStateDigest(authority)
	packages, packageError := runtimeport.ExpectedPackageStateDigest(authority)
	removedPackages, removedPackageError := runtimeport.ExpectedRemovedPackageStateDigest(authority)
	if repositoryError != nil || packageError != nil || removedPackageError != nil || request.ExpectedState().IsZero() ||
		result != runtimeport.PrivilegeResultCompleted && result != runtimeport.PrivilegeResultAlreadyApplied {
		return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	output := PrivilegeOperationObservationInput{
		Result: result, ObservedState: request.ExpectedState(),
	}
	switch request.Operation() {
	case runtimeport.PrivilegeConfigureRepository:
		if observed.RepositoryDigest != repository {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		output.RepositoryDigest = observed.RepositoryDigest
	case runtimeport.PrivilegeInstallPackages:
		if observed.RepositoryDigest != repository || observed.PackageStateDigest != packages {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		output.RepositoryDigest, output.PackageStateDigest = observed.RepositoryDigest, observed.PackageStateDigest
	case runtimeport.PrivilegeConfigureSubordinateIDs:
		if !validPrivilegeSubordinateObservation(authority, observed) {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		projectPrivilegeSubordinates(&output, observed)
	case runtimeport.PrivilegeEnableUserService:
		if !validPrivilegeServiceObservation(authority, observed) {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		projectPrivilegeService(&output, observed)
	case runtimeport.PrivilegeVerifyManagedState:
		if observed.RepositoryDigest != repository || observed.PackageStateDigest != packages ||
			!validPrivilegeSubordinateObservation(authority, observed) ||
			!validPrivilegeServiceObservation(authority, observed) {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		output.RepositoryDigest, output.PackageStateDigest = observed.RepositoryDigest, observed.PackageStateDigest
		projectPrivilegeSubordinates(&output, observed)
		projectPrivilegeService(&output, observed)
	case runtimeport.PrivilegeRemoveManagedPackages:
		if observed.PackageStateDigest != removedPackages || !validRemovedPrivilegeServiceObservation(authority, observed) {
			return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
		}
		output.PackageStateDigest = observed.PackageStateDigest
		projectPrivilegeService(&output, observed)
	default:
		return PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	return output, nil
}

func validRemovedPrivilegeServiceObservation(
	authority runtimeport.LinuxAuthority,
	observed PrivilegeManagedStateObservation,
) bool {
	return observed.ServiceUnitDigest == authority.ServiceUnitDigest() && !observed.ServiceEnabled &&
		!observed.ServiceActive
}

func validPrivilegeSubordinateObservation(
	authority runtimeport.LinuxAuthority,
	observed PrivilegeManagedStateObservation,
) bool {
	count := observed.SubordinateIDs
	return count == authority.SubordinateIDCount() && observed.SubordinateUIDStart >= count &&
		observed.SubordinateGIDStart >= count && !observed.SubordinateStateDigest.IsZero() &&
		uint64(observed.SubordinateUIDStart)+uint64(count) <= uint64(math.MaxUint32)+1 &&
		uint64(observed.SubordinateGIDStart)+uint64(count) <= uint64(math.MaxUint32)+1
}

func validPrivilegeServiceObservation(
	authority runtimeport.LinuxAuthority,
	observed PrivilegeManagedStateObservation,
) bool {
	return observed.ServiceUnitDigest == authority.ServiceUnitDigest() && observed.ServiceEnabled &&
		observed.ServiceActive && observed.UserLingerEnabled
}

func projectPrivilegeSubordinates(
	output *PrivilegeOperationObservationInput,
	observed PrivilegeManagedStateObservation,
) {
	output.SubordinateIDs = observed.SubordinateIDs
	output.SubordinateUIDStart = observed.SubordinateUIDStart
	output.SubordinateGIDStart = observed.SubordinateGIDStart
	output.SubordinateStateDigest = observed.SubordinateStateDigest
}

func projectPrivilegeService(
	output *PrivilegeOperationObservationInput,
	observed PrivilegeManagedStateObservation,
) {
	output.ServiceUnitDigest = observed.ServiceUnitDigest
	output.ServiceEnabled = observed.ServiceEnabled
	output.ServiceActive = observed.ServiceActive
	output.UserLingerEnabled = observed.UserLingerEnabled
}

func privilegeOperationContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrPrivilegeIntegrity
}

var _ PrivilegeOperationExecutor = (*ClosedPrivilegeOperationExecutor)(nil)
