//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// PrivilegeManagedStateDependencies are independent read-side capabilities.
type PrivilegeManagedStateDependencies struct {
	Repository   PrivilegeRepositoryStateProbe
	Packages     PrivilegePackageStateProbe
	Subordinates PrivilegeSubordinateIDStateProbe
	Service      PrivilegeUserServiceStateProbe
}

// NativePrivilegeManagedStateObserver projects only the evidence required by
// the selected closed operation, and re-proves every surface for final verify.
type NativePrivilegeManagedStateObserver struct {
	dependencies PrivilegeManagedStateDependencies
}

// NewNativePrivilegeManagedStateObserver rejects any missing read-side proof.
func NewNativePrivilegeManagedStateObserver(
	dependencies PrivilegeManagedStateDependencies,
) (*NativePrivilegeManagedStateObserver, error) {
	if nilArtifactDependency(dependencies.Repository) || nilArtifactDependency(dependencies.Packages) ||
		nilArtifactDependency(dependencies.Subordinates) || nilArtifactDependency(dependencies.Service) {
		return nil, errors.New("complete privilege managed-state observers are required")
	}
	return &NativePrivilegeManagedStateObserver{dependencies: dependencies}, nil
}

// ObservePrivilegeManagedState executes no mutations and returns zero values
// for evidence outside the operation's admitted receipt projection.
func (o *NativePrivilegeManagedStateObserver) ObservePrivilegeManagedState(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (PrivilegeManagedStateObservation, error) {
	if o == nil || ctx == nil || request.Digest().IsZero() || !request.Authority().Valid() {
		return PrivilegeManagedStateObservation{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return PrivilegeManagedStateObservation{}, err
	}
	observation := PrivilegeManagedStateObservation{}
	var err error
	switch request.Operation() {
	case runtimeport.PrivilegeConfigureRepository:
		err = o.observeRepository(ctx, request, &observation)
	case runtimeport.PrivilegeInstallPackages:
		if err = o.observeRepository(ctx, request, &observation); err == nil {
			err = o.observePackages(ctx, request, &observation)
		}
	case runtimeport.PrivilegeConfigureSubordinateIDs:
		err = o.observeSubordinates(ctx, request, &observation)
	case runtimeport.PrivilegeEnableUserService:
		err = o.observeService(ctx, request, &observation)
	case runtimeport.PrivilegeVerifyManagedState:
		if err = o.observeRepository(ctx, request, &observation); err == nil {
			err = o.observePackages(ctx, request, &observation)
		}
		if err == nil {
			err = o.observeSubordinates(ctx, request, &observation)
		}
		if err == nil {
			err = o.observeService(ctx, request, &observation)
		}
	case runtimeport.PrivilegeRemoveManagedPackages:
		if err = o.observeRemovedPackages(ctx, request, &observation); err == nil {
			err = o.observeService(ctx, request, &observation)
		}
	default:
		err = runtimeport.ErrPrivilegeIntegrity
	}
	if err != nil {
		return PrivilegeManagedStateObservation{}, privilegeOperationContextOrIntegrity(ctx)
	}
	return observation, nil
}

func (o *NativePrivilegeManagedStateObserver) observeRemovedPackages(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	observation *PrivilegeManagedStateObservation,
) error {
	absent, err := o.dependencies.Packages.PrivilegeManagedPackagesAbsent(ctx, request.Authority())
	if err != nil || !absent {
		return runtimeport.ErrPrivilegeIntegrity
	}
	observation.PackageStateDigest, err = runtimeport.ExpectedRemovedPackageStateDigest(request.Authority())
	return err
}

func (o *NativePrivilegeManagedStateObserver) observeRepository(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	observation *PrivilegeManagedStateObservation,
) error {
	matches, err := o.dependencies.Repository.PrivilegeRepositoryStateMatches(ctx, request.Authority())
	if err != nil || !matches {
		return runtimeport.ErrPrivilegeIntegrity
	}
	observation.RepositoryDigest, err = runtimeport.ExpectedRepositoryStateDigest(request.Authority())
	return err
}

func (o *NativePrivilegeManagedStateObserver) observePackages(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	observation *PrivilegeManagedStateObservation,
) error {
	matches, err := o.dependencies.Packages.PrivilegePackageStateMatches(ctx, request.Authority())
	if err != nil || !matches {
		return runtimeport.ErrPrivilegeIntegrity
	}
	observation.PackageStateDigest, err = runtimeport.ExpectedPackageStateDigest(request.Authority())
	return err
}

func (o *NativePrivilegeManagedStateObserver) observeSubordinates(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	observation *PrivilegeManagedStateObservation,
) error {
	uidStart, gidStart, count, digest, err := o.dependencies.Subordinates.ObservePrivilegeSubordinateIDState(
		ctx, request.Authority(),
	)
	if err != nil {
		return err
	}
	observation.SubordinateUIDStart, observation.SubordinateGIDStart = uidStart, gidStart
	observation.SubordinateIDs, observation.SubordinateStateDigest = count, digest
	return nil
}

func (o *NativePrivilegeManagedStateObserver) observeService(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	observation *PrivilegeManagedStateObservation,
) error {
	unit, linger, enabled, active, err := o.dependencies.Service.ObservePrivilegeUserServiceState(
		ctx, request.Authority(),
	)
	if err != nil {
		return err
	}
	observation.ServiceUnitDigest, observation.UserLingerEnabled = unit, linger
	observation.ServiceEnabled, observation.ServiceActive = enabled, active
	return nil
}

var _ PrivilegeManagedStateObserver = (*NativePrivilegeManagedStateObserver)(nil)
