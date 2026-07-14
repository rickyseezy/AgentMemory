package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installworker"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
)

type nativeProductionFirstStartDependencies struct {
	Release      nativeReleaseAuthorityDependencies
	Applications nativeInstallApplicationsBuilder
	FirstStart   nativeFirstStartDependencies
}

type nativeInstallApplicationsBuilder func(
	context.Context,
	*nativeReleaseAuthority,
) (nativeInstallApplicationFactory, error)

// nativeProductionFirstStart owns both the retained release authority and the
// sole process supervisor used by initialization and Setup Accept/Retry.
type nativeProductionFirstStart struct {
	Factory    *Factory
	Supervisor *installworker.Supervisor
	Release    *nativeReleaseAuthority
}

// composeNativeProductionFirstStart is the only bridge from independently
// verified release bytes into pristine publication and asynchronous install
// execution. It never accepts a hand-built template or a second supervisor.
func composeNativeProductionFirstStart(
	ctx context.Context,
	dependencies nativeProductionFirstStartDependencies,
) (nativeProductionFirstStart, error) {
	if ctx == nil || dependencies.Applications == nil ||
		nilAny(dependencies.FirstStart.Resolver) || nilAny(dependencies.FirstStart.Plans) ||
		nilAny(dependencies.FirstStart.Operations) || nilAny(dependencies.FirstStart.Preparations) ||
		nilAny(dependencies.FirstStart.Binder) || nilAny(dependencies.FirstStart.Runtime) {
		return nativeProductionFirstStart{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nativeProductionFirstStart{}, err
	}
	release, err := newNativeReleaseAuthority(ctx, dependencies.Release)
	if err != nil {
		return nativeProductionFirstStart{}, err
	}
	failed := true
	defer func() {
		if failed {
			_ = release.Close(context.WithoutCancel(ctx))
		}
	}()
	firstStart := dependencies.FirstStart
	applications, err := dependencies.Applications(ctx, release)
	if err != nil || nilAny(applications) {
		return nativeProductionFirstStart{}, errNativeInstallerIntegrity
	}
	firstStart.Applications = applications
	firstStart.Templates = release.templates()
	// The subordinate composer has no operation context; its only context use
	// is an unconditional cleanup context if construction fails.
	composition, err := composeNativeFirstStart(firstStart) //nolint:contextcheck
	if err != nil {
		return nativeProductionFirstStart{}, firststartapp.ErrIntegrity
	}
	failed = false
	return nativeProductionFirstStart{
		Factory: composition.Factory, Supervisor: composition.Supervisor, Release: release,
	}, nil
}
