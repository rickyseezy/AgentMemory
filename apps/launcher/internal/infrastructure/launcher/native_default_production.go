package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/nativepackage"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
)

// composeDefaultNativeProduction is the exported factory's sole pristine and
// resume composition. Source builds without embedded production trust fail
// closed before publishing an installation pointer.
func composeDefaultNativeProduction(
	ctx context.Context,
	composition *nativeComposition,
) (nativeProductionFirstStart, error) {
	return composeNativeProduction(ctx, composition, defaultNativeReleaseBundleRoot)
}

func composeInstalledNativeProduction(
	ctx context.Context,
	composition *nativeComposition,
) (nativeProductionFirstStart, error) {
	return composeNativeProduction(ctx, composition, nativepackage.NativeInstalledReleaseBundleRoot)
}

func composeNativeProduction(
	ctx context.Context,
	composition *nativeComposition,
	bundleRoot nativeReleaseBundleRootResolver,
) (nativeProductionFirstStart, error) {
	if ctx == nil || composition == nil || nilAny(composition.resolver) || composition.runtime == nil ||
		composition.plans == nil || composition.operations == nil ||
		composition.rebootCoordinator == nil ||
		nilAny(composition.preparations) || nilAny(composition.binder) || composition.releaseAnchor == nil ||
		bundleRoot == nil {
		return nativeProductionFirstStart{}, errNativeInstallerIntegrity
	}
	applications, err := newNativeInstallApplicationsBuilder(composition)
	if err != nil {
		return nativeProductionFirstStart{}, errNativeInstallerIntegrity
	}
	production, err := composeNativeProductionFirstStart(ctx, nativeProductionFirstStartDependencies{
		Release: nativeReleaseAuthorityDependencies{
			BundleRoot:   bundleRoot,
			Trust:        loadEmbeddedNativeReleaseTrust,
			Clock:        setuphost.Clock{},
			AntiRollback: composition.releaseAnchor,
		},
		Applications: applications,
		FirstStart: nativeFirstStartDependencies{
			Resolver: composition.resolver,
			Plans:    composition.plans, Operations: composition.operations,
			Preparations: composition.preparations, Binder: composition.binder,
			Runtime: composition.runtime,
		},
	})
	if err != nil {
		return nativeProductionFirstStart{}, err
	}
	ready, err := newNativeProductionReadySurfaceFactory(composition, production.Release)
	if err != nil {
		_ = production.Supervisor.Close(context.WithoutCancel(ctx))
		_ = production.Release.Close(context.WithoutCancel(ctx))
		return nativeProductionFirstStart{}, errNativeInstallerIntegrity
	}
	composition.runtime.readyForPlan = ready
	return production, nil
}
