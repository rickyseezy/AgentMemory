package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
)

func newNativeProductionReadySurfaceFactory(
	composition *nativeComposition,
	release *nativeReleaseAuthority,
) (readySurfaceFactory, error) {
	if composition == nil || composition.resources == nil || composition.plans == nil ||
		composition.operations == nil || composition.resourceState == nil || composition.runtimeRemoval == nil ||
		composition.runtimeOwnership == nil || composition.removalConsentBroker == nil ||
		composition.runtimeCatalogAnchor == nil || composition.readinessRoot == "" || release == nil ||
		release.runtimeCatalogLoader() == nil || release.hostVerification() == nil {
		return nil, errNativeInstallerIntegrity
	}
	return func(
		ctx context.Context,
		projection runtimePlanProjection,
	) (mcpbootstrap.ReadySurfaceProvider, error) {
		if ctx == nil || projection.operationID.IsZero() || projection.digest.IsZero() ||
			projection.installationID == "" {
			return nil, errNativeInstallerIntegrity
		}
		status, err := corehttp.NewStatusClient(
			corehttp.NewNativeCredentialSource(), projection.coreEndpoint, projection.credentialPath,
		)
		if err != nil {
			return nil, errors.New("native core status authority is unavailable")
		}
		verified, err := resolveNativeReadyRuntimeExecution(ctx, composition, release, projection)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		removal, err := newNativePlatformManagedRuntimeRemoval(ctx, composition, release, verified)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		return newCoreReadySurfaceWithRemoval(projection.installationID, status, removal)
	}, nil
}

func resolveNativeReadyRuntimeExecution(
	ctx context.Context,
	composition *nativeComposition,
	release *nativeReleaseAuthority,
	projection runtimePlanProjection,
) (nativeVerifiedRuntimeExecution, error) {
	if ctx == nil || composition == nil || release == nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	observer, err := runtimeprovision.NewNativeCatalogObserver(
		release.runtimeCatalogPublisherVerifier(),
		nativeRuntimeHostReattestor{verifier: release.hostVerification()},
	)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	policy, err := newNativeRuntimeCatalogPolicy(
		setuphost.Clock{}, release.runtimeCatalogSignatureVerifier(),
		release.runtimeCatalogPublisherVerifier(), composition.runtimeCatalogAnchor,
	)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	evidence, err := newNativeRuntimeEvidenceResolver(release.runtimeCatalogLoader(), policy, observer)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	verifier, err := newNativeRuntimeExecutionVerifier(release.runtimeCatalogLoader(), policy)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	receipts, err := installplanfs.NewReadinessRepository(
		ctx, composition.readinessRoot, projection.credentialPath, corehttp.NewNativeCredentialSource(),
	)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	defer func() { _ = receipts.Close() }()
	plans, err := installplanapp.New(installplanapp.Dependencies{
		Plans: composition.plans, RuntimePlans: composition.plans, RuntimeEvidence: evidence,
		Operations: composition.operations, ReadinessReceipts: receipts,
		Resources: composition.resourceState, OperationID: projection.operationID,
	})
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	execution, err := plans.ResolveRuntimeExecutionAuthority(ctx, projection.digest, projection.operationID)
	if err != nil {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	verified, err := verifier.VerifyRuntimeExecution(ctx, execution)
	if err != nil || verified.authority.OperationID() != projection.operationID ||
		!verified.authority.ParentPlanDigest().Equal(projection.digest) {
		return nativeVerifiedRuntimeExecution{}, errNativeInstallerIntegrity
	}
	return verified, nil
}

func nativeRuntimeRemovalCommand(
	verified nativeVerifiedRuntimeExecution,
) (runtimeremovalapp.Command, error) {
	source := verified.authority.OperationID()
	removalID, err := deriveManagedRuntimeRemovalOperationID(source)
	if err != nil || verified.authority.Plan().Digest().IsZero() {
		return runtimeremovalapp.Command{}, errNativeInstallerIntegrity
	}
	return runtimeremovalapp.Command{
		OperationID: removalID.String(), SourceOperationID: source.String(),
		CanonicalRuntimePlan: verified.authority.Plan().CanonicalBytes(),
	}, nil
}
