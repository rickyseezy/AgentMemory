//go:build darwin || windows

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func newNativePlatformManagedRuntimeRemoval(
	ctx context.Context,
	composition *nativeComposition,
	release *nativeReleaseAuthority,
	verified nativeVerifiedRuntimeExecution,
) (managedRuntimeRemovalController, error) {
	factory := &nativePlatformRuntimeFactory{
		composition: composition, release: release,
		desktopAuthority: buildNativeDesktopAuthority, desktopHelpers: buildNativeDesktopHelpers,
	}
	return factory.buildDesktopManagedRuntimeRemoval(ctx, verified)
}

func (f *nativePlatformRuntimeFactory) buildDesktopManagedRuntimeRemoval(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (managedRuntimeRemovalController, error) {
	if f == nil || ctx == nil || f.composition == nil || f.composition.resources == nil || f.release == nil ||
		f.desktopAuthority == nil || f.desktopHelpers == nil ||
		(verified.runtime.Platform() != runtimeinstall.PlatformDarwin &&
			verified.runtime.Platform() != runtimeinstall.PlatformWindows) {
		return nil, errNativeInstallerIntegrity
	}
	security, err := newNativeDesktopPlatformSecurity()
	if err != nil {
		return nil, errNativeInstallerUnavailable
	}
	retained := false
	defer func() {
		if !retained {
			_ = closeNativeRuntimeResources(context.WithoutCancel(ctx), security.closers)
		}
	}()
	authoritySet, err := f.desktopAuthority(ctx, verified, f.release)
	if err != nil || nilAny(authoritySet.resolver) || !authoritySet.authority.ValidFor(verified.authority.Plan()) {
		return nil, errNativeInstallerIntegrity
	}
	desktop := authoritySet.authority
	runners, err := newNativeDesktopRunnerPair(desktop, verified.request.SignedRelease.Manifest().Digest())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	executors, err := dockercli.NewExecutors(runners.docker, runners.compose)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	scanner, err := dockercli.NewRuntimeDependencyScanner(
		executors, dockercli.NewNativeActiveRuntimeClientScanner(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	installed, err := runtimeprovision.NewNativeDesktopInstalledApplicationProbe(
		runtimeprovision.DesktopInstalledApplicationProbeDependencies{WindowsSigner: security.signer},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	presence, err := runtimeprovision.NewDesktopRuntimeRemovalPresenceVerifier(authoritySet.resolver, installed)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	helperSet, err := f.desktopHelpers(f.release, verified)
	if err != nil || nilAny(helperSet.authority) || nilAny(helperSet.publisher) || nilAny(helperSet.encoder) {
		return nil, errNativeInstallerIntegrity
	}
	mutation, err := runtimeprovision.NewNativeDesktopMutationBroker(
		runtimeprovision.NativeDesktopMutationDependencies{
			Authority: helperSet.authority, Publisher: helperSet.publisher, Encoder: helperSet.encoder,
		},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	resolvedHelper, err := helperSet.authority.ResolveDesktopHelperAuthority(ctx, desktop)
	if err != nil || !resolvedHelper.ValidFor(desktop) ||
		helperSet.publisher.VerifyDesktopHelperPublisher(ctx, resolvedHelper) != nil {
		return nil, errNativeInstallerIntegrity
	}
	publicKeys, err := runtimeprovision.NewProtectedDesktopMutationReceiptPublicKeySource(
		resolvedHelper.CanonicalPath(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	authenticator, err := runtimeprovision.NewProtectedEd25519DesktopMutationAuthenticator(
		publicKeys, resolvedHelper.SHA256(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	replay, err := f.composition.newRuntimeReplayLedger(verified.authority.OperationID())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	remover, err := runtimeprovision.NewDesktopRuntimeRemover(
		runtimeprovision.DesktopRuntimeRemoverDependencies{
			Authority: authoritySet.resolver, Mutation: mutation, MutationAuthenticator: authenticator,
			MutationReplay: replay, Nonces: runtimeprovision.NewCryptoNonceSource(), Clock: setuphost.Clock{},
		},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	application, err := runtimeremovalapp.New(runtimeremovalapp.Dependencies{
		Operations: f.composition.runtimeRemoval, Ownership: f.composition.runtimeOwnership,
		Scanner: scanner, Consent: f.composition.removalConsentBroker, Presence: presence, Remover: remover,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	command, err := nativeRuntimeRemovalCommand(verified)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	controller, err := newNativeManagedRuntimeRemovalController(
		command, nativeRuntimeRemovalApplication{application: application}, f.composition.removalConsentBroker,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	if err := f.composition.resources.addClosers(security.closers...); err != nil {
		return nil, errNativeInstallerUnavailable
	}
	retained = true
	return controller, nil
}
