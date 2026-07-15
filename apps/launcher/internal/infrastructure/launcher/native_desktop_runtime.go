package launcher

import (
	"context"
	"errors"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func (f *nativePlatformRuntimeFactory) buildDesktopRuntimeApplication(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	if f == nil || f.composition == nil || f.release == nil || ctx == nil ||
		f.desktopAuthority == nil || f.desktopArtifacts == nil || f.desktopHelpers == nil ||
		(verified.runtime.Platform() != runtimeinstall.PlatformDarwin &&
			verified.runtime.Platform() != runtimeinstall.PlatformWindows) {
		return nil, errNativeInstallerIntegrity
	}
	security, err := newNativeDesktopPlatformSecurity()
	if err != nil {
		return nil, errNativeInstallerUnavailable
	}
	failed := true
	defer func() {
		if failed {
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
	installed, err := runtimeprovision.NewNativeDesktopInstalledApplicationProbe(
		runtimeprovision.DesktopInstalledApplicationProbeDependencies{WindowsSigner: security.signer},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	inspector, err := runtimeprovision.NewDesktopDockerInspector(runners.docker, runners.compose, installed)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	capabilities, err := runtimeprovision.NewDockerCapabilityProbe(runners.docker, runners.compose)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	artifactSet, err := f.desktopArtifacts(verified, f.artifacts, f.composition, security)
	if err != nil || nilAny(artifactSet.acquirer) || nilAny(artifactSet.verifier) {
		return nil, errNativeInstallerIntegrity
	}
	host, err := runtimeprovision.NewNativeDesktopHostProbe(security.host)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	launcher, err := runtimeprovision.NewNativeDesktopRuntimeLauncher()
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
	mutationAuthenticator, err := runtimeprovision.NewProtectedEd25519DesktopMutationAuthenticator(
		publicKeys, resolvedHelper.SHA256(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	replay, err := f.composition.newRuntimeReplayLedger(verified.authority.OperationID())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	provisioner, err := runtimeprovision.NewDesktopProvisioner(runtimeprovision.DesktopDependencies{
		Authority: authoritySet.resolver, Host: host, Runtime: inspector,
		Consent: f.composition.consentBroker, ConsentAuthenticator: f.composition.consentBroker,
		ConsentRepository: f.composition.consentRepository,
		Artifacts:         artifactSet.acquirer, ArtifactVerifier: artifactSet.verifier,
		Mutation: mutation, MutationAuthenticator: mutationAuthenticator, MutationReplay: replay,
		Launcher: launcher, Capabilities: capabilities, Nonces: runtimeprovision.NewCryptoNonceSource(),
		Clock: setuphost.Clock{},
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: f.composition.runtimeState,
		Host:       provisioner, Detector: provisioner, Catalog: provisioner, Consent: provisioner,
		Fetcher: provisioner, Verifier: provisioner, Prerequisites: provisioner,
		Installer: provisioner, Terms: provisioner, Controller: provisioner, Capabilities: provisioner,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	failed = false
	return &managedNativeRuntimeApplication{application: application, closers: security.closers}, nil
}

func buildNativeDesktopAuthority(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
	release *nativeReleaseAuthority,
) (nativeDesktopAuthoritySet, error) {
	if release == nil {
		return nativeDesktopAuthoritySet{}, errNativeInstallerIntegrity
	}
	resolver, err := runtimeprovision.NewCatalogDesktopAuthorityResolver(
		verified.catalog, runtimeprovision.NewNativeDesktopHostBindingProvider(),
		release.runtimeCatalogPublisherVerifier(),
	)
	if err != nil {
		return nativeDesktopAuthoritySet{}, errNativeInstallerIntegrity
	}
	authority, err := resolver.ResolveDesktopAuthority(ctx, verified.authority.Plan().CanonicalBytes())
	if err != nil {
		return nativeDesktopAuthoritySet{}, errNativeInstallerIntegrity
	}
	return nativeDesktopAuthoritySet{resolver: resolver, authority: authority}, nil
}

func buildNativeDesktopArtifacts(
	verified nativeVerifiedRuntimeExecution,
	artifacts *artifactapp.Application,
	composition *nativeComposition,
	security nativeDesktopPlatformSecurity,
) (nativeDesktopArtifactSet, error) {
	if composition == nil {
		return nativeDesktopArtifactSet{}, errNativeInstallerIntegrity
	}
	acquirer, err := runtimeprovision.NewCatalogDesktopArtifactAcquirer(
		verified.catalog, artifacts, composition.artifactStore,
	)
	if err != nil {
		return nativeDesktopArtifactSet{}, errNativeInstallerIntegrity
	}
	verifier, err := runtimeprovision.NewNativeDesktopArtifactVerifier(
		runtimeprovision.DesktopArtifactVerifierDependencies{Provenance: acquirer, WindowsSigner: security.signer},
	)
	if err != nil {
		return nativeDesktopArtifactSet{}, errNativeInstallerIntegrity
	}
	return nativeDesktopArtifactSet{acquirer: acquirer, verifier: verifier}, nil
}

func buildNativeDesktopHelpers(
	release *nativeReleaseAuthority,
	verified nativeVerifiedRuntimeExecution,
) (nativeDesktopHelperSet, error) {
	authority, publisher, err := newNativeDesktopHelperTrust(release, verified.request.SignedRelease)
	if err != nil {
		return nativeDesktopHelperSet{}, errNativeInstallerIntegrity
	}
	encoder, err := buildNativeDesktopMutationEncoder(verified)
	if err != nil {
		return nativeDesktopHelperSet{}, errNativeInstallerIntegrity
	}
	return nativeDesktopHelperSet{authority: authority, publisher: publisher, encoder: encoder}, nil
}

type managedNativeRuntimeApplication struct {
	application installphase.RuntimeEnsurer
	closers     []nativeRuntimeResourceCloser
	closeOnce   sync.Once
	closeError  error
}

func (a *managedNativeRuntimeApplication) Ensure(
	ctx context.Context,
	command runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	if a == nil || nilAny(a.application) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	result, ensureError := a.application.Ensure(ctx, command)
	closeError := a.Close(context.WithoutCancel(ctx))
	if closeError != nil {
		return result, errors.Join(ensureError, errNativeInstallerUnavailable)
	}
	return result, ensureError
}

func (a *managedNativeRuntimeApplication) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() { a.closeError = closeNativeRuntimeResources(ctx, a.closers) })
	return a.closeError
}

func closeNativeRuntimeResources(ctx context.Context, closers []nativeRuntimeResourceCloser) error {
	var closeErrors []error
	for index := len(closers) - 1; index >= 0; index-- {
		if !nilAny(closers[index]) {
			if err := closers[index].Close(ctx); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
	}
	return errors.Join(closeErrors...)
}

var _ installphase.RuntimeEnsurer = (*managedNativeRuntimeApplication)(nil)
