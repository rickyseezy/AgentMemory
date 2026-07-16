//go:build darwin || windows

package launcher

import (
	"context"
	"errors"
	"path/filepath"
	"slices"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/hostlock"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseanchor"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimecataloganchor"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeDesktopHelperExchange interface {
	ReadDesktopMutationRequest(context.Context, string) ([]byte, string, error)
	WriteDesktopMutationReceipt(context.Context, string, []byte) error
	PrincipalID() string
}

type nativeDesktopHelperCommandApplication interface {
	ExecuteDesktopMutationRequest(context.Context, []byte) ([]byte, error)
}

type nativeDesktopHelperCommandRelease interface {
	Close(context.Context) error
}

type nativeDesktopHelperCommandDependencies struct {
	elevated    func() bool
	boundaries  func(string) (string, nativeDesktopHelperExchange, error)
	application func(
		context.Context,
		string,
		string,
	) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error)
}

// RunNativeDesktopMutationHelper is the installed macOS/Windows helper's
// complete command boundary. It accepts exactly one request path and writes
// the canonical receipt beside that owner-private request.
func RunNativeDesktopMutationHelper(ctx context.Context, arguments []string) error {
	return runNativeDesktopMutationHelper(ctx, arguments, nativeDesktopHelperCommandDependencies{
		elevated: nativeDesktopHelperElevated, boundaries: nativeDesktopHelperPlatformBoundaries,
		application: func(
			ctx context.Context,
			stateRoot string,
			principalID string,
		) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
			return newNativeDesktopMutationHelperApplication(ctx, stateRoot, principalID)
		},
	})
}

func runNativeDesktopMutationHelper(
	ctx context.Context,
	arguments []string,
	dependencies nativeDesktopHelperCommandDependencies,
) error {
	if ctx == nil || dependencies.elevated == nil || dependencies.boundaries == nil ||
		dependencies.application == nil || !dependencies.elevated() || len(arguments) != 2 ||
		arguments[0] != "--execute-desktop-mutation" || arguments[1] == "" {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stateRoot, exchange, err := dependencies.boundaries(arguments[1])
	if err != nil || stateRoot == "" || nilAny(exchange) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	raw, receiptPath, err := exchange.ReadDesktopMutationRequest(ctx, arguments[1])
	if err != nil || len(raw) == 0 || receiptPath == "" {
		clear(raw)
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	lockPort, err := hostlock.New(filepath.Join(stateRoot, "execution.lock"))
	if err != nil {
		clear(raw)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	lock, err := lockPort.Acquire(ctx)
	if err != nil {
		clear(raw)
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	application, release, closers, err := dependencies.application(
		ctx, stateRoot, exchange.PrincipalID(),
	)
	if err != nil || nilAny(application) || nilAny(release) {
		_ = lock.Release(context.WithoutCancel(ctx))
		clear(raw)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	receipt, executeError := application.ExecuteDesktopMutationRequest(ctx, raw)
	clear(raw)
	closeError := closeNativeRuntimeResources(context.WithoutCancel(ctx), closers)
	releaseError := release.Close(context.WithoutCancel(ctx))
	writeError := error(nil)
	if executeError == nil && len(receipt) != 0 {
		writeError = exchange.WriteDesktopMutationReceipt(ctx, receiptPath, receipt)
	}
	clear(receipt)
	unlockError := lock.Release(context.WithoutCancel(ctx))
	if executeError != nil || closeError != nil || releaseError != nil || writeError != nil || unlockError != nil {
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	return nil
}

func newNativeDesktopMutationHelperApplication(
	ctx context.Context,
	stateRoot string,
	principalID string,
) (*runtimeprovision.DesktopMutationHelperApplication, *nativeReleaseAuthority, []nativeRuntimeResourceCloser, error) {
	return newNativeDesktopMutationHelperApplicationWithAuthority(
		ctx, stateRoot, principalID, nativeDesktopMutationHelperCompositionAuthority{
			elevated:   nativeDesktopHelperElevated,
			bundleRoot: nativeDesktopHelperReleaseBundleRoot,
			trust:      loadEmbeddedNativeReleaseTrust,
			binding:    runtimeprovision.NewPrivilegedDesktopHostBindingProvider,
			journals: func(root string, name string) (filesystem.OperationJournalProvider, error) {
				locator, err := bootstrapadapter.NewOperationLocator(filepath.Join(root, name))
				if err != nil {
					return nil, err
				}
				return newPlatformJournalProvider(locator)
			},
		},
	)
}

type nativeDesktopMutationHelperCompositionAuthority struct {
	elevated   func() bool
	bundleRoot nativeReleaseBundleRootResolver
	trust      nativeReleaseTrustLoader
	binding    func(string) (runtimeprovision.DesktopHostBindingProvider, error)
	journals   func(string, string) (filesystem.OperationJournalProvider, error)
}

func newNativeDesktopMutationHelperApplicationWithAuthority(
	ctx context.Context,
	stateRoot string,
	principalID string,
	compositionAuthority nativeDesktopMutationHelperCompositionAuthority,
) (*runtimeprovision.DesktopMutationHelperApplication, *nativeReleaseAuthority, []nativeRuntimeResourceCloser, error) {
	if ctx == nil || compositionAuthority.elevated == nil || compositionAuthority.bundleRoot == nil || compositionAuthority.trust == nil ||
		compositionAuthority.binding == nil || compositionAuthority.journals == nil ||
		!compositionAuthority.elevated() || stateRoot == "" || principalID == "" {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	clock := setuphost.Clock{}
	newJournals := func(name string) (filesystem.OperationJournalProvider, error) {
		return compositionAuthority.journals(stateRoot, name)
	}
	releaseJournals, err := newJournals("release-anchor-state")
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	catalogJournals, err := newJournals("runtime-catalog-anchor-state")
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	replayJournals, err := newJournals("request-replay-state")
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	releaseAnchors, err := releaseanchor.NewRepositoryFromProvider(ctx, releaseJournals, clock)
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	catalogAnchors, err := runtimecataloganchor.NewRepositoryFromProvider(ctx, catalogJournals, clock)
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	release, err := newNativeReleaseAuthority(ctx, nativeReleaseAuthorityDependencies{
		BundleRoot: compositionAuthority.bundleRoot, Trust: compositionAuthority.trust,
		Clock: clock, AntiRollback: releaseAnchors,
	})
	if err != nil {
		return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	fail := func(cause error, closers []nativeRuntimeResourceCloser) (
		*runtimeprovision.DesktopMutationHelperApplication, *nativeReleaseAuthority, []nativeRuntimeResourceCloser, error,
	) {
		_ = closeNativeRuntimeResources(context.WithoutCancel(ctx), closers)
		_ = release.Close(context.WithoutCancel(ctx))
		return nil, nil, nil, errors.Join(runtimeport.ErrDesktopMutationIntegrity, cause)
	}
	binding, err := compositionAuthority.binding(principalID)
	if err != nil {
		return fail(err, nil)
	}
	host, err := runtimeprovision.NewPrivilegedDesktopCatalogHostProvider(binding)
	if err != nil {
		return fail(err, nil)
	}
	catalogApplication, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: clock, Host: host, Signature: release.runtimeCatalogSignatureVerifier(),
		NativePublisher: release.runtimeCatalogPublisherVerifier(), AntiRollback: catalogAnchors,
	})
	if err != nil {
		return fail(err, nil)
	}
	releases, err := newNativeVerifiedDesktopReleaseAuthority(
		release.verifier(), release.runtimeHelperPublisherCertificates,
	)
	if err != nil {
		return fail(err, nil)
	}
	catalogs, err := newNativeVerifiedDesktopCatalogAuthority(
		catalogApplication, binding, release.runtimeCatalogPublisherVerifier(),
	)
	if err != nil {
		return fail(err, nil)
	}
	self, err := runtimeprovision.NewNativeDesktopHelperExecutableVerifier(
		release.runtimeHelperPublisherCertificates,
	)
	if err != nil {
		return fail(err, nil)
	}
	authority, err := newNativeDesktopMutationAuthorityVerifier(releases, catalogs, self)
	if err != nil {
		return fail(err, nil)
	}
	artifacts, err := runtimeprovision.NewProtectedDesktopMutationArtifactStore()
	if err != nil {
		return fail(err, nil)
	}
	signer, err := runtimeprovision.NewNativeDesktopMutationReceiptSigner()
	if err != nil {
		return fail(err, nil)
	}
	replay, err := runtimeprovision.NewAnchoredDesktopMutationHelperReplayRepository(replayJournals, clock)
	if err != nil {
		return fail(err, nil)
	}
	security, err := newNativeDesktopPlatformSecurity()
	if err != nil {
		return fail(err, nil)
	}
	probe, err := runtimeprovision.NewNativeDesktopHostProbe(security.host)
	if err != nil {
		return fail(err, security.closers)
	}
	installed, err := runtimeprovision.NewNativeDesktopInstalledApplicationProbe(
		runtimeprovision.DesktopInstalledApplicationProbeDependencies{WindowsSigner: security.signer},
	)
	if err != nil {
		return fail(err, security.closers)
	}
	executor, err := runtimeprovision.NewNativeDesktopMutationOperationExecutor(
		probe, installed, nativeDesktopMutationCommandRunner{}, release.source,
	)
	if err != nil {
		return fail(err, security.closers)
	}
	application, err := runtimeprovision.NewDesktopMutationHelperApplication(
		runtimeprovision.DesktopMutationHelperDependencies{
			Decoder: runtimeprovision.CanonicalDesktopMutationRequestDecoder{}, Authority: authority,
			Artifacts: artifacts, Executor: executor, Replay: replay, Signer: signer,
			Clock: clock, Encoder: runtimeprovision.CanonicalDesktopMutationReceiptEncoder{},
		},
	)
	if err != nil {
		return fail(err, security.closers)
	}
	return application, release, slices.Clone(security.closers), nil
}

func desktopHelperCommandContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrDesktopMutationIntegrity
}

//lint:ignore U1000 platform-specific desktop helper decoders call this function
func canonicalDesktopHelperDigest(value string) bool {
	digest, err := runtimeinstall.ParseHash(value)
	return err == nil && !digest.IsZero()
}
