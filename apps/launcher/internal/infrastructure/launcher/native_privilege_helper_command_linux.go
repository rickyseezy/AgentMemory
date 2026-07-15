//go:build linux

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/hostlock"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseanchor"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimecataloganchor"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

const (
	nativePrivilegeHelperStateRoot   = "/var/lib/agentmemory/runtime-helper"
	nativePrivilegeRequestInputLimit = 64 * 1024 * 1024
)

// RunNativeLinuxPrivilegeHelper is the installed helper's complete command
// boundary. It accepts no paths, commands, identities, or configuration from
// argv and emits only one canonical signed receipt on success.
func RunNativeLinuxPrivilegeHelper(
	ctx context.Context,
	arguments []string,
	input io.Reader,
	output io.Writer,
) error {
	if ctx == nil || !slices.Equal(arguments, []string{"--request-stdin"}) ||
		nilAny(input) || nilAny(output) || os.Geteuid() != 0 {
		return runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(input, nativePrivilegeRequestInputLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > nativePrivilegeRequestInputLimit {
		return runtimeport.ErrPrivilegeIntegrity
	}
	lockPort, err := hostlock.New(nativePrivilegeHelperStateRoot + "/execution.lock")
	if err != nil {
		clear(raw)
		return runtimeport.ErrPrivilegeIntegrity
	}
	lock, err := lockPort.Acquire(ctx)
	if err != nil {
		clear(raw)
		return privilegeHelperCommandContextOrIntegrity(ctx)
	}
	application, release, err := newNativeLinuxPrivilegeHelperApplication(ctx)
	if err != nil {
		_ = lock.Release(context.WithoutCancel(ctx))
		clear(raw)
		return runtimeport.ErrPrivilegeIntegrity
	}
	receipt, executeError := application.ExecutePrivilegeRequest(ctx, raw)
	clear(raw)
	closeError := release.Close(context.WithoutCancel(ctx))
	unlockError := lock.Release(context.WithoutCancel(ctx))
	if executeError != nil || closeError != nil || unlockError != nil || len(receipt) == 0 {
		return privilegeHelperCommandContextOrIntegrity(ctx)
	}
	written, err := io.Copy(output, bytes.NewReader(receipt))
	if err != nil || written != int64(len(receipt)) { // #nosec G115 -- canonical receipt length is strictly bounded.
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

func newNativeLinuxPrivilegeHelperApplication(
	ctx context.Context,
) (*runtimeprovision.PrivilegeHelperApplication, *nativeReleaseAuthority, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	clock := setuphost.Clock{}
	releaseLocator, err := bootstrapadapter.NewOperationLocator(
		nativePrivilegeHelperStateRoot + "/release-anchor-state",
	)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	catalogLocator, err := bootstrapadapter.NewOperationLocator(
		nativePrivilegeHelperStateRoot + "/runtime-catalog-anchor-state",
	)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	releaseJournals, err := newPlatformJournalProvider(releaseLocator)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	catalogJournals, err := newPlatformJournalProvider(catalogLocator)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	replayLocator, err := bootstrapadapter.NewOperationLocator(
		nativePrivilegeHelperStateRoot + "/request-replay-state",
	)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	replayJournals, err := newPlatformJournalProvider(replayLocator)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	releaseAnchors, err := releaseanchor.NewRepositoryFromProvider(ctx, releaseJournals, clock)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	catalogAnchors, err := runtimecataloganchor.NewRepositoryFromProvider(ctx, catalogJournals, clock)
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	release, err := newNativeReleaseAuthority(ctx, nativeReleaseAuthorityDependencies{
		BundleRoot: defaultNativeReleaseBundleRoot, Trust: loadEmbeddedNativeReleaseTrust,
		Clock: clock, AntiRollback: releaseAnchors,
	})
	if err != nil {
		return nil, nil, runtimeport.ErrPrivilegeIntegrity
	}
	fail := func(cause error) (*runtimeprovision.PrivilegeHelperApplication, *nativeReleaseAuthority, error) {
		_ = release.Close(context.WithoutCancel(ctx))
		return nil, nil, errors.Join(runtimeport.ErrPrivilegeIntegrity, cause)
	}
	binding, err := runtimeprovision.NewPrivilegedLinuxHostBindingProvider()
	if err != nil {
		return fail(err)
	}
	host, err := runtimeprovision.NewPrivilegedLinuxCatalogHostProvider(binding)
	if err != nil {
		return fail(err)
	}
	catalogApplication, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: clock, Host: host, Signature: release.runtimeCatalogSignatureVerifier(),
		NativePublisher: release.runtimeCatalogPublisherVerifier(), AntiRollback: catalogAnchors,
	})
	if err != nil {
		return fail(err)
	}
	releases, err := newNativeVerifiedPrivilegeReleaseAuthority(release.verifier())
	if err != nil {
		return fail(err)
	}
	catalogs, err := newNativeVerifiedPrivilegeCatalogAuthority(catalogApplication, binding)
	if err != nil {
		return fail(err)
	}
	self, err := NewNativePrivilegeHelperSelfVerifier()
	if err != nil {
		return fail(err)
	}
	authority, err := newNativePrivilegeAuthorityVerifier(releases, catalogs, self)
	if err != nil {
		return fail(err)
	}
	artifacts, err := runtimeprovision.NewRootPrivilegeArtifactStore()
	if err != nil {
		return fail(err)
	}
	signer, err := runtimeprovision.NewRootPrivilegeReceiptSigner()
	if err != nil {
		return fail(err)
	}
	replay, err := runtimeprovision.NewAnchoredPrivilegeHelperReplayRepository(replayJournals, clock)
	if err != nil {
		return fail(err)
	}
	application, err := runtimeprovision.NewPrivilegeHelperApplication(runtimeprovision.PrivilegeHelperDependencies{
		Decoder: runtimeprovision.CanonicalPrivilegeRequestDecoder{}, Authority: authority,
		Artifacts: artifacts, Executor: &nativePrivilegeOperationExecutor{}, Signer: signer,
		Replay: replay, Clock: clock, Encoder: runtimeprovision.CanonicalPrivilegeReceiptEncoder{},
	})
	if err != nil {
		return fail(err)
	}
	return application, release, nil
}

func privilegeHelperCommandContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrPrivilegeIntegrity
}
