package launcher

import (
	"context"
	"errors"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/hostverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
)

type nativeReleaseBundleRootResolver func() (string, error)
type nativeReleaseTrustLoader func() (nativeReleaseTrustMaterial, error)

type nativeReleaseAuthorityDependencies struct {
	BundleRoot   nativeReleaseBundleRootResolver
	Trust        nativeReleaseTrustLoader
	Clock        appreleaseverify.Clock
	AntiRollback appreleaseverify.AntiRollbackRepository
}

// nativeReleaseAuthority owns the retained descriptor-rooted bundle and the
// complete verifier stack derived from independently embedded public trust.
// No environment variable, working directory, network locator, or MCP input
// participates in its construction.
type nativeReleaseAuthority struct {
	source          *artifactfs.BundleFetcher
	stack           nativeReleaseStack
	hostProbe       *hostverify.NativeProbe
	hostVerifier    *hostverifyapp.Application
	releaseVerifier *installphase.ReleaseApplicationAdapter
	runtimeCatalog  *nativeRuntimeCatalogLoader
	closeOnce       sync.Once
	closeError      error
}

func newNativeReleaseAuthority(
	ctx context.Context,
	dependencies nativeReleaseAuthorityDependencies,
) (*nativeReleaseAuthority, error) {
	if ctx == nil || dependencies.BundleRoot == nil || dependencies.Trust == nil ||
		nilAny(dependencies.Clock) || nilAny(dependencies.AntiRollback) {
		return nil, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := dependencies.BundleRoot()
	if err != nil || root == "" {
		return nil, firststartapp.ErrUnavailable
	}
	source, err := artifactfs.NewBundleFetcher(root)
	if err != nil {
		return nil, firststartapp.ErrUnavailable
	}
	failed := true
	defer func() {
		if failed {
			_ = source.Close()
		}
	}()
	trust, err := dependencies.Trust()
	if err != nil {
		return nil, firststartapp.ErrIntegrity
	}
	stack, err := newNativeReleaseStack(nativeReleaseStackDependencies{
		Source: source, Clock: dependencies.Clock,
		AntiRollback: dependencies.AntiRollback, Trust: trust,
	})
	if err != nil {
		return nil, firststartapp.ErrIntegrity
	}
	hostSignature, err := hostverify.NewEd25519Verifier(trust.HostPolicyKeys)
	if err != nil {
		return nil, firststartapp.ErrIntegrity
	}
	hostProbe := hostverify.NewNativeProbe()
	hostApplication, err := hostverifyapp.NewApplication(hostverifyapp.Dependencies{
		Signature: hostSignature, Probe: hostProbe,
	})
	if err != nil {
		_ = hostProbe.Close(context.WithoutCancel(ctx))
		return nil, firststartapp.ErrIntegrity
	}
	releaseApplication, err := installphase.NewReleaseApplicationAdapter(stack.application)
	if err != nil {
		_ = hostProbe.Close(context.WithoutCancel(ctx))
		return nil, firststartapp.ErrIntegrity
	}
	authority := &nativeReleaseAuthority{
		source: source, stack: stack, hostProbe: hostProbe,
		hostVerifier: hostApplication, releaseVerifier: releaseApplication,
	}
	runtimeCatalog, err := newNativeRuntimeCatalogLoader(authority)
	if err != nil {
		_ = hostProbe.Close(context.WithoutCancel(ctx))
		return nil, firststartapp.ErrIntegrity
	}
	authority.runtimeCatalog = runtimeCatalog
	failed = false
	return authority, nil
}

func (a *nativeReleaseAuthority) templates() firststartapp.VerifiedTemplateSource {
	if a == nil || a.stack.templates == nil {
		return nil
	}
	return a.stack.templates
}

func (a *nativeReleaseAuthority) verifier() *appreleaseverify.Application {
	if a == nil {
		return nil
	}
	return a.stack.application
}

func (a *nativeReleaseAuthority) hostVerification() *hostverifyapp.Application {
	if a == nil {
		return nil
	}
	return a.hostVerifier
}

func (a *nativeReleaseAuthority) releaseVerification() *installphase.ReleaseApplicationAdapter {
	if a == nil {
		return nil
	}
	return a.releaseVerifier
}

func (a *nativeReleaseAuthority) runtimeCatalogLoader() *nativeRuntimeCatalogLoader {
	if a == nil {
		return nil
	}
	return a.runtimeCatalog
}

func (a *nativeReleaseAuthority) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	cleanup := context.Background()
	if ctx != nil {
		cleanup = context.WithoutCancel(ctx)
	}
	a.closeOnce.Do(func() {
		var closeErrors []error
		if a.hostProbe != nil {
			if err := a.hostProbe.Close(cleanup); err != nil {
				closeErrors = append(closeErrors, errors.New("native host probe close failed"))
			}
		}
		if a.source != nil {
			if err := a.source.Close(); err != nil {
				closeErrors = append(closeErrors, errors.New("native release bundle close failed"))
			}
		}
		a.closeError = errors.Join(closeErrors...)
	})
	return a.closeError
}

var _ interface{ Close(context.Context) error } = (*nativeReleaseAuthority)(nil)
