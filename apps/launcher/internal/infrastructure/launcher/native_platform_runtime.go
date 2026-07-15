package launcher

import (
	"context"
	"errors"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type nativeDesktopAuthoritySet struct {
	resolver  runtimeport.DesktopAuthorityResolver
	authority runtimeport.DesktopAuthority
}

type nativeDesktopArtifactSet struct {
	acquirer runtimeport.DesktopArtifactAcquirer
	verifier runtimeport.DesktopArtifactVerifier
}

type nativeDesktopHelperSet struct {
	authority runtimeport.DesktopHelperAuthorityResolver
	publisher runtimeport.DesktopHelperPublisherVerifier
}

type nativeDesktopAuthorityBuilder func(
	context.Context,
	nativeVerifiedRuntimeExecution,
	*nativeReleaseAuthority,
) (nativeDesktopAuthoritySet, error)

type nativeDesktopArtifactBuilder func(
	nativeVerifiedRuntimeExecution,
	*artifactapp.Application,
	*nativeComposition,
	nativeDesktopPlatformSecurity,
) (nativeDesktopArtifactSet, error)

type nativeDesktopHelperBuilder func(
	*nativeReleaseAuthority,
	nativeVerifiedRuntimeExecution,
) (nativeDesktopHelperSet, error)

type nativePlatformRuntimeFactory struct {
	composition      *nativeComposition
	release          *nativeReleaseAuthority
	artifacts        *artifactapp.Application
	desktopAuthority nativeDesktopAuthorityBuilder
	desktopArtifacts nativeDesktopArtifactBuilder
	desktopHelpers   nativeDesktopHelperBuilder
}

func newNativePlatformRuntimeFactory(
	composition *nativeComposition,
	release *nativeReleaseAuthority,
	artifacts *artifactapp.Application,
) (*nativePlatformRuntimeFactory, error) {
	if composition == nil || composition.runtimeState == nil || composition.consentBroker == nil ||
		composition.consentRepository == nil || nilAny(composition.replayJournals) ||
		composition.artifactStore == nil || release == nil || release.verifier() == nil ||
		len(release.runtimeHelperAuthenticationKey()) == 0 || nilAny(artifacts) {
		return nil, errNativeInstallerIntegrity
	}
	return &nativePlatformRuntimeFactory{
		composition: composition, release: release, artifacts: artifacts,
		desktopAuthority: buildNativeDesktopAuthority,
		desktopArtifacts: buildNativeDesktopArtifacts,
		desktopHelpers:   buildNativeDesktopHelpers,
	}, nil
}

func (f *nativePlatformRuntimeFactory) BuildRuntimeApplication(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	if f == nil || ctx == nil || f.composition == nil || f.release == nil || nilAny(f.artifacts) ||
		verified.authority.BindingDigest().IsZero() || !verified.catalog.Manifest().Digest().Equal(verified.manifestDigest) {
		return nil, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return f.buildDesktopRuntimeApplication(ctx, verified)
	case "linux":
		return f.buildLinuxRuntimeApplication(ctx, verified)
	default:
		return nil, errors.New("native runtime platform is unsupported")
	}
}

var _ nativePlatformRuntimeApplicationFactory = (*nativePlatformRuntimeFactory)(nil)
