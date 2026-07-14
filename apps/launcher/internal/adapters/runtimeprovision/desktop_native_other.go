//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type unavailableDesktopNative struct{}

// NewNativeDesktopHostProbe fails closed where no certified native adapter exists.
func NewNativeDesktopHostProbe(_ DesktopHostProbeDependencies) (runtimeport.DesktopHostProbe, error) {
	return unavailableDesktopNative{}, nil
}

func (unavailableDesktopNative) ProbeDesktopHost(
	ctx context.Context,
	_ runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	if ctx == nil || ctx.Err() != nil {
		return runtimeport.DesktopHostEvidence{}, context.Canceled
	}
	return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
}

// NewNativeDesktopArtifactVerifier fails closed without native publisher APIs.
func NewNativeDesktopArtifactVerifier(
	_ DesktopArtifactVerifierDependencies,
) (runtimeport.DesktopArtifactVerifier, error) {
	return unavailableDesktopNative{}, nil
}

func (unavailableDesktopNative) VerifyDesktopArtifact(
	ctx context.Context,
	_ runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	if ctx == nil || ctx.Err() != nil {
		return runtimeport.DesktopArtifactEvidence{}, context.Canceled
	}
	return runtimeport.DesktopArtifactEvidence{}, ErrUnsupportedHost
}

// NewNativeDesktopInstalledApplicationProbe fails closed without native publisher APIs.
func NewNativeDesktopInstalledApplicationProbe(
	_ DesktopInstalledApplicationProbeDependencies,
) (runtimeport.DesktopInstalledApplicationProbe, error) {
	return unavailableDesktopNative{}, nil
}

func (unavailableDesktopNative) ProbeDesktopInstalledApplication(
	ctx context.Context,
	_ runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	if ctx == nil || ctx.Err() != nil {
		return runtimeport.DesktopInstalledApplicationEvidence{}, context.Canceled
	}
	return runtimeport.DesktopInstalledApplicationEvidence{}, ErrUnsupportedHost
}

// NewNativeDesktopRuntimeLauncher fails closed without a certified native launch API.
func NewNativeDesktopRuntimeLauncher() (runtimeport.DesktopRuntimeLauncher, error) {
	return unavailableDesktopNative{}, nil
}

func (unavailableDesktopNative) LaunchDesktopRuntime(
	ctx context.Context,
	_ runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	if ctx == nil || ctx.Err() != nil {
		return runtimeinstall.Hash{}, context.Canceled
	}
	return runtimeinstall.Hash{}, ErrUnsupportedHost
}

var (
	_ runtimeport.DesktopHostProbe                 = unavailableDesktopNative{}
	_ runtimeport.DesktopArtifactVerifier          = unavailableDesktopNative{}
	_ runtimeport.DesktopInstalledApplicationProbe = unavailableDesktopNative{}
	_ runtimeport.DesktopRuntimeLauncher           = unavailableDesktopNative{}
)
