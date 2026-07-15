package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type nativeDesktopWindowsSigner interface {
	runtimeport.DesktopWindowsSignerIdentityVerifier
	runtimeport.DesktopWindowsApplicationSignerIdentityVerifier
}

type nativeRuntimeResourceCloser interface {
	Close(context.Context) error
}

type nativeDesktopPlatformSecurity struct {
	host    runtimeprovision.DesktopHostProbeDependencies
	signer  nativeDesktopWindowsSigner
	closers []nativeRuntimeResourceCloser
}
