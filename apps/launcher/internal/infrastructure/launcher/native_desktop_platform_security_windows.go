//go:build windows

package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/hostverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
)

func newNativeDesktopPlatformSecurity() (nativeDesktopPlatformSecurity, error) {
	encryption, err := hostverify.NewDesktopEncryptionAttestor()
	if err != nil {
		return nativeDesktopPlatformSecurity{}, err
	}
	signer := runtimeprovision.NewNativeDesktopWindowsSignerIdentityVerifier()
	return nativeDesktopPlatformSecurity{
		host:   runtimeprovision.DesktopHostProbeDependencies{WindowsEncryption: encryption},
		signer: signer, closers: []nativeRuntimeResourceCloser{encryption},
	}, nil
}
