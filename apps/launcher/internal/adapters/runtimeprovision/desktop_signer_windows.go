//go:build windows

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// NativeDesktopWindowsSignerIdentityVerifier extracts the exact primary
// Authenticode signer for both the downloaded installer and installed app.
type NativeDesktopWindowsSignerIdentityVerifier struct{}

// NewNativeDesktopWindowsSignerIdentityVerifier constructs the concrete
// Windows signer dependency required by both desktop verification adapters.
func NewNativeDesktopWindowsSignerIdentityVerifier() *NativeDesktopWindowsSignerIdentityVerifier {
	return &NativeDesktopWindowsSignerIdentityVerifier{}
}

func (*NativeDesktopWindowsSignerIdentityVerifier) VerifyWindowsDesktopSigner(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return verifyDesktopWindowsSigner(ctx, authority, authority.ArtifactPath())
}

func (*NativeDesktopWindowsSignerIdentityVerifier) VerifyWindowsDesktopApplicationSigner(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return verifyDesktopWindowsSigner(ctx, authority, authority.ApplicationExecutable())
}

func verifyDesktopWindowsSigner(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
	path string,
) (runtimeinstall.Hash, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.Platform() != runtimeinstall.PlatformWindows ||
		authority.Publisher().Kind() != runtimeport.DesktopPublisherAuthenticode || path == "" {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	certificate, err := windowssecurity.AuthenticodeLeafCertificateSHA256(ctx, path)
	observed := runtimeinstall.Hash(certificate)
	if err != nil || observed != authority.Publisher().CertificateSHA256() || ctx.Err() != nil {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	return observed, nil
}
