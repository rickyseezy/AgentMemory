//go:build windows

package process

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type nativeWindowsSignerIdentityVerifier struct{}

// NewNativeWindowsSignerIdentityVerifier constructs the exact Authenticode
// leaf-certificate binding used after WinVerifyTrust chain validation.
func NewNativeWindowsSignerIdentityVerifier() WindowsSignerIdentityVerifier {
	return nativeWindowsSignerIdentityVerifier{}
}

func (nativeWindowsSignerIdentityVerifier) VerifyWindowsSignerIdentity(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != "windows" ||
		authority.PublisherPolicyID() != windowsPublisherPolicy || evidence.retainedHandle == 0 ||
		evidence.CanonicalID != authority.CanonicalID() || evidence.Digest != authority.SHA256() ||
		evidence.OwnerIdentity != authority.OwnerIdentity() ||
		evidence.ReleaseManifestDigest != authority.ReleaseManifestDigest() ||
		evidence.RuntimePlanDigest != authority.RuntimePlanDigest() || evidence.Role != authority.Role() {
		return argvprocess.ErrInvalidInvocation
	}
	certificate, err := windowssecurity.AuthenticodeLeafCertificateSHA256(ctx, authority.CanonicalPath())
	if err != nil || certificate != authority.PublisherTrustDigest() || ctx.Err() != nil {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}
