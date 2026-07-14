//go:build linux

package process

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type nativePublisherVerifier struct{ receipt LinuxPackageReceiptVerifier }

// NewNativePublisherVerifier requires aggregate-authenticated package receipt
// evidence; a root-owned digest by itself is intentionally insufficient.
func NewNativePublisherVerifier(dependencies NativePublisherDependencies) (PublisherVerifier, error) {
	if nilTrustDependency(dependencies.LinuxPackageReceipt) {
		return nil, errors.New("authenticated Linux package receipt verifier is required")
	}
	return nativePublisherVerifier{receipt: dependencies.LinuxPackageReceipt}, nil
}

func (v nativePublisherVerifier) VerifyExecutablePublisher(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.OwnerIdentity() != "uid:0" || authority.PublisherPolicyID() != linuxPublisherPolicy ||
		evidence.Digest != authority.SHA256() || nilTrustDependency(v.receipt) {
		return argvprocess.ErrInvalidInvocation
	}
	if err := v.receipt.VerifyLinuxPackageReceipt(ctx, authority, evidence); err != nil {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}
