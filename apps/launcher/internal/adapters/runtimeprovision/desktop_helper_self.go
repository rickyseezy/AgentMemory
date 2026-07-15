package runtimeprovision

import (
	"context"
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// NativeDesktopHelperExecutableVerifier binds helper bytes and native signer
// identity to independently embedded release trust.
type NativeDesktopHelperExecutableVerifier struct {
	certificates map[string]releaseinventory.Digest
}

// NewNativeDesktopHelperExecutableVerifier copies exact resource-to-leaf-
// certificate bindings. The signed catalog cannot supply this trust.
func NewNativeDesktopHelperExecutableVerifier(
	certificates map[string]releaseinventory.Digest,
) (*NativeDesktopHelperExecutableVerifier, error) {
	if len(certificates) == 0 {
		return nil, errors.New("native desktop helper certificate trust is required")
	}
	copyCertificates := make(map[string]releaseinventory.Digest, len(certificates))
	for resourceID, digest := range certificates {
		if resourceID == "" || digest.IsZero() {
			return nil, errors.New("native desktop helper certificate binding is invalid")
		}
		copyCertificates[resourceID] = digest
	}
	return &NativeDesktopHelperExecutableVerifier{certificates: copyCertificates}, nil
}

//lint:ignore U1000 platform-specific native verifier implementations call this method
func (v *NativeDesktopHelperExecutableVerifier) expectedCertificate(
	resource releaseinventory.Resource,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	if v == nil || len(v.certificates) == 0 || !authority.Valid() ||
		resource.ID() == "" || resource.Kind() != releaseinventory.ResourceKindHelper ||
		resource.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
		resource.MediaType() != releaseinventory.MediaTypeNativeExecutable || resource.Platform().IsAny() ||
		resource.Platform().OS() != authority.Platform().String() ||
		resource.Platform().Architecture() != authority.Architecture().String() ||
		resource.Digest().IsZero() || resource.Size() == 0 ||
		resource.NativePublisherIdentity() == "" || resource.NativePublisherPolicyID() == "" {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	certificate := v.certificates[resource.ID()]
	if certificate.IsZero() {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return runtimeinstall.Hash(certificate), nil
}

// VerifyDesktopHelperSelf is implemented by platform files so each helper
// uses native code-signing policy and a retained no-substitution file object.
func (v *NativeDesktopHelperExecutableVerifier) VerifyDesktopHelperSelf(
	ctx context.Context,
	resource releaseinventory.Resource,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return v.verifyDesktopHelperSelf(ctx, resource, authority)
}
