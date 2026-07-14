package runtimeprovision

import (
	"context"
	"crypto/ed25519"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// Ed25519PrivilegeReceiptAuthenticator verifies receipts from one exact
// release-authorized Linux privilege helper. The helper executable digest and
// receipt public key are independent trust bindings.
type Ed25519PrivilegeReceiptAuthenticator struct {
	key    ed25519.PublicKey
	helper runtimeinstall.Hash
}

// NewEd25519PrivilegeReceiptAuthenticator copies immutable public trust.
func NewEd25519PrivilegeReceiptAuthenticator(
	key ed25519.PublicKey,
	helper runtimeinstall.Hash,
) (*Ed25519PrivilegeReceiptAuthenticator, error) {
	if len(key) != ed25519.PublicKeySize || helper.IsZero() {
		return nil, ErrProvisionIntegrity
	}
	return &Ed25519PrivilegeReceiptAuthenticator{
		key: append(ed25519.PublicKey(nil), key...), helper: helper,
	}, nil
}

// VerifyPrivilegeReceipt authenticates the signature only after rechecking
// the exact helper executable binding carried by the receipt.
func (a *Ed25519PrivilegeReceiptAuthenticator) VerifyPrivilegeReceipt(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	receipt runtimeport.PrivilegeReceipt,
) error {
	if a == nil || ctx == nil || len(a.key) != ed25519.PublicKeySize || a.helper.IsZero() ||
		request.Digest().IsZero() || receipt.Digest().IsZero() || receipt.HelperDigest() != a.helper ||
		!receipt.Matches(request, request.IssuedAt()) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	payload := receipt.AuthenticationPayload()
	signature := receipt.Signature()
	if len(payload) == 0 || len(signature) != ed25519.SignatureSize || !ed25519.Verify(a.key, payload, signature) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

// Ed25519DesktopMutationAuthenticator verifies exact native-helper mutation
// receipt statements against independently embedded release trust.
type Ed25519DesktopMutationAuthenticator struct {
	key ed25519.PublicKey
}

// NewEd25519DesktopMutationAuthenticator copies immutable public trust.
func NewEd25519DesktopMutationAuthenticator(
	key ed25519.PublicKey,
) (*Ed25519DesktopMutationAuthenticator, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrProvisionIntegrity
	}
	return &Ed25519DesktopMutationAuthenticator{key: append(ed25519.PublicKey(nil), key...)}, nil
}

// VerifyDesktopMutation rejects substitution, cancellation, malformed
// statements, and signatures from any key outside the signed release.
func (a *Ed25519DesktopMutationAuthenticator) VerifyDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	receipt runtimeport.DesktopMutationReceipt,
) error {
	if a == nil || ctx == nil || len(a.key) != ed25519.PublicKeySize || request.Digest().IsZero() ||
		receipt.Digest().IsZero() || !receipt.BoundTo(request) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	payload := receipt.AuthenticationPayload()
	signature := receipt.Signature()
	if len(payload) == 0 || len(signature) != ed25519.SignatureSize || !ed25519.Verify(a.key, payload, signature) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

var (
	_ runtimeport.ReceiptAuthenticator         = (*Ed25519PrivilegeReceiptAuthenticator)(nil)
	_ runtimeport.DesktopMutationAuthenticator = (*Ed25519DesktopMutationAuthenticator)(nil)
)
