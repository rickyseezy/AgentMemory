package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"reflect"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// PrivilegeReceiptSigner is available only to the root helper and emits one
// domain-valid receipt authenticated by protected per-machine key material.
type PrivilegeReceiptSigner interface {
	SignPrivilegeReceipt(
		context.Context,
		runtimeport.PrivilegeReceiptInput,
	) (runtimeport.PrivilegeReceipt, error)
}

type privilegeReceiptSigningKeySource interface {
	LoadPrivilegeReceiptSigningKey(context.Context) (ed25519.PrivateKey, error)
}

type protectedPrivilegeReceiptSigner struct {
	source privilegeReceiptSigningKeySource
}

func newProtectedPrivilegeReceiptSigner(
	source privilegeReceiptSigningKeySource,
) (*protectedPrivilegeReceiptSigner, error) {
	if nilPrivilegeReceiptSigningKeySource(source) {
		return nil, ErrProvisionIntegrity
	}
	return &protectedPrivilegeReceiptSigner{source: source}, nil
}

func (s *protectedPrivilegeReceiptSigner) SignPrivilegeReceipt(
	ctx context.Context,
	input runtimeport.PrivilegeReceiptInput,
) (runtimeport.PrivilegeReceipt, error) {
	if s == nil || ctx == nil || nilPrivilegeReceiptSigningKeySource(s.source) || len(input.Signature) != 0 {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.PrivilegeReceipt{}, err
	}
	key, err := s.source.LoadPrivilegeReceiptSigningKey(ctx)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		if contextError := ctx.Err(); contextError != nil {
			return runtimeport.PrivilegeReceipt{}, contextError
		}
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	defer clear(key)
	input.Signature = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	unsigned, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	input.Signature = ed25519.Sign(key, unsigned.AuthenticationPayload())
	signed, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	return signed, nil
}

func nilPrivilegeReceiptSigningKeySource(source privilegeReceiptSigningKeySource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() { //nolint:exhaustive // Non-nilable implementations are valid sources.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// PrivilegeReceiptPublicKeySource loads the root-owned per-machine public key
// only after the signed helper has produced a receipt. It grants no signing
// capability to the unprivileged launcher.
type PrivilegeReceiptPublicKeySource interface {
	LoadPrivilegeReceiptPublicKey(context.Context) (ed25519.PublicKey, error)
}

// ProtectedEd25519PrivilegeReceiptAuthenticator authenticates the immutable
// helper digest with a per-machine key whose private half never leaves the
// root-owned helper state directory.
type ProtectedEd25519PrivilegeReceiptAuthenticator struct {
	source PrivilegeReceiptPublicKeySource
	helper runtimeinstall.Hash
}

// NewProtectedEd25519PrivilegeReceiptAuthenticator constructs the dynamic
// local-key verifier without loading or retaining caller-owned key bytes.
func NewProtectedEd25519PrivilegeReceiptAuthenticator(
	source PrivilegeReceiptPublicKeySource,
	helper runtimeinstall.Hash,
) (*ProtectedEd25519PrivilegeReceiptAuthenticator, error) {
	if nilPrivilegeReceiptKeySource(source) || helper.IsZero() {
		return nil, ErrProvisionIntegrity
	}
	return &ProtectedEd25519PrivilegeReceiptAuthenticator{source: source, helper: helper}, nil
}

// VerifyPrivilegeReceipt reloads protected public state for every receipt,
// rejects helper/request substitution, then authenticates the exact payload.
func (a *ProtectedEd25519PrivilegeReceiptAuthenticator) VerifyPrivilegeReceipt(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	receipt runtimeport.PrivilegeReceipt,
) error {
	if a == nil || ctx == nil || nilPrivilegeReceiptKeySource(a.source) || a.helper.IsZero() ||
		request.Digest().IsZero() || receipt.Digest().IsZero() || receipt.HelperDigest() != a.helper ||
		!receipt.Matches(request, request.IssuedAt()) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := a.source.LoadPrivilegeReceiptPublicKey(ctx)
	if err != nil || len(key) != ed25519.PublicKeySize || ctx.Err() != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return runtimeport.ErrPrivilegeIntegrity
	}
	payload := receipt.AuthenticationPayload()
	signature := receipt.Signature()
	if len(payload) == 0 || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, payload, signature) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

func nilPrivilegeReceiptKeySource(source PrivilegeReceiptPublicKeySource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() { //nolint:exhaustive // Non-nilable implementations are valid sources.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

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
	_ runtimeport.ReceiptAuthenticator         = (*ProtectedEd25519PrivilegeReceiptAuthenticator)(nil)
	_ runtimeport.ReceiptAuthenticator         = (*Ed25519PrivilegeReceiptAuthenticator)(nil)
	_ runtimeport.DesktopMutationAuthenticator = (*Ed25519DesktopMutationAuthenticator)(nil)
)
