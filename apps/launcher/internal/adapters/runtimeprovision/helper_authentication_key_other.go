//go:build !linux

package runtimeprovision

import (
	"context"
	"crypto/ed25519"
)

type rootPrivilegeReceiptPublicKeySource struct{}

type unavailablePrivilegeReceiptSigningKeySource struct{}

// NewRootPrivilegeReceiptPublicKeySource constructs the platform source. It
// remains fail-closed away from Linux.
func NewRootPrivilegeReceiptPublicKeySource() PrivilegeReceiptPublicKeySource {
	return rootPrivilegeReceiptPublicKeySource{}
}

func (rootPrivilegeReceiptPublicKeySource) LoadPrivilegeReceiptPublicKey(
	context.Context,
) (ed25519.PublicKey, error) {
	return nil, ErrUnsupportedHost
}

// NewRootPrivilegeReceiptSigner constructs a signer that remains unavailable
// away from the Linux root helper.
func NewRootPrivilegeReceiptSigner() (PrivilegeReceiptSigner, error) {
	return newProtectedPrivilegeReceiptSigner(unavailablePrivilegeReceiptSigningKeySource{})
}

func (unavailablePrivilegeReceiptSigningKeySource) LoadPrivilegeReceiptSigningKey(
	context.Context,
) (ed25519.PrivateKey, error) {
	return nil, ErrUnsupportedHost
}
