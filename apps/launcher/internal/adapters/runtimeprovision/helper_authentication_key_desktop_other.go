//go:build !darwin && !windows

package runtimeprovision

import (
	"context"
	"crypto/ed25519"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type unavailableDesktopMutationPublicKeySource struct{}
type unavailableDesktopMutationSigningKeySource struct{}

func NewProtectedDesktopMutationReceiptPublicKeySource(
	string,
) (DesktopMutationReceiptPublicKeySource, error) {
	return unavailableDesktopMutationPublicKeySource{}, nil
}

func (unavailableDesktopMutationPublicKeySource) LoadDesktopMutationPublicKey(
	context.Context,
	runtimeinstall.Hash,
) (ed25519.PublicKey, error) {
	return nil, ErrUnsupportedHost
}

func NewNativeDesktopMutationReceiptSigner() (DesktopMutationReceiptSigner, error) {
	return NewProtectedDesktopMutationReceiptSigner(unavailableDesktopMutationSigningKeySource{})
}

func (unavailableDesktopMutationSigningKeySource) LoadDesktopMutationSigningKey(
	context.Context,
) (ed25519.PrivateKey, error) {
	return nil, ErrUnsupportedHost
}
