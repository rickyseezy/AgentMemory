// Package releaseverifyadapter contains capability-bearing release trust adapters.
package releaseverifyadapter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// Ed25519KeyIDVerifier verifies only ADR-016's explicit key-ID trust mode.
// It is deliberately not a Cosign, certificate-chain, Rekor, revocation, or
// trusted-time verifier; those decisions remain mandatory separate ports.
type Ed25519KeyIDVerifier struct {
	trustedKeys map[string]ed25519.PublicKey
}

var _ application.ManifestSignatureVerifier = (*Ed25519KeyIDVerifier)(nil)

// NewEd25519KeyIDVerifier copies a closed embedded trust-root set.
func NewEd25519KeyIDVerifier(
	trustedKeys map[string]ed25519.PublicKey,
) (*Ed25519KeyIDVerifier, error) {
	if len(trustedKeys) == 0 {
		return nil, errors.New("at least one Ed25519 release trust root is required")
	}
	copied := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for keyID, publicKey := range trustedKeys {
		if keyID == "" || len(keyID) > 128 || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("Ed25519 release trust root is invalid")
		}
		copied[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &Ed25519KeyIDVerifier{trustedKeys: copied}, nil
}

// VerifyManifestSignature checks the exact RFC 8785 canonical payload against
// the exact trust-root ID embedded in the signed launcher.
func (v *Ed25519KeyIDVerifier) VerifyManifestSignature(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if signed.TrustMode() != releaseinventory.SignatureTrustModeKeyID {
		return application.ErrSignatureModeUnsupported
	}
	publicKey, found := v.trustedKeys[signed.TrustRootID()]
	if !found {
		return application.ErrUntrustedSigner
	}
	if !ed25519.Verify(publicKey, signed.SignaturePayload(), signed.Signature()) {
		return fmt.Errorf("%w: Ed25519 verification failed", application.ErrSignatureInvalid)
	}
	return nil
}
