package hostverify

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

// Ed25519Verifier copies a closed embedded host-policy trust-root set.
type Ed25519Verifier struct{ trustedKeys map[string]ed25519.PublicKey }

// NewEd25519Verifier copies and validates a non-empty trust-root set.
func NewEd25519Verifier(trustedKeys map[string]ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(trustedKeys) == 0 {
		return nil, errors.New("at least one host-policy trust root is required")
	}
	copied := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for keyID, publicKey := range trustedKeys {
		if keyID == "" || len(keyID) > 128 || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("host-policy trust root is invalid")
		}
		copied[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &Ed25519Verifier{trustedKeys: copied}, nil
}

// VerifyHostPlanSignature authenticates exact canonical host-plan bytes.
func (v *Ed25519Verifier) VerifyHostPlanSignature(
	ctx context.Context,
	signed hostverification.SignedPlan,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !signed.Valid() {
		return hostverifyapp.ErrSignatureInvalid
	}
	publicKey, found := v.trustedKeys[signed.SigningKeyID()]
	if !found {
		return hostverifyapp.ErrUntrustedSigner
	}
	if !ed25519.Verify(publicKey, signed.SignaturePayload(), signed.Signature()) {
		return hostverifyapp.ErrSignatureInvalid
	}
	return nil
}

var _ hostverifyapp.PlanSignatureVerifier = (*Ed25519Verifier)(nil)
