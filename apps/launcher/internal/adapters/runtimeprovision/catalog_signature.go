package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// CatalogSignatureVerifier authenticates exact canonical runtime-catalog
// manifest bytes against an independently embedded key-ID trust domain.
type CatalogSignatureVerifier struct {
	keys map[string]ed25519.PublicKey
}

// NewCatalogSignatureVerifier copies a closed non-empty public-key set.
func NewCatalogSignatureVerifier(keys map[string]ed25519.PublicKey) (*CatalogSignatureVerifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("runtime catalog signing keys are required")
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if keyID == "" || len(keyID) > 128 || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("runtime catalog signing key is invalid")
		}
		copied[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return &CatalogSignatureVerifier{keys: copied}, nil
}

// VerifyManifestSignature rejects unknown keys and any detached-signature or
// canonical-manifest substitution.
func (v *CatalogSignatureVerifier) VerifyManifestSignature(
	ctx context.Context,
	signed runtimecatalog.SignedManifest,
) error {
	if v == nil || ctx == nil || !signed.Valid() {
		return runtimecatalogapp.ErrSignatureInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, found := v.keys[signed.SigningKeyID()]
	if !found {
		return runtimecatalogapp.ErrUntrustedSigner
	}
	if !ed25519.Verify(key, signed.Manifest().CanonicalBytes(), signed.Signature()) {
		return runtimecatalogapp.ErrSignatureInvalid
	}
	return nil
}

var _ runtimecatalogapp.ManifestSignatureVerifier = (*CatalogSignatureVerifier)(nil)
