package runtimecatalog

// SignedManifest binds canonical manifest bytes to one detached signature and declared key.
type SignedManifest struct {
	manifest     Manifest
	signingKeyID string
	signature    []byte
}

// NewSignedManifest validates the detached signature envelope without performing cryptography.
func NewSignedManifest(manifest Manifest, signingKeyID string, signature []byte) (SignedManifest, error) {
	if !manifest.Valid() || signingKeyID != manifest.signingKeyID || len(signature) == 0 || len(signature) > 16*1024 {
		return SignedManifest{}, ErrManifestIntegrity
	}
	return SignedManifest{
		manifest: manifest, signingKeyID: signingKeyID, signature: append([]byte(nil), signature...),
	}, nil
}

// Manifest returns immutable signed catalog authority.
func (s SignedManifest) Manifest() Manifest { return s.manifest }

// SigningKeyID returns the declared detached-signature key identity.
func (s SignedManifest) SigningKeyID() string { return s.signingKeyID }

// Signature returns a defensive copy of detached signature bytes.
func (s SignedManifest) Signature() []byte { return append([]byte(nil), s.signature...) }

// Valid reports whether the signature envelope remains bound to the manifest.
func (s SignedManifest) Valid() bool {
	return s.manifest.Valid() && s.signingKeyID == s.manifest.signingKeyID &&
		len(s.signature) > 0 && len(s.signature) <= 16*1024
}
