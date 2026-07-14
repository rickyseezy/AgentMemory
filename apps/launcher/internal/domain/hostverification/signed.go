package hostverification

// SignedPlan binds canonical host authority to one detached signature and key.
type SignedPlan struct {
	plan         Plan
	signingKeyID string
	signature    []byte
}

// NewSignedPlan validates the envelope shape without claiming cryptographic verification.
func NewSignedPlan(plan Plan, signingKeyID string, signature []byte) (SignedPlan, error) {
	if !plan.Valid() || signingKeyID != plan.SigningKeyID() || len(signature) == 0 || len(signature) > 16*1024 {
		return SignedPlan{}, ErrIntegrity
	}
	return SignedPlan{plan: plan, signingKeyID: signingKeyID, signature: append([]byte(nil), signature...)}, nil
}

// Plan returns immutable signed host authority.
func (s SignedPlan) Plan() Plan { return s.plan }

// SigningKeyID returns the declared trust-root identity.
func (s SignedPlan) SigningKeyID() string { return s.signingKeyID }

// Signature returns a caller-owned detached-signature copy.
func (s SignedPlan) Signature() []byte { return append([]byte(nil), s.signature...) }

// SignaturePayload returns exact canonical bytes covered by the signature.
func (s SignedPlan) SignaturePayload() []byte { return s.plan.CanonicalBytes() }

// Valid reports whether the envelope remains structurally bound to its plan.
func (s SignedPlan) Valid() bool {
	return s.plan.Valid() && s.signingKeyID == s.plan.SigningKeyID() && len(s.signature) > 0 && len(s.signature) <= 16*1024
}
