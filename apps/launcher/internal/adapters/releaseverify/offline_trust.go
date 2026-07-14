package releaseverifyadapter

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const offlineTrustSchemaVersion uint16 = 1

// OfflineTrustPolicyInput supplies independently embedded trust authorities.
// It contains public verification material only; the adapter has no network,
// filesystem, command, or private-key capability.
type OfflineTrustPolicyInput struct {
	TrustDomain           string
	RevocationAuthorities map[string]ed25519.PublicKey
	TimeAuthorities       map[string]ed25519.PublicKey
	MaximumFutureSkew     time.Duration
}

// OfflineTrustPolicy is an immutable revocation/trusted-time authority set.
type OfflineTrustPolicy struct {
	trustDomain           string
	revocationAuthorities map[string]ed25519.PublicKey
	timeAuthorities       map[string]ed25519.PublicKey
	maximumFutureSkew     time.Duration
}

// NewOfflineTrustPolicy rejects permissive or unbounded time policy.
func NewOfflineTrustPolicy(input OfflineTrustPolicyInput) (OfflineTrustPolicy, error) {
	if !validSafeEvidenceText(input.TrustDomain, 128) || input.MaximumFutureSkew < 0 ||
		input.MaximumFutureSkew > 10*time.Minute {
		return OfflineTrustPolicy{}, errors.New("offline release trust policy is invalid")
	}
	revocationKeys, err := copyEd25519Keys(input.RevocationAuthorities)
	if err != nil {
		return OfflineTrustPolicy{}, errors.New("offline revocation authorities are invalid")
	}
	timeKeys, err := copyEd25519Keys(input.TimeAuthorities)
	if err != nil {
		return OfflineTrustPolicy{}, errors.New("offline trusted-time authorities are invalid")
	}
	return OfflineTrustPolicy{
		trustDomain: input.TrustDomain, revocationAuthorities: revocationKeys,
		timeAuthorities: timeKeys, maximumFutureSkew: input.MaximumFutureSkew,
	}, nil
}

// CanonicalOfflineTrustVerifier verifies signed, release-bound revocation and
// trusted-time evidence for both supported signature modes. Certificate,
// transparency-log, and signature verification remain a separate port.
type CanonicalOfflineTrustVerifier struct {
	clock  application.Clock
	policy OfflineTrustPolicy
}

var _ application.OfflineTrustEvidenceVerifier = (*CanonicalOfflineTrustVerifier)(nil)

// NewCanonicalOfflineTrustVerifier requires a trusted clock and closed policy.
func NewCanonicalOfflineTrustVerifier(
	clock application.Clock,
	policy OfflineTrustPolicy,
) (*CanonicalOfflineTrustVerifier, error) {
	if adapterNil(clock) || !policy.valid() {
		return nil, errors.New("offline release trust clock and policy are required")
	}
	return &CanonicalOfflineTrustVerifier{clock: clock, policy: policy}, nil
}

// VerifyOfflineTrustEvidence proves that neither the manifest root nor the
// evidence authorities are self-asserted and that policy time is fresh.
func (v *CanonicalOfflineTrustVerifier) VerifyOfflineTrustEvidence(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if signed.TrustMode() != releaseinventory.SignatureTrustModeKeyID &&
		signed.TrustMode() != releaseinventory.SignatureTrustModeCertificateTransparency {
		return application.ErrTrustEvidenceInvalid
	}
	manifest := signed.Manifest()
	if signed.TrustRootID() != manifest.TrustPolicy().TrustRootID() ||
		!releaseinventory.DigestBytes(signed.RevocationSet()).Equal(manifest.TrustPolicy().RevocationSetDigest()) {
		return application.ErrTrustEvidenceInvalid
	}
	now := v.clock.Now()
	if now.IsZero() {
		return application.ErrDependencyUnavailable
	}
	revocation, err := v.verifyRevocationSet(signed.RevocationSet(), now)
	if err != nil {
		return err
	}
	for _, rootID := range revocation.Payload.RevokedRootIDs {
		if rootID == signed.TrustRootID() {
			return application.ErrTrustRootRevoked
		}
	}
	if err := v.verifyTrustedTime(signed.TrustedTimeEvidence(), manifest, signed.TrustRootID(), now); err != nil {
		return err
	}
	return nil
}

type revocationEnvelope struct {
	Payload   revocationPayload      `json:"payload"`
	Signature qualificationSignature `json:"signature"`
}

type revocationPayload struct {
	ExpiresAt      int64    `json:"expiresAt"`
	GeneratedAt    int64    `json:"generatedAt"`
	RevokedRootIDs []string `json:"revokedRootIds"`
	SchemaVersion  uint16   `json:"schemaVersion"`
	Sequence       uint64   `json:"sequence"`
	TrustDomain    string   `json:"trustDomain"`
}

type trustedTimeEnvelope struct {
	Payload   trustedTimePayload     `json:"payload"`
	Signature qualificationSignature `json:"signature"`
}

type trustedTimePayload struct {
	ExpiresAt       int64  `json:"expiresAt"`
	IssuedAt        int64  `json:"issuedAt"`
	ManifestDigest  string `json:"manifestDigest"`
	ReleaseID       string `json:"releaseId"`
	ReleaseSequence uint64 `json:"releaseSequence"`
	SchemaVersion   uint16 `json:"schemaVersion"`
	TrustDomain     string `json:"trustDomain"`
	TrustRootID     string `json:"trustRootId"`
}

func (v *CanonicalOfflineTrustVerifier) verifyRevocationSet(
	raw []byte,
	now time.Time,
) (revocationEnvelope, error) {
	var envelope revocationEnvelope
	if err := decodeCanonicalJSON(raw, &envelope); err != nil {
		return revocationEnvelope{}, errors.Join(application.ErrTrustEvidenceInvalid, err)
	}
	payload := envelope.Payload
	nowMicroseconds := now.UTC().UnixMicro()
	maximumIssuedAt := now.Add(v.policy.maximumFutureSkew).UTC().UnixMicro()
	if payload.SchemaVersion != offlineTrustSchemaVersion || payload.TrustDomain != v.policy.trustDomain ||
		payload.Sequence == 0 || payload.GeneratedAt <= 0 || payload.GeneratedAt > maximumIssuedAt ||
		payload.ExpiresAt <= nowMicroseconds || payload.ExpiresAt > maximumSafeJSONInteger ||
		payload.ExpiresAt <= payload.GeneratedAt ||
		!exactUniqueStrings(payload.RevokedRootIDs, true) {
		return revocationEnvelope{}, application.ErrTrustEvidenceInvalid
	}
	for _, rootID := range payload.RevokedRootIDs {
		if !validSafeEvidenceText(rootID, 128) {
			return revocationEnvelope{}, application.ErrTrustEvidenceInvalid
		}
	}
	if err := verifyPolicySignature(envelope.Signature, payload, v.policy.revocationAuthorities); err != nil {
		return revocationEnvelope{}, application.ErrTrustEvidenceInvalid
	}
	return envelope, nil
}

func (v *CanonicalOfflineTrustVerifier) verifyTrustedTime(
	raw []byte,
	manifest releaseinventory.Manifest,
	trustRootID string,
	now time.Time,
) error {
	var envelope trustedTimeEnvelope
	if err := decodeCanonicalJSON(raw, &envelope); err != nil {
		return errors.Join(application.ErrTrustEvidenceInvalid, err)
	}
	payload := envelope.Payload
	issuedAt := time.UnixMicro(payload.IssuedAt).UTC()
	expiresAt := time.UnixMicro(payload.ExpiresAt).UTC()
	if payload.SchemaVersion != offlineTrustSchemaVersion || payload.TrustDomain != v.policy.trustDomain ||
		payload.ManifestDigest != manifest.Digest().Hex() || payload.ReleaseID != manifest.ReleaseID() ||
		payload.ReleaseSequence != manifest.Sequence() || payload.TrustRootID != trustRootID ||
		payload.IssuedAt <= 0 || payload.ExpiresAt <= payload.IssuedAt ||
		payload.ExpiresAt > maximumSafeJSONInteger || issuedAt.Before(manifest.BuildTimestamp()) ||
		issuedAt.After(manifest.ValidFrom()) || issuedAt.After(now.Add(v.policy.maximumFutureSkew)) ||
		expiresAt.Before(manifest.ValidUntil()) || !now.Before(expiresAt) {
		return application.ErrTrustEvidenceInvalid
	}
	if err := verifyPolicySignature(envelope.Signature, payload, v.policy.timeAuthorities); err != nil {
		return application.ErrTrustEvidenceInvalid
	}
	return nil
}

func verifyPolicySignature(
	signature qualificationSignature,
	payload any,
	keys map[string]ed25519.PublicKey,
) error {
	if signature.Algorithm != "ed25519" || !validSafeEvidenceText(signature.KeyID, 128) {
		return errEvidenceContent
	}
	key, exists := keys[signature.KeyID]
	if !exists {
		return errEvidenceContent
	}
	decoded, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != signature.Value ||
		len(decoded) != ed25519.SignatureSize {
		return errEvidenceContent
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil || !ed25519.Verify(key, canonicalPayload, decoded) {
		return errEvidenceContent
	}
	return nil
}

func (p OfflineTrustPolicy) valid() bool {
	return p.trustDomain != "" && len(p.revocationAuthorities) > 0 && len(p.timeAuthorities) > 0 &&
		p.maximumFutureSkew >= 0 && p.maximumFutureSkew <= 10*time.Minute
}
