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

const (
	qualificationSchemaVersion uint16 = 1
	maximumSafeJSONInteger            = int64(1<<53 - 1)
)

// QualificationTrustPolicyInput binds each signed policy snapshot to exactly
// one qualification authority key. Public keys and maps are defensively copied.
type QualificationTrustPolicyInput struct {
	PublicKeys                 map[string]ed25519.PublicKey
	LicensePolicySigners       map[releaseinventory.Digest]string
	VulnerabilityPolicySigners map[releaseinventory.Digest]string
}

// QualificationTrustPolicy is the immutable release qualification trust set.
type QualificationTrustPolicy struct {
	publicKeys                 map[string]ed25519.PublicKey
	licensePolicySigners       map[releaseinventory.Digest]string
	vulnerabilityPolicySigners map[releaseinventory.Digest]string
}

// NewQualificationTrustPolicy rejects incomplete keys, ambiguous snapshots,
// and snapshot bindings that name a missing signer.
func NewQualificationTrustPolicy(input QualificationTrustPolicyInput) (QualificationTrustPolicy, error) {
	keys, err := copyEd25519Keys(input.PublicKeys)
	if err != nil {
		return QualificationTrustPolicy{}, errors.New("qualification authority keys are invalid")
	}
	license, err := copyPolicySigners(input.LicensePolicySigners, keys)
	if err != nil {
		return QualificationTrustPolicy{}, errors.New("license qualification policy is invalid")
	}
	vulnerability, err := copyPolicySigners(input.VulnerabilityPolicySigners, keys)
	if err != nil {
		return QualificationTrustPolicy{}, errors.New("vulnerability qualification policy is invalid")
	}
	return QualificationTrustPolicy{
		publicKeys: keys, licensePolicySigners: license, vulnerabilityPolicySigners: vulnerability,
	}, nil
}

// SignedQualificationVerifier verifies canonical Ed25519-signed license and
// vulnerability evaluation envelopes from immutable local release resources.
type SignedQualificationVerifier struct {
	source ResourceContentSource
	clock  application.Clock
	policy QualificationTrustPolicy
}

var (
	_ application.LicenseVerifier       = (*SignedQualificationVerifier)(nil)
	_ application.VulnerabilityVerifier = (*SignedQualificationVerifier)(nil)
)

// NewSignedQualificationVerifier requires local content, trusted policy time,
// and independently configured qualification authorities.
func NewSignedQualificationVerifier(
	source ResourceContentSource,
	clock application.Clock,
	policy QualificationTrustPolicy,
) (*SignedQualificationVerifier, error) {
	if adapterNil(source) || adapterNil(clock) || !policy.valid() {
		return nil, errors.New("signed qualification source, clock, and trust policy are required")
	}
	return &SignedQualificationVerifier{source: source, clock: clock, policy: policy}, nil
}

// VerifyLicense requires an exact signed, passed evaluation for the manifest's
// immutable license-policy snapshot. License decisions never silently expire.
func (v *SignedQualificationVerifier) VerifyLicense(
	ctx context.Context,
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
) error {
	return v.verify(
		ctx,
		subject,
		evidence,
		releaseinventory.ResourceKindLicense,
		v.policy.licensePolicySigners,
		application.ErrLicenseDenied,
	)
}

// VerifyVulnerabilities requires an exact signed, passed and currently
// unexpired evaluation for the vulnerability-policy snapshot.
func (v *SignedQualificationVerifier) VerifyVulnerabilities(
	ctx context.Context,
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
) error {
	return v.verify(
		ctx,
		subject,
		evidence,
		releaseinventory.ResourceKindVulnerabilityReport,
		v.policy.vulnerabilityPolicySigners,
		application.ErrVulnerabilityDenied,
	)
}

type qualificationEnvelope struct {
	Payload   qualificationPayload   `json:"payload"`
	Signature qualificationSignature `json:"signature"`
}

type qualificationPayload struct {
	EvidenceResourceID   string `json:"evidenceResourceId"`
	EvaluatedAt          int64  `json:"evaluatedAt"`
	ExpiresAt            int64  `json:"expiresAt"`
	PolicySnapshotDigest string `json:"policySnapshotDigest"`
	QualificationResult  string `json:"qualificationResult"`
	SchemaVersion        uint16 `json:"schemaVersion"`
	SubjectDigest        string `json:"subjectDigest"`
	SubjectResourceID    string `json:"subjectResourceId"`
}

type qualificationSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

func (v *SignedQualificationVerifier) verify(
	ctx context.Context,
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
	kind releaseinventory.ResourceKind,
	policySigners map[releaseinventory.Digest]string,
	sentinel error,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if subject.Kind().IsEvidence() || evidence.Kind() != kind ||
		evidence.SubjectResourceID() != subject.ID() ||
		!evidence.SubjectDigest().Equal(subject.Digest()) ||
		evidence.QualificationResult() != releaseinventory.QualificationResultPassed ||
		evidence.PolicySnapshotDigest().IsZero() {
		return sentinel
	}
	raw, err := readEvidence(ctx, v.source, evidence)
	if err != nil {
		return evidencePortError(sentinel, err)
	}
	var envelope qualificationEnvelope
	if err := decodeCanonicalJSON(raw, &envelope); err != nil {
		return evidencePortError(sentinel, err)
	}
	expectedSigner, exists := policySigners[evidence.PolicySnapshotDigest()]
	if !exists || expectedSigner != envelope.Signature.KeyID || envelope.Signature.Algorithm != "ed25519" {
		return sentinel
	}
	if !qualificationPayloadBinds(envelope.Payload, subject, evidence, kind, v.clock.Now()) {
		return sentinel
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature.Value)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != envelope.Signature.Value ||
		len(signature) != ed25519.SignatureSize {
		return sentinel
	}
	payload, err := json.Marshal(envelope.Payload)
	if err != nil || !ed25519.Verify(v.policy.publicKeys[expectedSigner], payload, signature) {
		return sentinel
	}
	return nil
}

func qualificationPayloadBinds(
	payload qualificationPayload,
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
	kind releaseinventory.ResourceKind,
	now time.Time,
) bool {
	if payload.SchemaVersion != qualificationSchemaVersion ||
		payload.EvidenceResourceID != evidence.ID() || payload.SubjectResourceID != subject.ID() ||
		payload.SubjectDigest != subject.Digest().Hex() ||
		payload.PolicySnapshotDigest != evidence.PolicySnapshotDigest().Hex() ||
		payload.QualificationResult != string(releaseinventory.QualificationResultPassed) ||
		payload.EvaluatedAt <= 0 || payload.EvaluatedAt > maximumSafeJSONInteger || now.IsZero() {
		return false
	}
	nowMicroseconds := now.UTC().UnixMicro()
	if payload.EvaluatedAt > nowMicroseconds {
		return false
	}
	if kind == releaseinventory.ResourceKindLicense {
		return payload.ExpiresAt == 0 && evidence.QualificationExpiresAt().IsZero()
	}
	expiry := evidence.QualificationExpiresAt()
	return !expiry.IsZero() && payload.ExpiresAt == expiry.UnixMicro() &&
		payload.ExpiresAt > payload.EvaluatedAt && nowMicroseconds < payload.ExpiresAt &&
		payload.ExpiresAt <= maximumSafeJSONInteger
}

func copyEd25519Keys(input map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	if len(input) == 0 || len(input) > 64 {
		return nil, errEvidenceContent
	}
	result := make(map[string]ed25519.PublicKey, len(input))
	for keyID, key := range input {
		if !validSafeEvidenceText(keyID, 128) || len(key) != ed25519.PublicKeySize {
			return nil, errEvidenceContent
		}
		result[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return result, nil
}

func copyPolicySigners(
	input map[releaseinventory.Digest]string,
	keys map[string]ed25519.PublicKey,
) (map[releaseinventory.Digest]string, error) {
	if len(input) == 0 || len(input) > 256 {
		return nil, errEvidenceContent
	}
	result := make(map[releaseinventory.Digest]string, len(input))
	for digest, keyID := range input {
		if digest.IsZero() || len(keys[keyID]) != ed25519.PublicKeySize {
			return nil, errEvidenceContent
		}
		result[digest] = keyID
	}
	return result, nil
}

func (p QualificationTrustPolicy) valid() bool {
	return len(p.publicKeys) > 0 && len(p.licensePolicySigners) > 0 &&
		len(p.vulnerabilityPolicySigners) > 0
}
