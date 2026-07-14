package releaseverifyadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestCanonicalOfflineTrustVerifierAcceptsSignedFreshEvidence(t *testing.T) {
	t.Parallel()

	fixture := newOfflineTrustFixture(t, nil, nil)
	if err := fixture.verifier.VerifyOfflineTrustEvidence(context.Background(), fixture.signed); err != nil {
		t.Fatalf("VerifyOfflineTrustEvidence() error = %v", err)
	}
}

func TestCanonicalOfflineTrustVerifierAcceptsCertificateTransparencyModeEvidence(t *testing.T) {
	t.Parallel()

	fixture := newOfflineTrustFixture(t, nil, nil)
	signed := offlineSignedWithRevocationMode(
		t,
		fixture,
		fixture.revocationRaw,
		nil,
		releaseinventory.SignatureTrustModeCertificateTransparency,
	)
	if err := fixture.verifier.VerifyOfflineTrustEvidence(context.Background(), signed); err != nil {
		t.Fatalf("VerifyOfflineTrustEvidence() CT error = %v", err)
	}
}

func TestCanonicalOfflineTrustVerifierRejectsRevocationTamperAndStaleTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		mutateRevocation func(*revocationPayload)
		mutateTime       func(*trustedTimePayload)
		want             error
	}{
		{
			name:             "revoked root",
			mutateRevocation: func(payload *revocationPayload) { payload.RevokedRootIDs = []string{"root-2026"} },
			want:             application.ErrTrustRootRevoked,
		},
		{
			name:             "expired revocations",
			mutateRevocation: func(payload *revocationPayload) { payload.ExpiresAt = offlineFixtureNow.UnixMicro() },
			want:             application.ErrTrustEvidenceInvalid,
		},
		{
			name: "wrong manifest digest",
			mutateTime: func(payload *trustedTimePayload) {
				payload.ManifestDigest = releaseinventory.DigestBytes([]byte("wrong")).Hex()
			},
			want: application.ErrTrustEvidenceInvalid,
		},
		{
			name:       "expired trusted time",
			mutateTime: func(payload *trustedTimePayload) { payload.ExpiresAt = offlineFixtureNow.UnixMicro() },
			want:       application.ErrTrustEvidenceInvalid,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newOfflineTrustFixture(t, test.mutateRevocation, test.mutateTime)
			if err := fixture.verifier.VerifyOfflineTrustEvidence(context.Background(), fixture.signed); !errors.Is(err, test.want) {
				t.Fatalf("VerifyOfflineTrustEvidence() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCanonicalOfflineTrustVerifierFailsClosedForUnsupportedModeNilContextAndBadSignature(t *testing.T) {
	t.Parallel()

	fixture := newOfflineTrustFixture(t, nil, nil)
	//lint:ignore SA1012 Deliberate nil-context attack proves offline trust verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := fixture.verifier.VerifyOfflineTrustEvidence(nil, fixture.signed); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}

	ctManifest := adapterManifest(t, releaseinventory.SignatureTrustModeCertificateTransparency)
	ctSigned := adapterSignedManifest(
		t,
		ctManifest,
		releaseinventory.SignatureTrustModeCertificateTransparency,
		"root-2026",
		[]byte("certificate signature"),
	)
	if err := fixture.verifier.VerifyOfflineTrustEvidence(context.Background(), ctSigned); !errors.Is(err, application.ErrTrustEvidenceInvalid) {
		t.Fatalf("CT mode error = %v, want ErrTrustEvidenceInvalid", err)
	}

	var revocation revocationEnvelope
	if err := json.Unmarshal(fixture.signed.RevocationSet(), &revocation); err != nil {
		t.Fatal(err)
	}
	revocation.Signature.Value = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x4a}, ed25519.SignatureSize))
	badRaw := mustJSON(t, revocation)
	bad := offlineSignedWithRevocation(t, fixture, badRaw, nil)
	if err := fixture.verifier.VerifyOfflineTrustEvidence(context.Background(), bad); !errors.Is(err, application.ErrTrustEvidenceInvalid) {
		t.Fatalf("bad signature error = %v, want ErrTrustEvidenceInvalid", err)
	}
}

func TestOfflineTrustPolicyRejectsInvalidAuthorityAndClockPolicy(t *testing.T) {
	t.Parallel()

	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	valid := OfflineTrustPolicyInput{
		TrustDomain: "agentmemory.release", RevocationAuthorities: map[string]ed25519.PublicKey{"revocation": publicKey},
		TimeAuthorities: map[string]ed25519.PublicKey{"time": publicKey}, MaximumFutureSkew: time.Minute,
	}
	tests := []OfflineTrustPolicyInput{
		{},
		{TrustDomain: "bad domain", RevocationAuthorities: valid.RevocationAuthorities, TimeAuthorities: valid.TimeAuthorities},
		{TrustDomain: valid.TrustDomain, RevocationAuthorities: nil, TimeAuthorities: valid.TimeAuthorities},
		{TrustDomain: valid.TrustDomain, RevocationAuthorities: valid.RevocationAuthorities, TimeAuthorities: nil},
		{TrustDomain: valid.TrustDomain, RevocationAuthorities: valid.RevocationAuthorities, TimeAuthorities: valid.TimeAuthorities, MaximumFutureSkew: 11 * time.Minute},
	}
	for _, input := range tests {
		if _, err := NewOfflineTrustPolicy(input); err == nil {
			t.Fatal("NewOfflineTrustPolicy() accepted invalid input")
		}
	}
	policy, err := NewOfflineTrustPolicy(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCanonicalOfflineTrustVerifier(nil, policy); err == nil {
		t.Fatal("NewCanonicalOfflineTrustVerifier() accepted nil clock")
	}
}

var offlineFixtureNow = time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)

type offlineTrustFixture struct {
	revocationPrivate ed25519.PrivateKey
	revocationRaw     []byte
	timePrivate       ed25519.PrivateKey
	verifier          *CanonicalOfflineTrustVerifier
	signed            releaseinventory.SignedManifest
}

func newOfflineTrustFixture(
	t *testing.T,
	mutateRevocation func(*revocationPayload),
	mutateTime func(*trustedTimePayload),
) offlineTrustFixture {
	t.Helper()
	revocationPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	timePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	policy, err := NewOfflineTrustPolicy(OfflineTrustPolicyInput{
		TrustDomain: "agentmemory.release",
		RevocationAuthorities: map[string]ed25519.PublicKey{
			"revocation": revocationPrivate.Public().(ed25519.PublicKey),
		},
		TimeAuthorities: map[string]ed25519.PublicKey{
			"time": timePrivate.Public().(ed25519.PublicKey),
		},
		MaximumFutureSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCanonicalOfflineTrustVerifier(fixedClock{now: offlineFixtureNow}, policy)
	if err != nil {
		t.Fatal(err)
	}
	revocationPayload := revocationPayload{
		ExpiresAt:   offlineFixtureNow.Add(48 * time.Hour).UnixMicro(),
		GeneratedAt: offlineFixtureNow.Add(-time.Hour).UnixMicro(), RevokedRootIDs: []string{},
		SchemaVersion: 1, Sequence: 7, TrustDomain: "agentmemory.release",
	}
	if mutateRevocation != nil {
		mutateRevocation(&revocationPayload)
	}
	revocationRaw := signedOfflineEnvelope(t, revocationPayload, revocationPrivate, "revocation", func(signature qualificationSignature) any {
		return revocationEnvelope{Payload: revocationPayload, Signature: signature}
	})
	fixture := offlineTrustFixture{
		revocationPrivate: revocationPrivate, revocationRaw: revocationRaw,
		timePrivate: timePrivate, verifier: verifier,
	}
	fixture.signed = offlineSignedWithRevocation(t, fixture, revocationRaw, mutateTime)
	return fixture
}

func offlineSignedWithRevocation(
	t *testing.T,
	fixture offlineTrustFixture,
	revocationRaw []byte,
	mutateTime func(*trustedTimePayload),
) releaseinventory.SignedManifest {
	return offlineSignedWithRevocationMode(
		t,
		fixture,
		revocationRaw,
		mutateTime,
		releaseinventory.SignatureTrustModeKeyID,
	)
}

func offlineSignedWithRevocationMode(
	t *testing.T,
	fixture offlineTrustFixture,
	revocationRaw []byte,
	mutateTime func(*trustedTimePayload),
	mode releaseinventory.SignatureTrustMode,
) releaseinventory.SignedManifest {
	t.Helper()
	manifest := manifestWithRevocationDigestMode(t, releaseinventory.DigestBytes(revocationRaw), mode)
	timePayload := trustedTimePayload{
		ExpiresAt:      manifest.ValidUntil().Add(24 * time.Hour).UnixMicro(),
		IssuedAt:       manifest.BuildTimestamp().Add(30 * time.Minute).UnixMicro(),
		ManifestDigest: manifest.Digest().Hex(), ReleaseID: manifest.ReleaseID(),
		ReleaseSequence: manifest.Sequence(), SchemaVersion: 1, TrustDomain: "agentmemory.release",
		TrustRootID: "root-2026",
	}
	if mutateTime != nil {
		mutateTime(&timePayload)
	}
	timeRaw := signedOfflineEnvelope(t, timePayload, fixture.timePrivate, "time", func(signature qualificationSignature) any {
		return trustedTimeEnvelope{Payload: timePayload, Signature: signature}
	})
	input := releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     mode, TrustRootID: "root-2026",
		Signature:     bytes.Repeat([]byte{0x7f}, releaseinventory.ManifestSignatureSize),
		RevocationSet: revocationRaw, TrustedTimeEvidence: timeRaw,
	}
	if mode == releaseinventory.SignatureTrustModeCertificateTransparency {
		input.Signature = nil
		input.SigstoreBundle = []byte("official Sigstore bundle")
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, input)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func signedOfflineEnvelope[T any](
	t *testing.T,
	payload T,
	privateKey ed25519.PrivateKey,
	keyID string,
	envelope func(qualificationSignature) any,
) []byte {
	t.Helper()
	payloadRaw := mustJSON(t, payload)
	signature := qualificationSignature{
		Algorithm: "ed25519", KeyID: keyID,
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payloadRaw)),
	}
	return mustJSON(t, envelope(signature))
}

func manifestWithRevocationDigestMode(
	t *testing.T,
	revocationDigest releaseinventory.Digest,
	mode releaseinventory.SignatureTrustMode,
) releaseinventory.Manifest {
	t.Helper()
	base := adapterManifest(t, mode)
	transparencyLogID := ""
	if mode == releaseinventory.SignatureTrustModeCertificateTransparency {
		transparencyLogID = "rekor-production"
	}
	trustPolicy, err := releaseinventory.NewTrustPolicy(
		mode,
		"root-2026",
		revocationDigest,
		transparencyLogID,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: base.SchemaVersion(), ReleaseID: base.ReleaseID(), Version: base.Version(),
		BuildID: base.BuildID(), SourceCommit: base.SourceCommit(), BuildTimestamp: base.BuildTimestamp(),
		Channel: base.Channel(), Sequence: base.Sequence(), DataGeneration: base.DataGeneration(),
		ValidFrom: base.ValidFrom(), ValidUntil: base.ValidUntil(), Protocol: base.Protocol(),
		Compatibility: base.Compatibility(), TrustPolicy: trustPolicy, ReleaseHistory: base.ReleaseHistory(),
		LicensePolicyDigest: base.LicensePolicyDigest(), VulnerabilityPolicyDigest: base.VulnerabilityPolicyDigest(),
		DockerTopology: base.DockerTopology(), Resources: base.Resources(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
