package releaseverifyadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	testSigstoreSAN    = "foo!oidc.local"
	testSigstoreIssuer = "http://oidc.local:8080"
	testArtifactDigest = "bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
	testRekorLogID     = "f6fb357e481d95b94fc8cb9688b44041b120d219831c4e94c02f76571c8b4bc8"
)

func TestSigstoreVerifierValidatesCompleteOfficialBundleEntirelyOffline(t *testing.T) {
	verifier, rawBundle, digest, _, _ := staticSigstoreVerifier(t)

	oldTransport := http.DefaultTransport
	http.DefaultTransport = rejectingRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	if err := verifier.verifyBundleDigest(rawBundle, digest); err != nil {
		t.Fatalf("verifyBundleDigest() error = %v", err)
	}
}

func TestSigstoreVerifierRejectsDigestIdentityAndTrustSubstitution(t *testing.T) {
	verifier, rawBundle, digest, logID, rootJSON := staticSigstoreVerifier(t)

	wrongDigest := append([]byte(nil), digest...)
	wrongDigest[0] ^= 0xff
	if err := verifier.verifyBundleDigest(rawBundle, wrongDigest); err == nil {
		t.Fatal("verifyBundleDigest() accepted a different artifact digest")
	}

	wrongIdentity, err := NewSigstoreCertificateTransparencyVerifier(SigstoreTrustPolicyInput{
		TrustRootID: "sigstore-root", TrustedRootJSON: rootJSON, RekorLogID: logID,
		CertificateSAN: "attacker@invalid.example", OIDCIssuer: testSigstoreIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongIdentity.verifyBundleDigest(rawBundle, digest); err == nil {
		t.Fatal("verifyBundleDigest() accepted a different certificate SAN")
	}

	missingLogID := strings.Repeat("0", 64)
	if _, err := NewSigstoreCertificateTransparencyVerifier(SigstoreTrustPolicyInput{
		TrustRootID: "sigstore-root", TrustedRootJSON: rootJSON, RekorLogID: missingLogID,
		CertificateSAN: testSigstoreSAN, OIDCIssuer: testSigstoreIssuer,
	}); err == nil {
		t.Fatal("constructor accepted a Rekor log ID absent from the injected trusted root")
	}

	var rootDocument map[string]any
	if err := json.Unmarshal(rootJSON, &rootDocument); err != nil {
		t.Fatal(err)
	}
	delete(rootDocument, "ctlogs")
	withoutCT, err := json.Marshal(rootDocument)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigstoreCertificateTransparencyVerifier(SigstoreTrustPolicyInput{
		TrustRootID: "sigstore-root", TrustedRootJSON: withoutCT, RekorLogID: logID,
		CertificateSAN: testSigstoreSAN, OIDCIssuer: testSigstoreIssuer,
	}); err == nil {
		t.Fatal("constructor accepted trusted material without a CT authority")
	}
}

func TestSigstoreVerifierRejectsTamperedProofCheckpointSignatureAndEncoding(t *testing.T) {
	verifier, rawBundle, digest, logID, _ := staticSigstoreVerifier(t)

	duplicate := append([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",`), rawBundle[1:]...)
	if _, err := decodeSigstoreBundle(duplicate, logID); !errors.Is(err, errEvidenceDuplicateKey) {
		t.Fatalf("duplicate-key error = %v, want errEvidenceDuplicateKey", err)
	}
	if _, err := decodeSigstoreBundle(append([]byte(" "), rawBundle...), logID); !errors.Is(err, errEvidenceNonCanonical) {
		t.Fatalf("noncanonical error = %v, want errEvidenceNonCanonical", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "signature",
			mutate: func(document map[string]any) {
				signature := document["messageSignature"].(map[string]any)
				raw, _ := base64.StdEncoding.DecodeString(signature["signature"].(string))
				raw[0] ^= 0xff
				signature["signature"] = base64.StdEncoding.EncodeToString(raw)
			},
		},
		{
			name: "checkpoint",
			mutate: func(document map[string]any) {
				proof := firstTlogEntry(document)["inclusionProof"].(map[string]any)
				checkpoint := proof["checkpoint"].(map[string]any)
				checkpoint["envelope"] = checkpoint["envelope"].(string) + "tampered"
			},
		},
		{
			name: "missing proof",
			mutate: func(document map[string]any) {
				delete(firstTlogEntry(document), "inclusionProof")
			},
		},
		{
			name: "DSSE is not a manifest signature",
			mutate: func(document map[string]any) {
				delete(document, "messageSignature")
				document["dsseEnvelope"] = map[string]any{
					"payload":     base64.StdEncoding.EncodeToString([]byte("{}")),
					"payloadType": "application/vnd.in-toto+json",
					"signatures": []any{map[string]any{
						"sig": base64.StdEncoding.EncodeToString([]byte("not a signature")),
					}},
				}
			},
		},
		{
			name: "non-SHA-256 signature",
			mutate: func(document map[string]any) {
				signature := document["messageSignature"].(map[string]any)
				digest := signature["messageDigest"].(map[string]any)
				digest["algorithm"] = "SHA2_512"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(rawBundle, &document); err != nil {
				t.Fatal(err)
			}
			test.mutate(document)
			tampered, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.verifyBundleDigest(tampered, digest); err == nil {
				t.Fatal("verification accepted tampered Sigstore evidence")
			}
		})
	}
}

func TestSigstoreManifestAdapterBindsPolicyAndExactCanonicalManifest(t *testing.T) {
	verifier, rawBundle, _, logID, _ := staticSigstoreVerifier(t)
	manifest := sigstoreAdapterManifest(t, "sigstore-root", logID)
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeCertificateTransparency, TrustRootID: "sigstore-root",
		SigstoreBundle: rawBundle, RevocationSet: []byte("revocations"), TrustedTimeEvidence: []byte("trusted time"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyManifestSignature(context.Background(), signed); !errors.Is(err, application.ErrSignatureInvalid) {
		t.Fatalf("published bundle for another digest error = %v, want ErrSignatureInvalid", err)
	}

	unitVerifier := *verifier
	unitVerifier.verifier = sigstoreVerifierStub{result: completeSigstoreResult()}
	if err := unitVerifier.VerifyManifestSignature(context.Background(), signed); err != nil {
		t.Fatalf("VerifyManifestSignature() error = %v", err)
	}
	wrongRoot, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeCertificateTransparency, TrustRootID: "other-root",
		SigstoreBundle: rawBundle, RevocationSet: []byte("revocations"), TrustedTimeEvidence: []byte("trusted time"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unitVerifier.VerifyManifestSignature(context.Background(), wrongRoot); !errors.Is(err, application.ErrUntrustedSigner) {
		t.Fatalf("wrong-root error = %v, want ErrUntrustedSigner", err)
	}
	keyMode := adapterSignedManifest(
		t,
		adapterManifest(t, releaseinventory.SignatureTrustModeKeyID),
		releaseinventory.SignatureTrustModeKeyID,
		"root-2026",
		bytes.Repeat([]byte{1}, releaseinventory.ManifestSignatureSize),
	)
	if err := unitVerifier.VerifyManifestSignature(context.Background(), keyMode); !errors.Is(err, application.ErrSignatureModeUnsupported) {
		t.Fatalf("key-mode error = %v, want ErrSignatureModeUnsupported", err)
	}
	var nilVerifier *SigstoreCertificateTransparencyVerifier
	if err := nilVerifier.VerifyManifestSignature(context.Background(), signed); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil-receiver error = %v, want ErrDependencyUnavailable", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyManifestSignature(ctx, signed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v, want context.Canceled", err)
	}
	afterCtx, afterCancel := context.WithCancel(context.Background())
	cancellingVerifier := *verifier
	cancellingVerifier.verifier = sigstoreVerifierStub{result: completeSigstoreResult(), cancel: afterCancel}
	if err := cancellingVerifier.VerifyManifestSignature(afterCtx, signed); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-verification cancellation error = %v, want context.Canceled", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves Sigstore verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyManifestSignature(nil, signed); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil-context error = %v, want ErrDependencyUnavailable", err)
	}
}

func TestSigstoreVerifierRejectsMalformedPolicyAndNilReceiver(t *testing.T) {
	_, _, digest, logID, rootJSON := staticSigstoreVerifier(t)
	tests := []SigstoreTrustPolicyInput{
		{},
		{TrustRootID: "sigstore-root", TrustedRootJSON: rootJSON, RekorLogID: strings.ToUpper(logID), CertificateSAN: testSigstoreSAN, OIDCIssuer: testSigstoreIssuer},
		{TrustRootID: "sigstore-root", TrustedRootJSON: rootJSON, RekorLogID: logID, CertificateSAN: "", OIDCIssuer: testSigstoreIssuer},
		{TrustRootID: "sigstore-root", TrustedRootJSON: []byte(`{"mediaType":"a","mediaType":"b"}`), RekorLogID: logID, CertificateSAN: testSigstoreSAN, OIDCIssuer: testSigstoreIssuer},
	}
	for index, input := range tests {
		if _, err := NewSigstoreCertificateTransparencyVerifier(input); err == nil {
			t.Fatalf("invalid policy %d was accepted", index)
		}
	}
	var verifier *SigstoreCertificateTransparencyVerifier
	if err := verifier.verifyBundleDigest([]byte("{}"), digest); !errors.Is(err, errEvidenceContent) {
		t.Fatalf("nil receiver error = %v, want errEvidenceContent", err)
	}
	if _, err := decodeSigstoreBundle(nil, logID); !errors.Is(err, errEvidenceMalformed) {
		t.Fatalf("nil bundle error = %v, want errEvidenceMalformed", err)
	}
}

func TestExactRekorTrustedMaterialDelegatesOnlyOfflineAuthorities(t *testing.T) {
	_, _, _, logID, rootJSON := staticSigstoreVerifier(t)
	trustedRoot, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		t.Fatal(err)
	}
	material := exactRekorTrustedMaterial{
		trustedRoot: trustedRoot,
		rekorLogID:  logID,
		rekorLog:    trustedRoot.RekorLogs()[logID],
	}
	_ = material.TimestampingAuthorities()
	if len(material.FulcioCertificateAuthorities()) == 0 || len(material.CTLogs()) == 0 ||
		len(material.RekorLogs()) != 1 || material.RekorLogs()[logID] == nil {
		t.Fatal("exact trusted-material wrapper lost an injected authority")
	}
	if _, err := material.PublicKeyVerifier("not-configured"); err == nil {
		t.Fatal("exact trusted-material wrapper synthesized an ambient public key")
	}
}

func FuzzDecodeSigstoreBundle(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = decodeSigstoreBundle(raw, testRekorLogID)
	})
}

func staticSigstoreVerifier(t *testing.T) (*SigstoreCertificateTransparencyVerifier, []byte, []byte, string, []byte) {
	t.Helper()
	entity := data.Bundle(t, "othername.sigstore.json")
	rawBundle, err := entity.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := entity.TlogEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("TlogEntries() = %d/%v", len(entries), err)
	}
	logID := hex.EncodeToString([]byte(entries[0].LogKeyID()))
	trustedRoot := data.TrustedRoot(t, "scaffolding.json")
	rootJSON, err := trustedRoot.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSigstoreCertificateTransparencyVerifier(SigstoreTrustPolicyInput{
		TrustRootID: "sigstore-root", TrustedRootJSON: rootJSON, RekorLogID: logID,
		CertificateSAN: testSigstoreSAN, OIDCIssuer: testSigstoreIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(testArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, rawBundle, digest, logID, rootJSON
}

func firstTlogEntry(document map[string]any) map[string]any {
	material := document["verificationMaterial"].(map[string]any)
	entries := material["tlogEntries"].([]any)
	return entries[0].(map[string]any)
}

func sigstoreAdapterManifest(t *testing.T, rootID, logID string) releaseinventory.Manifest {
	t.Helper()
	base := adapterManifest(t, releaseinventory.SignatureTrustModeCertificateTransparency)
	trustPolicy, err := releaseinventory.NewTrustPolicy(
		releaseinventory.SignatureTrustModeCertificateTransparency,
		rootID,
		releaseinventory.DigestBytes([]byte("revocations")),
		logID,
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

type rejectingRoundTripper struct{}

func (rejectingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network access attempted during offline Sigstore verification")
}

type sigstoreVerifierStub struct {
	result *verify.VerificationResult
	cancel context.CancelFunc
}

func (s sigstoreVerifierStub) Verify(
	verify.SignedEntity,
	verify.PolicyBuilder,
) (*verify.VerificationResult, error) {
	if s.cancel != nil {
		s.cancel()
	}
	return s.result, nil
}

func completeSigstoreResult() *verify.VerificationResult {
	return &verify.VerificationResult{
		Signature:        &verify.SignatureVerificationResult{Certificate: &certificate.Summary{}},
		VerifiedIdentity: &verify.CertificateIdentity{},
		VerifiedTimestamps: []verify.TimestampVerificationResult{{
			Type: "rekor", URI: "offline://rekor", Timestamp: time.Unix(1, 0).UTC(),
		}},
	}
}

func TestSigstoreBundleAccessorReturnsCopy(t *testing.T) {
	manifest := sigstoreAdapterManifest(t, "sigstore-root", strings.Repeat("1", 64))
	raw := []byte("bundle")
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeCertificateTransparency, TrustRootID: "sigstore-root",
		SigstoreBundle: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X'
	returned := signed.SigstoreBundle()
	returned[0] = 'Y'
	if !bytes.Equal(signed.SigstoreBundle(), []byte("bundle")) {
		t.Fatal("Sigstore bundle storage is mutable through an input or accessor")
	}
}
