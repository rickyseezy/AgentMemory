package releaseverify

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestVerifyReleaseProducesClosedInventoryOnlyAfterEveryTrustGate(t *testing.T) {
	t.Parallel()

	signed := signedReleaseFixture(t, fixtureOptions{})
	ports := newVerificationPorts(t)
	application := mustReleaseApplication(t, ports)

	result, err := application.Verify(context.Background(), signed)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.ManifestDigest() != signed.Manifest().Digest() || result.ReleaseID() != signed.Manifest().ReleaseID() {
		t.Fatal("verified inventory lost its signed manifest binding")
	}
	if result.Platform() != ports.platform || result.AlreadyAccepted() {
		t.Fatalf("verified platform/idempotency = %s/%t", result.Platform(), result.AlreadyAccepted())
	}
	if result.Sequence() != signed.Manifest().Sequence() || result.VerifiedAt() != ports.now {
		t.Fatal("verified inventory lost sequence or verification time")
	}
	if len(result.Resources()) != len(signed.Manifest().Resources()) {
		t.Fatalf("verified resources = %d, want %d", len(result.Resources()), len(signed.Manifest().Resources()))
	}
	if ports.signatureCalls != 1 || ports.trustCalls != 1 || ports.digestCalls != len(result.Resources()) {
		t.Fatalf("signature/trust/digest calls = %d/%d/%d", ports.signatureCalls, ports.trustCalls, ports.digestCalls)
	}
	subjectCount := 0
	for _, resource := range result.Resources() {
		if !resource.Kind().IsEvidence() {
			subjectCount++
		}
	}
	if ports.sbomCalls != subjectCount || ports.provenanceCalls != subjectCount ||
		ports.licenseCalls != subjectCount || ports.vulnerabilityCalls != subjectCount {
		t.Fatalf(
			"policy calls = sbom:%d provenance:%d license:%d vulnerability:%d",
			ports.sbomCalls,
			ports.provenanceCalls,
			ports.licenseCalls,
			ports.vulnerabilityCalls,
		)
	}
	if ports.nativePublisherCalls != 3 || ports.ociIndexCalls != 1 || ports.commits != 1 {
		t.Fatalf("native/OCI/anchor calls = %d/%d/%d", ports.nativePublisherCalls, ports.ociIndexCalls, ports.commits)
	}

	resources := result.Resources()
	if resources[0].Kind() == "" || resources[0].Digest().IsZero() || resources[0].Size() == 0 ||
		resources[0].Purpose() == "" || resources[0].SourceRef() == "" || !resources[0].Platform().Valid() {
		t.Fatal("verified resource accessors lost evidence")
	}
	helper, found := result.Resource("helper")
	if !found || helper.ID() != "helper" || helper.Kind() != releaseinventory.ResourceKindHelper ||
		helper.Purpose() != releaseinventory.ResourcePurposeNativeHelper || helper.MediaType() == "" ||
		helper.SourceRef() == "" {
		t.Fatal("exact verified resource selection lost signed execution authority")
	}
	var signedHelper releaseinventory.Resource
	for _, resource := range signed.Manifest().Resources() {
		if resource.ID() == "helper" {
			signedHelper = resource
			break
		}
	}
	if !helper.Authorizes(signedHelper) || helper.Authorizes(releaseinventory.Resource{}) {
		t.Fatal("verified resource did not authenticate its exact signed descriptor")
	}
	if _, found := result.Resource("future-or-foreign-resource"); found {
		t.Fatal("verified inventory selected a resource outside its closed target set")
	}
	resources[0] = VerifiedResource{}
	if result.Resources()[0].ID() == "" {
		t.Fatal("verified inventory exposed mutable resource storage")
	}
}

func TestVerifyReleaseRejectsNilContextWithoutCallingDependencies(t *testing.T) {
	t.Parallel()

	ports := newVerificationPorts(t)
	//lint:ignore SA1012 Deliberate nil-context attack proves the release use case fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	_, err := mustReleaseApplication(t, ports).Verify(nil, signedReleaseFixture(t, fixtureOptions{}))
	assertReleaseError(t, err, ErrorCodeDependencyUnavailable, FailureReasonDependencyUnavailable)
	if ports.signatureCalls != 0 || ports.trustCalls != 0 || ports.digestCalls != 0 {
		t.Fatal("nil context reached release-verification dependencies")
	}
}

func TestVerifyReleaseDoesNotCompareDifferentChannelHighWaterMarks(t *testing.T) {
	t.Parallel()
	signed := signedReleaseFixture(t, fixtureOptions{})
	ports := newVerificationPorts(t)
	ports.anchor = mustChannelReleaseAnchor(
		t,
		releaseinventory.ReleaseChannelNightly,
		signed.Manifest().Sequence()+1_000,
		releaseinventory.DigestBytes([]byte("nightly")),
		"nightly",
	)
	ports.hasAnchor = true

	result, err := mustReleaseApplication(t, ports).Verify(context.Background(), signed)
	if err != nil {
		t.Fatalf("stable verification was blocked by nightly sequence: %v", err)
	}
	if result.AlreadyAccepted() || ports.anchor.Channel() != releaseinventory.ReleaseChannelStable {
		t.Fatal("stable verification did not create its independent channel anchor")
	}
}

func TestVerifyReleaseBlocksEveryUntrustedReleaseCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		options    fixtureOptions
		configure  func(*verificationPorts, releaseinventory.SignedManifest)
		wantCode   ErrorCode
		wantReason FailureReason
	}{
		{
			name: "wrong signer",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.signatureError = ErrUntrustedSigner
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonUntrustedSigner,
		},
		{
			name: "signature tamper",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.signatureError = ErrSignatureInvalid
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonSignatureInvalid,
		},
		{
			name:     "missing revocation evidence",
			options:  fixtureOptions{omitRevocations: true},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonRevocationEvidence,
		},
		{
			name:     "missing trusted time",
			options:  fixtureOptions{omitTrustedTime: true},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonTrustedTimeEvidence,
		},
		{
			name:     "missing certificate transparency evidence",
			options:  fixtureOptions{transparencyMode: true, omitTransparency: true},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonTransparencyEvidence,
		},
		{
			name: "trust evidence rejected",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.trustError = ErrTrustEvidenceInvalid
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonTrustEvidenceInvalid,
		},
		{
			name: "revoked trust root",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.trustError = ErrTrustRootRevoked
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonTrustRootRevoked,
		},
		{
			name: "expired support window",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.now = time.Date(2028, time.January, 1, 0, 0, 0, 0, time.UTC)
			},
			wantCode: ErrorCodeConflict, wantReason: FailureReasonReleaseExpired,
		},
		{
			name: "wrong platform",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.platform = mustReleasePlatform(t, "darwin", "arm64")
			},
			wantCode: ErrorCodeUnsupportedHost, wantReason: FailureReasonPlatformUnsupported,
		},
		{
			name:     "incomplete platform inventory",
			options:  fixtureOptions{omitModel: true},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonInventoryIncomplete,
		},
		{
			name:      "protocol mismatch",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) { ports.protocol = 99 },
			wantCode:  ErrorCodeSchemaUnsupported, wantReason: FailureReasonProtocolUnsupported,
		},
		{
			name: "release rollback",
			configure: func(ports *verificationPorts, signed releaseinventory.SignedManifest) {
				ports.anchor = mustReleaseAnchor(t, signed.Manifest().Sequence()+1, releaseinventory.DigestBytes([]byte("newer")), "newer")
				ports.hasAnchor = true
			},
			wantCode: ErrorCodeConflict, wantReason: FailureReasonReleaseRollback,
		},
		{
			name: "sequence equivocation",
			configure: func(ports *verificationPorts, signed releaseinventory.SignedManifest) {
				ports.anchor = mustReleaseAnchor(t, signed.Manifest().Sequence(), releaseinventory.DigestBytes([]byte("different")), "different")
				ports.hasAnchor = true
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonSequenceEquivocation,
		},
		{
			name: "artifact digest tamper",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.digestError = ErrResourceDigestMismatch
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonDigestMismatch,
		},
		{
			name: "OCI index mismatch",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.ociIndexError = ErrOCIIndexInvalid
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonOCIIndexInvalid,
		},
		{
			name: "native publisher mismatch",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.nativePublisherError = ErrNativePublisherInvalid
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonNativePublisherInvalid,
		},
		{
			name:      "SBOM subject mismatch",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) { ports.sbomError = ErrSBOMInvalid },
			wantCode:  ErrorCodeIntegrityViolation, wantReason: FailureReasonSBOMInvalid,
		},
		{
			name: "provenance subject mismatch",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.provenanceError = ErrProvenanceInvalid
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonProvenanceInvalid,
		},
		{
			name: "disallowed license",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.licenseError = ErrLicenseDenied
			},
			wantCode: ErrorCodeForbidden, wantReason: FailureReasonLicenseDenied,
		},
		{
			name: "vulnerability policy failed",
			configure: func(ports *verificationPorts, _ releaseinventory.SignedManifest) {
				ports.vulnerabilityError = ErrVulnerabilityDenied
			},
			wantCode: ErrorCodeForbidden, wantReason: FailureReasonVulnerabilityDenied,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			signed := signedReleaseFixture(t, test.options)
			ports := newVerificationPorts(t)
			if test.configure != nil {
				test.configure(ports, signed)
			}
			application := mustReleaseApplication(t, ports)

			_, err := application.Verify(context.Background(), signed)
			assertReleaseError(t, err, test.wantCode, test.wantReason)
			if ports.commits != 0 {
				t.Fatalf("anti-rollback anchor commits = %d, want zero", ports.commits)
			}
		})
	}
}

func TestVerifyReleaseIsIdempotentForTheSameAcceptedManifest(t *testing.T) {
	t.Parallel()

	signed := signedReleaseFixture(t, fixtureOptions{})
	ports := newVerificationPorts(t)
	ports.anchor = mustReleaseAnchor(t, signed.Manifest().Sequence(), signed.Manifest().Digest(), signed.Manifest().ReleaseID())
	ports.hasAnchor = true
	application := mustReleaseApplication(t, ports)

	result, err := application.Verify(context.Background(), signed)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.AlreadyAccepted() || ports.commits != 0 || ports.digestCalls == 0 {
		t.Fatalf("already-accepted/digest/commit = %t/%d/%d", result.AlreadyAccepted(), ports.digestCalls, ports.commits)
	}
}

func TestVerifyReleaseSanitizesUnknownAndDeadlineFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failure    error
		wantCode   ErrorCode
		wantReason FailureReason
		retryable  bool
	}{
		{name: "unknown", failure: errors.New("secret /private/release path"), wantCode: ErrorCodeInternal, wantReason: FailureReasonInternal},
		{name: "deadline", failure: context.DeadlineExceeded, wantCode: ErrorCodeDeadlineExceeded, wantReason: FailureReasonDeadline, retryable: true},
		{name: "unavailable", failure: ErrResourceUnavailable, wantCode: ErrorCodeDependencyUnavailable, wantReason: FailureReasonResourceUnavailable, retryable: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ports := newVerificationPorts(t)
			ports.digestError = test.failure
			application := mustReleaseApplication(t, ports)

			_, err := application.Verify(context.Background(), signedReleaseFixture(t, fixtureOptions{}))
			assertReleaseError(t, err, test.wantCode, test.wantReason)
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) || verificationError.Retryable() != test.retryable {
				t.Fatalf("retryability = %v, want %t", err, test.retryable)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") || errors.Is(err, test.failure) {
				t.Fatalf("public error retained private cause: %v", err)
			}
		})
	}
}

func TestVerifyReleaseMapsEvidenceResourceUnavailabilityAsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*verificationPorts)
	}{
		{name: "OCI index", configure: func(ports *verificationPorts) { ports.ociIndexError = ErrResourceUnavailable }},
		{name: "SBOM", configure: func(ports *verificationPorts) { ports.sbomError = ErrResourceUnavailable }},
		{name: "provenance", configure: func(ports *verificationPorts) { ports.provenanceError = ErrResourceUnavailable }},
		{name: "license", configure: func(ports *verificationPorts) { ports.licenseError = ErrResourceUnavailable }},
		{name: "vulnerability", configure: func(ports *verificationPorts) { ports.vulnerabilityError = ErrResourceUnavailable }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ports := newVerificationPorts(t)
			test.configure(ports)
			_, err := mustReleaseApplication(t, ports).Verify(
				context.Background(),
				signedReleaseFixture(t, fixtureOptions{}),
			)
			assertReleaseError(t, err, ErrorCodeDependencyUnavailable, FailureReasonResourceUnavailable)
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) || !verificationError.Retryable() {
				t.Fatalf("evidence unavailability was not retryable: %v", err)
			}
		})
	}
}

func TestVerifyReleaseMapsAntiRollbackRepositoryFailuresFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configure  func(*verificationPorts)
		wantCode   ErrorCode
		wantReason FailureReason
	}{
		{
			name:      "load integrity",
			configure: func(ports *verificationPorts) { ports.anchorLoadError = ErrReleaseAnchorIntegrity },
			wantCode:  ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
		{
			name: "integrity dominates not found",
			configure: func(ports *verificationPorts) {
				ports.anchorLoadError = errors.Join(ErrReleaseAnchorNotFound, ErrReleaseAnchorIntegrity)
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
		{
			name: "deadline dominates not found",
			configure: func(ports *verificationPorts) {
				ports.anchorLoadError = errors.Join(ErrReleaseAnchorNotFound, context.DeadlineExceeded)
			},
			wantCode: ErrorCodeDeadlineExceeded, wantReason: FailureReasonDeadline,
		},
		{
			name: "invalid loaded anchor",
			configure: func(ports *verificationPorts) {
				ports.anchor = ReleaseAnchor{}
				ports.hasAnchor = true
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
		{
			name: "accepted anchor release identity mismatch",
			configure: func(ports *verificationPorts) {
				signed := signedReleaseFixture(t, fixtureOptions{})
				ports.anchor = mustReleaseAnchor(
					t,
					signed.Manifest().Sequence(),
					signed.Manifest().Digest(),
					"different-release",
				)
				ports.hasAnchor = true
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
		{
			name:      "compare and swap conflict",
			configure: func(ports *verificationPorts) { ports.anchorCommitError = ErrReleaseAnchorConflict },
			wantCode:  ErrorCodeConflict, wantReason: FailureReasonAnchorConflict,
		},
		{
			name:      "compare and swap integrity",
			configure: func(ports *verificationPorts) { ports.anchorCommitError = ErrReleaseAnchorIntegrity },
			wantCode:  ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
		{
			name: "compare and swap integrity dominates conflict",
			configure: func(ports *verificationPorts) {
				ports.anchorCommitError = errors.Join(ErrReleaseAnchorConflict, ErrReleaseAnchorIntegrity)
			},
			wantCode: ErrorCodeIntegrityViolation, wantReason: FailureReasonAnchorIntegrity,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ports := newVerificationPorts(t)
			test.configure(ports)
			_, err := mustReleaseApplication(t, ports).Verify(
				context.Background(),
				signedReleaseFixture(t, fixtureOptions{}),
			)
			assertReleaseError(t, err, test.wantCode, test.wantReason)
		})
	}
}

func TestReleaseApplicationRejectsEveryMissingDependencyAndInvalidAnchor(t *testing.T) {
	t.Parallel()

	ports := newVerificationPorts(t)
	valid := releaseDependencies(ports)
	tests := []struct {
		name   string
		remove func(*Dependencies)
	}{
		{name: "clock", remove: func(deps *Dependencies) { deps.Clock = nil }},
		{name: "platform", remove: func(deps *Dependencies) { deps.Platform = nil }},
		{name: "protocol", remove: func(deps *Dependencies) { deps.Protocol = nil }},
		{name: "signature", remove: func(deps *Dependencies) { deps.Signature = nil }},
		{name: "trust evidence", remove: func(deps *Dependencies) { deps.TrustEvidence = nil }},
		{name: "resource digest", remove: func(deps *Dependencies) { deps.ResourceDigest = nil }},
		{name: "SBOM", remove: func(deps *Dependencies) { deps.SBOM = nil }},
		{name: "provenance", remove: func(deps *Dependencies) { deps.Provenance = nil }},
		{name: "license", remove: func(deps *Dependencies) { deps.License = nil }},
		{name: "vulnerability", remove: func(deps *Dependencies) { deps.Vulnerability = nil }},
		{name: "native publisher", remove: func(deps *Dependencies) { deps.NativePublisher = nil }},
		{name: "OCI index", remove: func(deps *Dependencies) { deps.OCIIndex = nil }},
		{name: "anti-rollback", remove: func(deps *Dependencies) { deps.AntiRollback = nil }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.remove(&candidate)
			if application, err := NewApplication(candidate); err == nil || application != nil {
				t.Fatalf("NewApplication() = (%v, %v), want nil/error", application, err)
			}
		})
	}
	if _, err := NewReleaseAnchor("", 0, releaseinventory.Digest{}, ""); err == nil {
		t.Fatal("NewReleaseAnchor() accepted an invalid anchor")
	}
	if _, err := NewReleaseAnchor(
		releaseinventory.ReleaseChannelStable,
		1,
		releaseinventory.DigestBytes([]byte("manifest")),
		"unsafe/release",
	); err == nil {
		t.Fatal("NewReleaseAnchor() accepted an unsafe release identity")
	}
	anchor := mustReleaseAnchor(t, 1, releaseinventory.DigestBytes([]byte("manifest")), "release")
	if anchor.ReleaseID() != "release" || anchor.Channel() != releaseinventory.ReleaseChannelStable {
		t.Fatal("ReleaseAnchor accessors lost identity or channel")
	}
}

func TestReleaseVerificationUnknownPortFailuresRemainSanitizedAcrossEveryPolicyBoundary(t *testing.T) {
	t.Parallel()

	private := errors.New("secret /private/release-verifier detail")
	mappers := []struct {
		name string
		mapf func(error) error
	}{
		{name: "signature", mapf: mapSignatureError},
		{name: "trust", mapf: mapTrustError},
		{name: "target inventory", mapf: mapTargetInventoryError},
		{name: "OCI index", mapf: mapOCIIndexError},
		{name: "native publisher", mapf: mapNativePublisherError},
		{name: "SBOM", mapf: mapSBOMError},
		{name: "provenance", mapf: mapProvenanceError},
		{name: "license", mapf: mapLicenseError},
		{name: "vulnerability", mapf: mapVulnerabilityError},
		{name: "anchor load", mapf: mapAnchorLoadError},
		{name: "anchor mutation", mapf: mapAnchorMutationError},
	}
	for _, mapper := range mappers {
		t.Run(mapper.name, func(t *testing.T) {
			t.Parallel()
			err := mapper.mapf(private)
			assertReleaseError(t, err, ErrorCodeInternal, FailureReasonInternal)
			if errors.Is(err, private) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("mapped error retained the private cause: %v", err)
			}
		})
	}
}

type fixtureOptions struct {
	omitRevocations  bool
	omitTrustedTime  bool
	transparencyMode bool
	omitTransparency bool
	omitModel        bool
}

func signedReleaseFixture(t *testing.T, options fixtureOptions) releaseinventory.SignedManifest {
	t.Helper()
	platform := mustReleasePlatform(t, "linux", "amd64")
	resources := releaseFixtureResources(t, platform)
	if options.omitModel {
		modelIDs := make(map[string]struct{})
		for _, resource := range resources {
			if resource.Kind() == releaseinventory.ResourceKindModel {
				modelIDs[resource.ID()] = struct{}{}
			}
		}
		filtered := make([]releaseinventory.Resource, 0, len(resources))
		for _, resource := range resources {
			if resource.Kind() == releaseinventory.ResourceKindModel {
				continue
			}
			if _, modelEvidence := modelIDs[resource.SubjectResourceID()]; modelEvidence {
				continue
			}
			filtered = append(filtered, resource)
		}
		resources = filtered
	}
	protocol, _ := releaseinventory.NewProtocolRange(1, 3)
	versionRange, _ := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{
		Minimum: "1.0.0", Maximum: "1.0.0",
	})
	compatibility, _ := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange,
		Provider: versionRange, Schema: versionRange, Compose: versionRange,
		SQLite: versionRange, Neo4j: versionRange, RuntimeCatalog: versionRange,
	})
	mode := releaseinventory.SignatureTrustModeKeyID
	logID := ""
	if options.transparencyMode {
		mode = releaseinventory.SignatureTrustModeCertificateTransparency
		logID = "rekor-production"
	}
	revocations := []byte("signed revocations")
	trustPolicy, err := releaseinventory.NewTrustPolicy(mode, "release-root-2026", releaseinventory.DigestBytes(revocations), logID)
	if err != nil {
		t.Fatalf("NewTrustPolicy() error = %v", err)
	}
	topology, err := releaseFixtureTopology(resources)
	if err != nil {
		t.Fatalf("NewDockerTopology() error = %v", err)
	}
	history, _ := releaseinventory.NewReleaseHistory(nil, nil)
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion:             1,
		ReleaseID:                 "agentmemory-1.0.0",
		Version:                   "1.0.0",
		BuildID:                   "build-20260701-1",
		SourceCommit:              strings.Repeat("a", 40),
		BuildTimestamp:            time.Date(2026, time.June, 30, 23, 0, 0, 0, time.UTC),
		Channel:                   releaseinventory.ReleaseChannelStable,
		Sequence:                  42,
		DataGeneration:            6,
		ValidFrom:                 time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:                time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC),
		Protocol:                  protocol,
		Compatibility:             compatibility,
		TrustPolicy:               trustPolicy,
		ReleaseHistory:            history,
		LicensePolicyDigest:       releaseinventory.DigestBytes([]byte("license-policy")),
		VulnerabilityPolicyDigest: releaseinventory.DigestBytes([]byte("vulnerability_report-policy")),
		DockerTopology:            topology,
		Resources:                 resources,
	})
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	input := releaseinventory.SignatureBundleInput{
		SchemaVersion:       releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:           mode,
		TrustRootID:         "release-root-2026",
		Signature:           bytes.Repeat([]byte{0x1a}, releaseinventory.ManifestSignatureSize),
		RevocationSet:       revocations,
		TrustedTimeEvidence: []byte("trusted time"),
	}
	if options.omitRevocations {
		input.RevocationSet = nil
	}
	if options.omitTrustedTime {
		input.TrustedTimeEvidence = nil
	}
	if options.transparencyMode && !options.omitTransparency {
		input.Signature = nil
		input.SigstoreBundle = []byte("official Sigstore bundle")
	}
	if options.transparencyMode && options.omitTransparency {
		input.Signature = nil
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, input)
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	return signed
}

func releaseFixtureResources(t *testing.T, platform releaseinventory.Platform) []releaseinventory.Resource {
	t.Helper()
	inputs := make([]releaseinventory.ResourceInput, 0, 18)
	inputs = append(inputs,
		releaseSubjectInput("launcher", releaseinventory.ResourceKindLauncher, platform),
		releaseSubjectInput("helper", releaseinventory.ResourceKindHelper, platform),
		releaseSubjectInput("compose", releaseinventory.ResourceKindComposeBundle, platform),
		releaseSubjectInput("schema", releaseinventory.ResourceKindSchema, platform),
		releaseSubjectInput("migration", releaseinventory.ResourceKindMigration, platform),
		releaseSubjectInput("verifier", releaseinventory.ResourceKindVerifier, platform),
		releaseSubjectInput("setup-ui", releaseinventory.ResourceKindSetupUI, platform),
		releaseSubjectInput("runtime-catalog", releaseinventory.ResourceKindRuntimeCatalog, platform),
	)
	for _, role := range []releaseinventory.LocalProviderRole{
		releaseinventory.LocalProviderRoleEmbedding,
		releaseinventory.LocalProviderRoleReranking,
		releaseinventory.LocalProviderRoleExtraction,
	} {
		for _, kind := range []releaseinventory.ResourceKind{
			releaseinventory.ResourceKindModel,
			releaseinventory.ResourceKindTokenizer,
			releaseinventory.ResourceKindTemplate,
		} {
			input := releaseSubjectInput(string(kind)+"-"+string(role), kind, platform)
			input.ProviderRole = role
			inputs = append(inputs, input)
		}
	}
	imageDigest := releaseinventory.DigestBytes([]byte("image"))
	indexDigest := releaseinventory.DigestBytes([]byte("image-index"))
	image := releaseSubjectInput("image", releaseinventory.ResourceKindOCIImage, platform)
	image.Digest = imageDigest
	image.SourceRef = "registry.example/agentmemory/image@sha256:" + imageDigest.Hex()
	image.SourceAllowlist = []string{image.SourceRef}
	image.OCIIndexDigest = indexDigest
	image.OCIIndexResourceID = "image-index"
	index := releaseSubjectInput("image-index", releaseinventory.ResourceKindOCIIndex, releaseinventory.Platform{})
	index.Digest = indexDigest
	index.SourceRef = "registry.example/agentmemory/image-index@sha256:" + indexDigest.Hex()
	index.SourceAllowlist = []string{index.SourceRef}
	inputs = append(inputs, image, index)

	resources := make([]releaseinventory.Resource, 0, len(inputs)*6)
	for _, input := range inputs {
		input.CycloneDXSBOMResourceID = input.ID + "-cyclonedx"
		input.SPDXSBOMResourceID = input.ID + "-spdx"
		input.ProvenanceResourceID = input.ID + "-provenance"
		input.LicenseResourceID = input.ID + "-licenses"
		input.VulnerabilityResourceID = input.ID + "-vulnerabilities"
		resources = append(resources, mustReleaseResource(t, input))
		resources = append(resources, releaseEvidenceResources(t, input)...)
	}
	return resources
}

func releaseSubjectInput(
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
) releaseinventory.ResourceInput {
	digest := releaseinventory.DigestBytes([]byte(id))
	sourceRef := "bundle://" + id
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: releasePurpose(kind), MediaType: releaseMediaType(kind),
		Platform: platform, Digest: digest, Size: uint64(len(id)), SourceRef: sourceRef,
		SourceAllowlist: []string{sourceRef},
	}
	if kind == releaseinventory.ResourceKindLauncher || kind == releaseinventory.ResourceKindVerifier ||
		kind == releaseinventory.ResourceKindHelper {
		input.NativePublisherIdentity = "agentmemory.publisher"
		input.NativePublisherPolicyID = "agentmemory-native-2026"
	}
	if kind == releaseinventory.ResourceKindComposeBundle {
		input.ExpandedTarget = releaseinventory.ReleaseExpandedTargetInput{
			Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
			Digest: digest, Bytes: uint64(len(id)),
		}
	}
	return input
}

func releaseEvidenceResources(
	t *testing.T,
	subject releaseinventory.ResourceInput,
) []releaseinventory.Resource {
	t.Helper()
	types := []releaseinventory.ResourceKind{
		releaseinventory.ResourceKindCycloneDXSBOM,
		releaseinventory.ResourceKindSPDXSBOM,
		releaseinventory.ResourceKindProvenance,
		releaseinventory.ResourceKindLicense,
		releaseinventory.ResourceKindVulnerabilityReport,
	}
	resources := make([]releaseinventory.Resource, 0, len(types))
	for _, kind := range types {
		suffix := map[releaseinventory.ResourceKind]string{
			releaseinventory.ResourceKindCycloneDXSBOM:       "cyclonedx",
			releaseinventory.ResourceKindSPDXSBOM:            "spdx",
			releaseinventory.ResourceKindProvenance:          "provenance",
			releaseinventory.ResourceKindLicense:             "licenses",
			releaseinventory.ResourceKindVulnerabilityReport: "vulnerabilities",
		}[kind]
		id := subject.ID + "-" + suffix
		sourceRef := "bundle://" + id
		input := releaseinventory.ResourceInput{
			ID: id, Kind: kind, Purpose: releasePurpose(kind), MediaType: releaseMediaType(kind),
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: uint64(len(id)),
			SourceRef: sourceRef, SourceAllowlist: []string{sourceRef},
			SubjectResourceID: subject.ID, SubjectDigest: subject.Digest,
		}
		if kind == releaseinventory.ResourceKindLicense ||
			kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte(string(kind) + "-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.QualificationExpiresAt = time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)
		}
		resources = append(resources, mustReleaseResource(t, input))
	}
	return resources
}

func mustReleaseResource(t *testing.T, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(%q) error = %v", input.ID, err)
	}
	return resource
}

func releaseFixtureTopology(resources []releaseinventory.Resource) (releaseinventory.DockerTopology, error) {
	images := make([]string, 0)
	for _, resource := range resources {
		if resource.Kind() == releaseinventory.ResourceKindOCIImage {
			images = append(images, resource.ID())
		}
	}
	labels := []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	return releaseinventory.NewDockerTopology(releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		Volumes: []releaseinventory.DockerVolumeInput{{
			ID: "core-data", Purpose: "canonical-data", Labels: labels,
		}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "core-ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: images, Profiles: []string{"default"},
			NetworkIDs: []string{"internal"},
			VolumeMounts: []releaseinventory.VolumeMountInput{{
				VolumeID: "core-data", Target: "/var/lib/agentmemory",
			}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{
				Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080,
			}},
			Labels: labels,
		}},
	})
}

func releasePurpose(kind releaseinventory.ResourceKind) releaseinventory.ResourcePurpose {
	return map[releaseinventory.ResourceKind]releaseinventory.ResourcePurpose{
		releaseinventory.ResourceKindLauncher:            releaseinventory.ResourcePurposeNativeLauncher,
		releaseinventory.ResourceKindHelper:              releaseinventory.ResourcePurposeNativeHelper,
		releaseinventory.ResourceKindComposeBundle:       releaseinventory.ResourcePurposeComposeLock,
		releaseinventory.ResourceKindOCIImage:            releaseinventory.ResourcePurposeOCIPlatformManifest,
		releaseinventory.ResourceKindOCIIndex:            releaseinventory.ResourcePurposeOCIIndex,
		releaseinventory.ResourceKindSchema:              releaseinventory.ResourcePurposeContractBundle,
		releaseinventory.ResourceKindMigration:           releaseinventory.ResourcePurposeMigrationSet,
		releaseinventory.ResourceKindSetupUI:             releaseinventory.ResourcePurposeSetupUI,
		releaseinventory.ResourceKindVerifier:            releaseinventory.ResourcePurposeOfflineVerifier,
		releaseinventory.ResourceKindModel:               releaseinventory.ResourcePurposeModelWeights,
		releaseinventory.ResourceKindTokenizer:           releaseinventory.ResourcePurposeTokenizer,
		releaseinventory.ResourceKindTemplate:            releaseinventory.ResourcePurposePromptTemplate,
		releaseinventory.ResourceKindInstallPlanTemplate: releaseinventory.ResourcePurposeInstallPlanTemplate,
		releaseinventory.ResourceKindOfflineComponent:    releaseinventory.ResourcePurposeOfflineComponent,
		releaseinventory.ResourceKindRuntimeCatalog:      releaseinventory.ResourcePurposeRuntimeCatalog,
		releaseinventory.ResourceKindCycloneDXSBOM:       releaseinventory.ResourcePurposeCycloneDXSBOM,
		releaseinventory.ResourceKindSPDXSBOM:            releaseinventory.ResourcePurposeSPDXSBOM,
		releaseinventory.ResourceKindProvenance:          releaseinventory.ResourcePurposeSLSAProvenance,
		releaseinventory.ResourceKindLicense:             releaseinventory.ResourcePurposeLicenseEvaluation,
		releaseinventory.ResourceKindVulnerabilityReport: releaseinventory.ResourcePurposeVulnerabilityReport,
	}[kind]
}

func releaseMediaType(kind releaseinventory.ResourceKind) string {
	return map[releaseinventory.ResourceKind]string{
		releaseinventory.ResourceKindLauncher:            releaseinventory.MediaTypeNativeExecutable,
		releaseinventory.ResourceKindHelper:              releaseinventory.MediaTypeNativeExecutable,
		releaseinventory.ResourceKindComposeBundle:       releaseinventory.MediaTypeComposeLock,
		releaseinventory.ResourceKindOCIImage:            releaseinventory.MediaTypeOCIManifest,
		releaseinventory.ResourceKindOCIIndex:            releaseinventory.MediaTypeOCIIndex,
		releaseinventory.ResourceKindSchema:              releaseinventory.MediaTypeContractBundle,
		releaseinventory.ResourceKindMigration:           releaseinventory.MediaTypeMigrationSet,
		releaseinventory.ResourceKindSetupUI:             releaseinventory.MediaTypeSetupUI,
		releaseinventory.ResourceKindVerifier:            releaseinventory.MediaTypeNativeExecutable,
		releaseinventory.ResourceKindModel:               releaseinventory.MediaTypeModelWeights,
		releaseinventory.ResourceKindTokenizer:           releaseinventory.MediaTypeTokenizer,
		releaseinventory.ResourceKindTemplate:            releaseinventory.MediaTypePromptTemplate,
		releaseinventory.ResourceKindInstallPlanTemplate: releaseinventory.MediaTypeInstallPlanTemplate,
		releaseinventory.ResourceKindOfflineComponent:    releaseinventory.MediaTypeOfflineComponent,
		releaseinventory.ResourceKindRuntimeCatalog:      releaseinventory.MediaTypeRuntimeCatalog,
		releaseinventory.ResourceKindCycloneDXSBOM:       releaseinventory.MediaTypeCycloneDX,
		releaseinventory.ResourceKindSPDXSBOM:            releaseinventory.MediaTypeSPDX,
		releaseinventory.ResourceKindProvenance:          releaseinventory.MediaTypeSLSAProvenance,
		releaseinventory.ResourceKindLicense:             releaseinventory.MediaTypeLicenseEvaluation,
		releaseinventory.ResourceKindVulnerabilityReport: releaseinventory.MediaTypeVulnerabilityEvaluation,
	}[kind]
}

type verificationPorts struct {
	t                    *testing.T
	platform             releaseinventory.Platform
	protocol             uint32
	now                  time.Time
	anchor               ReleaseAnchor
	hasAnchor            bool
	signatureError       error
	trustError           error
	digestError          error
	sbomError            error
	provenanceError      error
	licenseError         error
	vulnerabilityError   error
	nativePublisherError error
	ociIndexError        error
	anchorCommitError    error
	anchorLoadError      error
	signatureCalls       int
	trustCalls           int
	digestCalls          int
	sbomCalls            int
	provenanceCalls      int
	licenseCalls         int
	vulnerabilityCalls   int
	nativePublisherCalls int
	ociIndexCalls        int
	commits              int
}

func newVerificationPorts(t *testing.T) *verificationPorts {
	t.Helper()
	return &verificationPorts{
		t:        t,
		platform: mustReleasePlatform(t, "linux", "amd64"),
		protocol: 2,
		now:      time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC),
	}
}

func (p *verificationPorts) Now() time.Time { return p.now }
func (p *verificationPorts) CurrentPlatform(context.Context) (releaseinventory.Platform, error) {
	return p.platform, nil
}
func (p *verificationPorts) CurrentProtocol(context.Context) (uint32, error) { return p.protocol, nil }
func (p *verificationPorts) VerifyManifestSignature(context.Context, releaseinventory.SignedManifest) error {
	p.signatureCalls++
	return p.signatureError
}
func (p *verificationPorts) VerifyOfflineTrustEvidence(context.Context, releaseinventory.SignedManifest) error {
	p.trustCalls++
	return p.trustError
}
func (p *verificationPorts) VerifyResourceDigest(context.Context, releaseinventory.Resource) error {
	p.digestCalls++
	return p.digestError
}
func (p *verificationPorts) VerifySBOMs(
	context.Context,
	releaseinventory.Resource,
	releaseinventory.Resource,
	releaseinventory.Resource,
) error {
	p.sbomCalls++
	return p.sbomError
}
func (p *verificationPorts) VerifyProvenance(
	context.Context,
	releaseinventory.Manifest,
	releaseinventory.Resource,
	releaseinventory.Resource,
) error {
	p.provenanceCalls++
	return p.provenanceError
}
func (p *verificationPorts) VerifyLicense(context.Context, releaseinventory.Resource, releaseinventory.Resource) error {
	p.licenseCalls++
	return p.licenseError
}
func (p *verificationPorts) VerifyVulnerabilities(context.Context, releaseinventory.Resource, releaseinventory.Resource) error {
	p.vulnerabilityCalls++
	return p.vulnerabilityError
}
func (p *verificationPorts) VerifyNativePublisher(context.Context, releaseinventory.Resource) error {
	p.nativePublisherCalls++
	return p.nativePublisherError
}
func (p *verificationPorts) VerifyOCIIndex(
	context.Context,
	releaseinventory.Resource,
	releaseinventory.Resource,
) error {
	p.ociIndexCalls++
	return p.ociIndexError
}
func (p *verificationPorts) LoadReleaseAnchor(
	_ context.Context,
	channel releaseinventory.ReleaseChannel,
) (ReleaseAnchor, error) {
	if p.anchorLoadError != nil {
		return ReleaseAnchor{}, p.anchorLoadError
	}
	if !p.hasAnchor || p.anchor.valid() && p.anchor.Channel() != channel {
		return ReleaseAnchor{}, ErrReleaseAnchorNotFound
	}
	return p.anchor, nil
}
func (p *verificationPorts) CompareAndSwapReleaseAnchor(
	_ context.Context,
	expected *ReleaseAnchor,
	next ReleaseAnchor,
) error {
	p.commits++
	channelHasAnchor := p.hasAnchor && p.anchor.Channel() == next.Channel()
	if channelHasAnchor && (expected == nil || *expected != p.anchor) {
		return ErrReleaseAnchorConflict
	}
	if !channelHasAnchor && expected != nil {
		return ErrReleaseAnchorConflict
	}
	if p.anchorCommitError != nil {
		return p.anchorCommitError
	}
	p.anchor = next
	p.hasAnchor = true
	return nil
}

func mustReleaseApplication(t *testing.T, ports *verificationPorts) *Application {
	t.Helper()
	application, err := NewApplication(releaseDependencies(ports))
	if err != nil {
		t.Fatalf("NewApplication() error = %v", err)
	}
	return application
}

func releaseDependencies(ports *verificationPorts) Dependencies {
	return Dependencies{
		Clock:           ports,
		Platform:        ports,
		Protocol:        ports,
		Signature:       ports,
		TrustEvidence:   ports,
		ResourceDigest:  ports,
		SBOM:            ports,
		Provenance:      ports,
		License:         ports,
		Vulnerability:   ports,
		NativePublisher: ports,
		OCIIndex:        ports,
		AntiRollback:    ports,
	}
}

func mustReleasePlatform(t *testing.T, operatingSystem string, architecture string) releaseinventory.Platform {
	t.Helper()
	platform, err := releaseinventory.NewPlatform(operatingSystem, architecture)
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}
	return platform
}

func mustReleaseAnchor(t *testing.T, sequence uint64, digest releaseinventory.Digest, releaseID string) ReleaseAnchor {
	t.Helper()
	return mustChannelReleaseAnchor(
		t, releaseinventory.ReleaseChannelStable, sequence, digest, releaseID,
	)
}

func mustChannelReleaseAnchor(
	t *testing.T,
	channel releaseinventory.ReleaseChannel,
	sequence uint64,
	digest releaseinventory.Digest,
	releaseID string,
) ReleaseAnchor {
	t.Helper()
	anchor, err := NewReleaseAnchor(channel, sequence, digest, releaseID)
	if err != nil {
		t.Fatalf("NewReleaseAnchor() error = %v", err)
	}
	return anchor
}

func assertReleaseError(t *testing.T, err error, code ErrorCode, reason FailureReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s/%s", code, reason)
	}
	var verificationError *VerificationError
	if !errors.As(err, &verificationError) {
		t.Fatalf("error type = %T, want *VerificationError", err)
	}
	if verificationError.Code() != code || verificationError.Reason() != reason {
		t.Fatalf("error = %s/%s, want %s/%s", verificationError.Code(), verificationError.Reason(), code, reason)
	}
}
