package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001NativeReleaseBundleValidationRejectsUntrustedOrUnavailableInputs(t *testing.T) {
	t.Parallel()
	validTrust := encodeNativeReleaseTrust(t, nativeReleaseTrustFixture())
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	missing := filepath.Join(t.TempDir(), "missing")
	empty := newNativeValidationBundleRoot(t)
	malformed := newNativeValidationBundleRoot(t)
	if err := os.Mkdir(filepath.Join(malformed, "bootstrap"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malformed, "bootstrap", "distribution-manifest.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidSignature := newNativeValidationBundleRoot(t)
	if err := os.Mkdir(filepath.Join(invalidSignature, "bootstrap"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(invalidSignature, "bootstrap", "distribution-manifest.json"),
		invalidlySignedReleaseEnvelope(t, now), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		ctx          context.Context
		root         string
		trust        string
		os           string
		architecture string
		at           time.Time
	}{
		{name: "nil context", root: missing, trust: validTrust, os: "linux", architecture: "amd64", at: now},
		{name: "zero time", ctx: context.Background(), root: missing, trust: validTrust, os: "linux", architecture: "amd64"},
		{name: "pre epoch", ctx: context.Background(), root: missing, trust: validTrust, os: "linux", architecture: "amd64", at: time.Unix(0, 0)},
		{name: "platform", ctx: context.Background(), root: missing, trust: validTrust, os: "plan9", architecture: "amd64", at: now},
		{name: "trust", ctx: context.Background(), root: missing, trust: "invalid", os: "linux", architecture: "amd64", at: now},
		{name: "bundle", ctx: context.Background(), root: missing, trust: validTrust, os: "linux", architecture: "amd64", at: now},
		{name: "distribution", ctx: context.Background(), root: empty, trust: validTrust, os: "linux", architecture: "amd64", at: now},
		{name: "malformed distribution", ctx: context.Background(), root: malformed, trust: validTrust, os: "linux", architecture: "amd64", at: now},
		{name: "invalid signature", ctx: context.Background(), root: invalidSignature, trust: validTrust, os: "linux", architecture: "amd64", at: now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateNativeReleaseBundle(
				test.ctx, test.root, test.trust, test.os, test.architecture, test.at,
			); !errors.Is(err, errNativeInstallerIntegrity) {
				t.Fatalf("ValidateNativeReleaseBundle() error=%v", err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateNativeReleaseBundle(cancelled, missing, validTrust, "linux", "amd64", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled validation error=%v", err)
	}
}

func newNativeValidationBundleRoot(t testing.TB) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestPF001ReleaseValidationPlatformAndAnchorAreClosedCASAuthorities(t *testing.T) {
	t.Parallel()
	platform, err := releaseinventory.NewPlatform("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	provider := nativeReleaseExactPlatform{platform: platform}
	if current, err := provider.CurrentPlatform(t.Context()); err != nil || current != platform {
		t.Fatalf("CurrentPlatform()=%+v,%v", current, err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := provider.CurrentPlatform(nil); !errors.Is(err, errNativeInstallerIntegrity) { //nolint:staticcheck
		t.Fatalf("nil platform context error=%v", err)
	}
	if _, err := (nativeReleaseExactPlatform{}).CurrentPlatform(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("empty platform error=%v", err)
	}
	cancelledPlatform, cancelPlatform := context.WithCancel(context.Background())
	cancelPlatform()
	if _, err := provider.CurrentPlatform(cancelledPlatform); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled platform error=%v", err)
	}

	repository := newReleaseValidationAnchor()
	channel := releaseinventory.ReleaseChannelStable
	var absent *releaseValidationAnchor
	if _, err := absent.LoadReleaseAnchor(t.Context(), channel); !errors.Is(err, appreleaseverify.ErrReleaseAnchorIntegrity) {
		t.Fatalf("absent anchor load error=%v", err)
	}
	if err := absent.CompareAndSwapReleaseAnchor(t.Context(), nil, appreleaseverify.ReleaseAnchor{}); !errors.Is(err, appreleaseverify.ErrReleaseAnchorIntegrity) {
		t.Fatalf("absent anchor CAS error=%v", err)
	}
	if _, err := repository.LoadReleaseAnchor(t.Context(), channel); !errors.Is(err, appreleaseverify.ErrReleaseAnchorNotFound) {
		t.Fatalf("initial LoadReleaseAnchor() error=%v", err)
	}
	first, err := appreleaseverify.NewReleaseAnchor(
		channel, 1, releaseinventory.DigestBytes([]byte("first")), "release-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := appreleaseverify.NewReleaseAnchor(
		channel, 2, releaseinventory.DigestBytes([]byte("second")), "release-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(t.Context(), nil, first); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(t.Context(), nil, second); !errors.Is(err, appreleaseverify.ErrReleaseAnchorConflict) {
		t.Fatalf("duplicate initial CAS error=%v", err)
	}
	foreign, _ := appreleaseverify.NewReleaseAnchor(
		channel, 9, releaseinventory.DigestBytes([]byte("foreign")), "release-9",
	)
	if err := repository.CompareAndSwapReleaseAnchor(t.Context(), &foreign, second); !errors.Is(err, appreleaseverify.ErrReleaseAnchorConflict) {
		t.Fatalf("foreign CAS error=%v", err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(t.Context(), &first, second); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadReleaseAnchor(t.Context(), channel)
	if err != nil || !sameReleaseValidationAnchor(loaded, second) {
		t.Fatalf("LoadReleaseAnchor()=%+v,%v", loaded, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.LoadReleaseAnchor(cancelled, channel); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load error=%v", err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(cancelled, &second, foreign); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CAS error=%v", err)
	}
}

func TestPF001NativeReleasePackageSelectionUsesOnlyAuthorizedBundleResources(t *testing.T) {
	t.Parallel()
	platform, err := releaseinventory.NewPlatform("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	launcher := nativePackageSubject(t, "launcher-linux-arm64", releaseinventory.ResourceKindLauncher, platform, "native/linux/arm64/agentmemory")
	helper := nativePackageSubject(t, "helper-linux-arm64", releaseinventory.ResourceKindHelper, platform, "native/linux/arm64/agentmemory-runtime-helper")
	selection, err := selectNativeReleasePackage(
		platform, []releaseinventory.Resource{launcher, helper},
		nativePackageAuthorizerStub{launcher.ID(): true, helper.ID(): true},
	)
	if err != nil || !selection.Valid() || selection.OperatingSystem() != "linux" ||
		selection.Architecture() != "arm64" || selection.Launcher().ResourceID() != launcher.ID() ||
		selection.Launcher().BundlePath() != "native/linux/arm64/agentmemory" ||
		selection.Launcher().SHA256() != launcher.Digest().Hex() ||
		selection.Launcher().Size() != launcher.Size() || selection.Helper().ResourceID() != helper.ID() {
		t.Fatalf("selection=%+v error=%v", selection, err)
	}
	for name, resources := range map[string][]releaseinventory.Resource{
		"missing helper": {launcher},
		"duplicate":      {launcher, launcher, helper},
	} {
		if selected, err := selectNativeReleasePackage(
			platform, resources, nativePackageAuthorizerStub{launcher.ID(): true, helper.ID(): true},
		); err == nil || selected.Valid() {
			t.Fatalf("%s selection=%+v error=%v", name, selected, err)
		}
	}
	if selected, err := selectNativeReleasePackage(
		platform, []releaseinventory.Resource{launcher, helper}, nativePackageAuthorizerStub{launcher.ID(): true},
	); err == nil || selected.Valid() {
		t.Fatalf("unauthorized selection=%+v error=%v", selected, err)
	}
	if selected, err := selectNativeReleasePackage(
		releaseinventory.Platform{}, []releaseinventory.Resource{launcher, helper}, nativePackageAuthorizerStub{},
	); err == nil || selected.Valid() {
		t.Fatalf("invalid platform selection=%+v error=%v", selected, err)
	}
	var absent nativePackageResourceAuthorizer = (*nativePackageAuthorizerPointerStub)(nil)
	if selected, err := selectNativeReleasePackage(platform, []releaseinventory.Resource{launcher, helper}, absent); err == nil || selected.Valid() {
		t.Fatalf("typed-nil authorizer selection=%+v error=%v", selected, err)
	}
	foreignPlatform, _ := releaseinventory.NewPlatform("linux", "amd64")
	foreign := nativePackageSubject(t, "launcher-linux-amd64", releaseinventory.ResourceKindLauncher, foreignPlatform, "native/linux/amd64/agentmemory")
	unrelated := nativeNonPackageSubject(t, platform)
	withIgnored, err := selectNativeReleasePackage(
		platform, []releaseinventory.Resource{foreign, unrelated, launcher, helper},
		nativePackageAuthorizerStub{launcher.ID(): true, helper.ID(): true},
	)
	if err != nil || !withIgnored.Valid() {
		t.Fatalf("selection with ignored resources=%+v error=%v", withIgnored, err)
	}
	httpsLauncher := nativePackageSubjectAtSource(
		t, "launcher-https", releaseinventory.ResourceKindLauncher, platform,
		"https://releases.agentmemory.dev/native/linux/arm64/agentmemory",
	)
	if selected, err := selectNativeReleasePackage(
		platform, []releaseinventory.Resource{httpsLauncher, helper},
		nativePackageAuthorizerStub{httpsLauncher.ID(): true, helper.ID(): true},
	); err == nil || selected.Valid() {
		t.Fatalf("network-native selection=%+v error=%v", selected, err)
	}
	if (nativeVerifiedPackageAuthorizer{}).Authorizes(launcher) {
		t.Fatal("empty verified inventory authorized a resource")
	}
	if (exactReleaseValidationClock{at: time.Unix(123, 0).UTC()}).Now().Unix() != 123 {
		t.Fatal("exact validation clock changed its release time")
	}
	private := errors.New("private")
	if !errors.Is(nativeReleaseValidationError(t.Context(), private), errNativeInstallerIntegrity) ||
		!errors.Is(nativeReleaseValidationError(t.Context(), context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("release validation error mapping exposed or changed an error")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(nativeReleaseValidationError(cancelled, private), context.Canceled) {
		t.Fatal("release validation error mapping lost cancellation")
	}
}

func nativePackageSubject(
	t testing.TB,
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
	path string,
) releaseinventory.Resource {
	t.Helper()
	return nativePackageSubjectAtSource(t, id, kind, platform, "bundle://"+path)
}

func nativePackageSubjectAtSource(
	t testing.TB,
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
	source string,
) releaseinventory.Resource {
	t.Helper()
	content := []byte(id + " signed bytes")
	purpose := releaseinventory.ResourcePurposeNativeLauncher
	if kind == releaseinventory.ResourceKindHelper {
		purpose = releaseinventory.ResourcePurposeNativeHelper
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: releaseinventory.MediaTypeNativeExecutable,
		Platform: platform, Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef: source, SourceAllowlist: []string{source},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
		VulnerabilityResourceID: id + "-vulnerability", NativePublisherIdentity: "agentmemory.publisher",
		NativePublisherPolicyID: "agentmemory-native-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func nativeNonPackageSubject(t testing.TB, platform releaseinventory.Platform) releaseinventory.Resource {
	t.Helper()
	content := []byte("runtime catalog")
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "runtime-catalog-linux-arm64", Kind: releaseinventory.ResourceKindRuntimeCatalog,
		Purpose: releaseinventory.ResourcePurposeRuntimeCatalog, MediaType: releaseinventory.MediaTypeRuntimeCatalog,
		Platform: platform, Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef:               "bundle://runtime/linux/arm64/catalog.json",
		SourceAllowlist:         []string{"bundle://runtime/linux/arm64/catalog.json"},
		CycloneDXSBOMResourceID: "runtime-catalog-cyclonedx", SPDXSBOMResourceID: "runtime-catalog-spdx",
		ProvenanceResourceID: "runtime-catalog-provenance", LicenseResourceID: "runtime-catalog-license",
		VulnerabilityResourceID: "runtime-catalog-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

type nativePackageAuthorizerStub map[string]bool

func (s nativePackageAuthorizerStub) Authorizes(resource releaseinventory.Resource) bool {
	return s[resource.ID()]
}

type nativePackageAuthorizerPointerStub struct{}

func (*nativePackageAuthorizerPointerStub) Authorizes(releaseinventory.Resource) bool { return true }

func invalidlySignedReleaseEnvelope(t testing.TB, now time.Time) []byte {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	licensePolicy := releaseinventory.DigestBytes([]byte("license policy"))
	vulnerabilityPolicy := releaseinventory.DigestBytes([]byte("vulnerability policy"))
	resources := make([]releaseinventory.Resource, 0, 128)
	specifications := []struct { //nolint:prealloc // The explicit base fixture is clearer than repeated anonymous append values.
		id   string
		kind releaseinventory.ResourceKind
		role releaseinventory.LocalProviderRole
	}{
		{id: "launcher", kind: releaseinventory.ResourceKindLauncher},
		{id: "helper", kind: releaseinventory.ResourceKindHelper},
		{id: "compose", kind: releaseinventory.ResourceKindComposeBundle},
		{id: "schema", kind: releaseinventory.ResourceKindSchema},
		{id: "migration", kind: releaseinventory.ResourceKindMigration},
		{id: "setup-ui", kind: releaseinventory.ResourceKindSetupUI},
		{id: "verifier", kind: releaseinventory.ResourceKindVerifier},
		{id: "runtime-catalog", kind: releaseinventory.ResourceKindRuntimeCatalog},
		{id: "image", kind: releaseinventory.ResourceKindOCIImage},
		{id: "image-index", kind: releaseinventory.ResourceKindOCIIndex},
	}
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
			specifications = append(specifications, struct {
				id   string
				kind releaseinventory.ResourceKind
				role releaseinventory.LocalProviderRole
			}{id: string(kind) + "-" + string(role), kind: kind, role: role})
		}
	}
	indexDigest := releaseinventory.DigestBytes([]byte("image-index bytes"))
	for _, specification := range specifications {
		content := []byte(specification.id + " bytes")
		digest := releaseinventory.DigestBytes(content)
		resourcePlatform := platform
		source := "bundle://" + specification.id
		if specification.kind == releaseinventory.ResourceKindOCIIndex {
			resourcePlatform = releaseinventory.Platform{}
			source = "registry.example/agentmemory/image-index@sha256:" + digest.Hex()
		}
		if specification.kind == releaseinventory.ResourceKindOCIImage {
			source = "registry.example/agentmemory/image@sha256:" + digest.Hex()
		}
		input := releaseinventory.ResourceInput{
			ID: specification.id, Kind: specification.kind,
			Purpose: releaseResourcePurpose(specification.kind), MediaType: releaseResourceMediaType(specification.kind),
			ProviderRole: specification.role, Platform: resourcePlatform, Digest: digest,
			Size: uint64(len(content)), SourceRef: source, SourceAllowlist: []string{source},
			CycloneDXSBOMResourceID: specification.id + "-cyclonedx",
			SPDXSBOMResourceID:      specification.id + "-spdx",
			ProvenanceResourceID:    specification.id + "-provenance",
			LicenseResourceID:       specification.id + "-license",
			VulnerabilityResourceID: specification.id + "-vulnerability",
		}
		if specification.kind == releaseinventory.ResourceKindLauncher ||
			specification.kind == releaseinventory.ResourceKindHelper ||
			specification.kind == releaseinventory.ResourceKindVerifier {
			input.NativePublisherIdentity = "agentmemory.publisher"
			input.NativePublisherPolicyID = "agentmemory-native-2026"
		}
		if specification.kind == releaseinventory.ResourceKindComposeBundle {
			input.ExpandedTarget = releaseinventory.ReleaseExpandedTargetInput{
				Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
				Digest: digest, Bytes: uint64(len(content)),
			}
		}
		if specification.kind == releaseinventory.ResourceKindOCIImage {
			input.OCIIndexDigest = indexDigest
			input.OCIIndexResourceID = "image-index"
		}
		subject, err := releaseinventory.NewResource(input)
		if err != nil {
			t.Fatalf("create subject %s: %v", specification.id, err)
		}
		resources = append(resources, subject)
		resources = append(resources, releaseEvidenceResources(
			t, subject, licensePolicy, vulnerabilityPolicy, now.Add(24*time.Hour),
		)...)
	}
	protocol, _ := releaseinventory.NewProtocolRange(1, 1)
	version, _ := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{Minimum: "1.0.0", Maximum: "1.0.0"})
	compatibility, _ := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: version, CoreAPI: version, MCP: version, Provider: version, Schema: version,
		Compose: version, SQLite: version, Neo4j: version, RuntimeCatalog: version,
	})
	revocations := []byte("signed revocation set")
	trust, _ := releaseinventory.NewTrustPolicyWithRuntimeRoot(
		releaseinventory.SignatureTrustModeKeyID, "release-root", "runtime-catalog-root",
		releaseinventory.DigestBytes(revocations), "",
	)
	history, _ := releaseinventory.NewReleaseHistory(nil, nil)
	topology, err := releaseinventory.NewDockerTopology(releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{
			ID: "internal", Internal: true,
			Labels: []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}},
		}},
		Volumes: []releaseinventory.DockerVolumeInput{{
			ID: "core-data", Purpose: "canonical-data",
			Labels: []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}},
		}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "core-ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"},
			NetworkIDs:    []string{"internal"},
			VolumeMounts:  []releaseinventory.VolumeMountInput{{VolumeID: "core-data", Target: "/var/lib/agentmemory"}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080}},
			Labels:         []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: 1, ReleaseID: "agentmemory-distribution-1.0.0", Version: "1.0.0",
		BuildID: "build-20260715-1", SourceCommit: string(bytes.Repeat([]byte{'a'}, 40)),
		BuildTimestamp: now.Add(-2 * time.Hour), Channel: releaseinventory.ReleaseChannelStable,
		Sequence: 1, DataGeneration: 1, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
		Protocol: protocol, Compatibility: compatibility, TrustPolicy: trust, ReleaseHistory: history,
		LicensePolicyDigest: licensePolicy, VulnerabilityPolicyDigest: vulnerabilityPolicy,
		DockerTopology: topology, Resources: resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeKeyID, TrustRootID: "release-root",
		Signature:     bytes.Repeat([]byte{0x42}, releaseinventory.ManifestSignatureSize),
		RevocationSet: revocations, TrustedTimeEvidence: []byte("invalid but present trusted time"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := releaseinventory.EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func releaseEvidenceResources(
	t testing.TB,
	subject releaseinventory.Resource,
	licensePolicy releaseinventory.Digest,
	vulnerabilityPolicy releaseinventory.Digest,
	expiresAt time.Time,
) []releaseinventory.Resource {
	t.Helper()
	types := []releaseinventory.ResourceKind{
		releaseinventory.ResourceKindCycloneDXSBOM, releaseinventory.ResourceKindSPDXSBOM,
		releaseinventory.ResourceKindProvenance, releaseinventory.ResourceKindLicense,
		releaseinventory.ResourceKindVulnerabilityReport,
	}
	result := make([]releaseinventory.Resource, 0, len(types))
	for _, kind := range types {
		suffix := map[releaseinventory.ResourceKind]string{
			releaseinventory.ResourceKindCycloneDXSBOM:       "cyclonedx",
			releaseinventory.ResourceKindSPDXSBOM:            "spdx",
			releaseinventory.ResourceKindProvenance:          "provenance",
			releaseinventory.ResourceKindLicense:             "license",
			releaseinventory.ResourceKindVulnerabilityReport: "vulnerability",
		}[kind]
		id := subject.ID() + "-" + suffix
		content := []byte(id + " bytes")
		input := releaseinventory.ResourceInput{
			ID: id, Kind: kind, Purpose: releaseResourcePurpose(kind), MediaType: releaseResourceMediaType(kind),
			Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
			SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
			SubjectResourceID: subject.ID(), SubjectDigest: subject.Digest(),
		}
		if kind == releaseinventory.ResourceKindLicense {
			input.PolicySnapshotDigest = licensePolicy
			input.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = vulnerabilityPolicy
			input.QualificationResult = releaseinventory.QualificationResultPassed
			input.QualificationExpiresAt = expiresAt
		}
		resource, err := releaseinventory.NewResource(input)
		if err != nil {
			t.Fatalf("create evidence %s: %v", id, err)
		}
		result = append(result, resource)
	}
	return result
}

func releaseResourcePurpose(kind releaseinventory.ResourceKind) releaseinventory.ResourcePurpose {
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
		releaseinventory.ResourceKindRuntimeCatalog:      releaseinventory.ResourcePurposeRuntimeCatalog,
		releaseinventory.ResourceKindCycloneDXSBOM:       releaseinventory.ResourcePurposeCycloneDXSBOM,
		releaseinventory.ResourceKindSPDXSBOM:            releaseinventory.ResourcePurposeSPDXSBOM,
		releaseinventory.ResourceKindProvenance:          releaseinventory.ResourcePurposeSLSAProvenance,
		releaseinventory.ResourceKindLicense:             releaseinventory.ResourcePurposeLicenseEvaluation,
		releaseinventory.ResourceKindVulnerabilityReport: releaseinventory.ResourcePurposeVulnerabilityReport,
	}[kind]
}

func releaseResourceMediaType(kind releaseinventory.ResourceKind) string {
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
		releaseinventory.ResourceKindRuntimeCatalog:      releaseinventory.MediaTypeRuntimeCatalog,
		releaseinventory.ResourceKindCycloneDXSBOM:       releaseinventory.MediaTypeCycloneDX,
		releaseinventory.ResourceKindSPDXSBOM:            releaseinventory.MediaTypeSPDX,
		releaseinventory.ResourceKindProvenance:          releaseinventory.MediaTypeSLSAProvenance,
		releaseinventory.ResourceKindLicense:             releaseinventory.MediaTypeLicenseEvaluation,
		releaseinventory.ResourceKindVulnerabilityReport: releaseinventory.MediaTypeVulnerabilityEvaluation,
	}[kind]
}
