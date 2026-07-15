package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001NativeVerifiedDesktopCatalogAuthorityReverifiesSignedCatalogAndHost(t *testing.T) {
	t.Parallel()
	manifestRaw, err := os.ReadFile("testdata/runtime-catalog-macos.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(manifestRaw))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("detached signature"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := runtimecatalog.EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: runtimecatalog.ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30, Virtualization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := &nativeDesktopVerifiedCatalogPorts{
		host: host, now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: ports, Host: ports, Signature: ports, NativePublisher: ports, AntiRollback: ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := application.Verify(t.Context(), runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: manifest.Digest(),
		SourceMode: runtimecatalog.SourceModeOfflineBundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	certified, err := verified.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	hostCapabilities, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "15.5.0",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(hostCapabilities, runtimeinstall.NewAbsentRuntimeDiscovery(), certified)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := runtimecatalogapp.NewDesktopHostBinding(runtimecatalogapp.DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: runtimeinstall.ArchitectureARM64,
		PrincipalID: "uid:501", UserName: "agentmemory", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		HomeDirectory: "/Users/agentmemory",
		ArtifactPath:  "/Users/agentmemory/Library/Caches/AgentMemory/runtime/Docker.dmg",
		Endpoint:      "unix:///Users/agentmemory/.docker/run/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := releaseinventory.NewPlatform("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "runtime-catalog-darwin-arm64", Kind: releaseinventory.ResourceKindRuntimeCatalog,
		Purpose: releaseinventory.ResourcePurposeRuntimeCatalog, MediaType: releaseinventory.MediaTypeRuntimeCatalog,
		Platform: cell, Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)),
		SourceRef: "bundle://runtime-catalog-darwin-arm64", SourceAllowlist: []string{"bundle://runtime-catalog-darwin-arm64"},
		CycloneDXSBOMResourceID: "catalog-cyclonedx", SPDXSBOMResourceID: "catalog-spdx",
		ProvenanceResourceID: "catalog-provenance", LicenseResourceID: "catalog-license",
		VulnerabilityResourceID: "catalog-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	trust := runtimecatalog.DigestBytes([]byte("native certificate"))
	verifier, err := newNativeVerifiedDesktopCatalogAuthority(
		application, &nativeDesktopCatalogHostStub{binding: binding}, &nativeDesktopCatalogTrustStub{digest: trust},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := verifier.VerifyDesktopCatalogAuthority(t.Context(), raw, resource, plan.CanonicalBytes())
	if err != nil || !authority.ValidFor(plan) || authority.Publisher().CertificateSHA256() != runtimeinstall.Hash(trust) {
		t.Fatalf("authority valid=%t certificate=%s error=%v", authority.ValidFor(plan), authority.Publisher().CertificateSHA256(), err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 1
	if authority, verifyError := verifier.VerifyDesktopCatalogAuthority(t.Context(), tampered, resource, plan.CanonicalBytes()); verifyError == nil || authority.Valid() {
		t.Fatalf("tampered catalog valid=%t error=%v", authority.Valid(), verifyError)
	}
	for name, candidate := range map[string]*nativeVerifiedDesktopCatalogAuthority{
		"application": {
			application: &nativeDesktopCatalogApplicationStub{err: errors.New("private")},
			host:        &nativeDesktopCatalogHostStub{binding: binding}, trust: &nativeDesktopCatalogTrustStub{digest: trust},
		},
		"host": {
			application: application, host: &nativeDesktopCatalogHostStub{err: errors.New("private")},
			trust: &nativeDesktopCatalogTrustStub{digest: trust},
		},
		"trust": {
			application: application, host: &nativeDesktopCatalogHostStub{binding: binding},
			trust: &nativeDesktopCatalogTrustStub{err: errors.New("private")},
		},
	} {
		if authority, verifyError := candidate.VerifyDesktopCatalogAuthority(t.Context(), raw, resource, plan.CanonicalBytes()); verifyError == nil || authority.Valid() {
			t.Fatalf("%s authority valid=%t error=%v", name, authority.Valid(), verifyError)
		}
	}
}

func TestPF001NativeDesktopReleaseAuthorityConstructorValidatesCompletePlatformCell(t *testing.T) {
	t.Parallel()
	manifest := releaseinventory.DigestBytes([]byte("release"))
	darwinAuthority := launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)
	darwinCatalog := desktopHelperCatalogResource(t, runtimeinstall.PlatformDarwin, darwinAuthority.Architecture())
	darwinHelper := nativeDesktopHelperResource(t, "darwin", darwinAuthority.Architecture().String())
	darwinCertificates := map[string]releaseinventory.Digest{
		darwinHelper.ID(): releaseinventory.DigestBytes([]byte("helper certificate")),
	}
	darwin, err := newNativeDesktopReleaseAuthority(
		manifest, darwinCatalog, darwinHelper, nil, darwinCertificates,
	)
	if err != nil || !darwin.valid() {
		t.Fatalf("darwin authority valid=%t error=%v", darwin.valid(), err)
	}
	darwinCertificates[darwinHelper.ID()] = releaseinventory.Digest{}
	if !darwin.valid() {
		t.Fatal("authority retained caller-owned certificate bindings")
	}

	windowsAuthority := launcherDesktopAuthority(t, runtimeinstall.PlatformWindows)
	windowsCatalog := desktopHelperCatalogResource(t, runtimeinstall.PlatformWindows, windowsAuthority.Architecture())
	windowsHelper := nativeDesktopHelperResource(t, "windows", windowsAuthority.Architecture().String())
	prerequisites, certificates := desktopHelperPrerequisiteResources(t, windowsAuthority.Architecture(), windowsHelper)
	windows, err := newNativeDesktopReleaseAuthority(
		manifest, windowsCatalog, windowsHelper, prerequisites, certificates,
	)
	if err != nil || !windows.valid() {
		t.Fatalf("windows authority valid=%t error=%v", windows.valid(), err)
	}
	prerequisites[0] = releaseinventory.Resource{}
	if !windows.valid() {
		t.Fatal("authority retained caller-owned prerequisite storage")
	}
	duplicatePrerequisite := windows
	duplicatePrerequisite.prerequisites = []releaseinventory.Resource{
		windows.prerequisites[0], windows.prerequisites[0],
	}
	if duplicatePrerequisite.valid() {
		t.Fatal("duplicate Windows prerequisite accepted")
	}
	missingInstallerCertificate := windows
	missingInstallerCertificate.certificates = copyNativeHelperCertificateBindings(windows.certificates)
	missingInstallerCertificate.certificates[windows.prerequisites[0].ID()] = releaseinventory.Digest{}
	if missingInstallerCertificate.valid() {
		t.Fatal("Windows installer without a publisher certificate accepted")
	}
	foreignPrerequisiteKind := windows
	foreignPrerequisiteKind.prerequisites = []releaseinventory.Resource{windows.helper, windows.prerequisites[1]}
	if foreignPrerequisiteKind.valid() {
		t.Fatal("helper resource accepted as a Windows runtime prerequisite")
	}
	selectedDarwin, err := selectNativeDesktopReleaseAuthority(
		manifest, []releaseinventory.Resource{darwinCatalog, darwinHelper},
		darwinCatalog.ID(), darwinHelper.ID(), darwin.certificates,
		nativeDesktopResourceAuthorizerStub{darwinCatalog.ID(): true, darwinHelper.ID(): true},
	)
	if err != nil || !selectedDarwin.valid() {
		t.Fatalf("selected Darwin authority valid=%t error=%v", selectedDarwin.valid(), err)
	}
	selectedWindows, err := selectNativeDesktopReleaseAuthority(
		manifest, append([]releaseinventory.Resource{windowsCatalog, windowsHelper}, windows.prerequisites...),
		windowsCatalog.ID(), windowsHelper.ID(), windows.certificates,
		nativeDesktopResourceAuthorizerStub{
			windowsCatalog.ID(): true, windowsHelper.ID(): true,
			windows.prerequisites[0].ID(): true, windows.prerequisites[1].ID(): true,
		},
	)
	if err != nil || !selectedWindows.valid() {
		t.Fatalf("selected Windows authority valid=%t error=%v", selectedWindows.valid(), err)
	}
	if selected, selectionError := selectNativeDesktopReleaseAuthority(
		manifest, []releaseinventory.Resource{darwinCatalog, darwinHelper},
		darwinCatalog.ID(), darwinHelper.ID(), darwin.certificates,
		nativeDesktopResourceAuthorizerStub{darwinHelper.ID(): true},
	); selectionError == nil || selected.valid() {
		t.Fatalf("unauthorized catalog valid=%t error=%v", selected.valid(), selectionError)
	}
	for name, resources := range map[string][]releaseinventory.Resource{
		"duplicate catalog": {darwinCatalog, darwinCatalog, darwinHelper},
		"duplicate helper":  {darwinCatalog, darwinHelper, darwinHelper},
	} {
		if selected, selectionError := selectNativeDesktopReleaseAuthority(
			manifest, resources, darwinCatalog.ID(), darwinHelper.ID(), darwin.certificates,
			nativeDesktopResourceAuthorizerStub{darwinCatalog.ID(): true, darwinHelper.ID(): true},
		); selectionError == nil || selected.valid() {
			t.Fatalf("%s valid=%t error=%v", name, selected.valid(), selectionError)
		}
	}
	if selected, selectionError := selectNativeDesktopReleaseAuthority(
		manifest, append([]releaseinventory.Resource{windowsCatalog, windowsHelper}, windows.prerequisites...),
		windowsCatalog.ID(), windowsHelper.ID(), windows.certificates,
		nativeDesktopResourceAuthorizerStub{
			windowsCatalog.ID(): true, windowsHelper.ID(): true, windows.prerequisites[0].ID(): true,
		},
	); selectionError == nil || selected.valid() {
		t.Fatalf("unauthorized Windows prerequisite valid=%t error=%v", selected.valid(), selectionError)
	}

	for name, candidate := range map[string]func() (nativeDesktopReleaseAuthority, error){
		"zero manifest": func() (nativeDesktopReleaseAuthority, error) {
			return newNativeDesktopReleaseAuthority(releaseinventory.Digest{}, darwinCatalog, darwinHelper, nil, darwinCertificates)
		},
		"darwin prerequisites": func() (nativeDesktopReleaseAuthority, error) {
			return newNativeDesktopReleaseAuthority(manifest, darwinCatalog, darwinHelper, windows.prerequisites, windows.certificates)
		},
		"windows prerequisites": func() (nativeDesktopReleaseAuthority, error) {
			return newNativeDesktopReleaseAuthority(manifest, windowsCatalog, windowsHelper, nil, certificates)
		},
		"missing helper certificate": func() (nativeDesktopReleaseAuthority, error) {
			return newNativeDesktopReleaseAuthority(manifest, darwinCatalog, darwinHelper, nil, map[string]releaseinventory.Digest{})
		},
	} {
		if authority, constructError := candidate(); constructError == nil || authority.valid() {
			t.Fatalf("%s authority valid=%t error=%v", name, authority.valid(), constructError)
		}
	}
}

func TestPF001NativeVerifiedDesktopHelperAuthorityAdaptersRejectUnverifiedInputs(t *testing.T) {
	t.Parallel()
	if (nativeVerifiedDesktopResourceAuthorizer{}).Authorizes(releaseinventory.Resource{}) {
		t.Fatal("empty verified inventory authorized a resource")
	}
	certificates := map[string]releaseinventory.Digest{
		"runtime-helper-darwin-arm64": releaseinventory.DigestBytes([]byte("certificate")),
	}
	releases, err := newNativeVerifiedDesktopReleaseAuthority(&nativeDesktopInventoryApplicationStub{}, certificates)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newNativeVerifiedDesktopReleaseAuthority(nil, certificates); err == nil {
		t.Fatal("nil release application accepted")
	}
	if _, err := newNativeVerifiedDesktopReleaseAuthority(&nativeDesktopInventoryApplicationStub{}, nil); err == nil {
		t.Fatal("empty certificate authority accepted")
	}
	if authority, verifyError := releases.VerifyDesktopReleaseAuthority(t.Context(), []byte(`{}`), "catalog", "helper"); verifyError == nil || authority.valid() {
		t.Fatalf("malformed release authority valid=%t error=%v", authority.valid(), verifyError)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, verifyError := releases.VerifyDesktopReleaseAuthority(cancelled, []byte(`{}`), "catalog", "helper"); !errors.Is(verifyError, context.Canceled) {
		t.Fatalf("release cancellation error=%v", verifyError)
	}

	catalogApplication := &nativeDesktopCatalogApplicationStub{}
	host := &nativeDesktopCatalogHostStub{}
	trust := &nativeDesktopCatalogTrustStub{}
	catalogs, err := newNativeVerifiedDesktopCatalogAuthority(catalogApplication, host, trust)
	if err != nil {
		t.Fatal(err)
	}
	for name, construct := range map[string]func() (*nativeVerifiedDesktopCatalogAuthority, error){
		"application": func() (*nativeVerifiedDesktopCatalogAuthority, error) {
			return newNativeVerifiedDesktopCatalogAuthority(nil, host, trust)
		},
		"host": func() (*nativeVerifiedDesktopCatalogAuthority, error) {
			return newNativeVerifiedDesktopCatalogAuthority(catalogApplication, nil, trust)
		},
		"trust": func() (*nativeVerifiedDesktopCatalogAuthority, error) {
			return newNativeVerifiedDesktopCatalogAuthority(catalogApplication, host, nil)
		},
	} {
		if candidate, constructError := construct(); candidate != nil || constructError == nil {
			t.Fatalf("nil %s accepted", name)
		}
	}
	if authority, verifyError := catalogs.VerifyDesktopCatalogAuthority(
		t.Context(), []byte(`{}`), releaseinventory.Resource{}, []byte(`{}`),
	); verifyError == nil || authority.Valid() {
		t.Fatalf("zero catalog resource valid=%t error=%v", authority.Valid(), verifyError)
	}
}

func TestPF001NativeDesktopAuthorityVerifierJoinsReleaseCatalogHostAndSelf(t *testing.T) {
	t.Parallel()
	authority := launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)
	catalog := desktopHelperCatalogResource(t, runtimeinstall.PlatformDarwin, authority.Architecture())
	helper := nativeDesktopHelperResource(t, "darwin", authority.Architecture().String())
	release := &nativeDesktopReleaseAuthorityStub{authority: nativeDesktopReleaseAuthority{
		manifestDigest: releaseinventory.DigestBytes([]byte("release")), catalog: catalog, helper: helper,
		certificates: map[string]releaseinventory.Digest{
			helper.ID(): releaseinventory.DigestBytes([]byte("helper certificate")),
		},
	}}
	catalogs := &nativeDesktopCatalogAuthorityStub{authority: authority}
	self := &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}
	verifier, err := newNativeDesktopMutationAuthorityVerifier(release, catalogs, self)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &nativeDesktopEnvelopeStub{
		release: []byte(`{"signed":"release"}`), catalog: []byte(`{"signed":"catalog"}`),
		plan: []byte(`{"canonical":"plan"}`), catalogID: catalog.ID(), helperID: helper.ID(),
	}
	evidence, err := verifier.VerifyDesktopMutationAuthority(t.Context(), envelope)
	if err != nil || evidence.Authority().Digest() != authority.Digest() ||
		evidence.HelperDigest() != runtimeinstall.Hash(helper.Digest()) ||
		evidence.ReleaseManifestDigest() != runtimeinstall.Hash(release.authority.manifestDigest) ||
		release.calls != 1 || catalogs.calls != 1 || self.calls != 1 ||
		catalogs.resource.ID() != catalog.ID() || self.resource.ID() != helper.ID() {
		t.Fatalf("evidence=%+v error=%v calls=%d/%d/%d", evidence, err, release.calls, catalogs.calls, self.calls)
	}
}

func TestPF001NativeDesktopAuthorityVerifierFailsClosedAtEveryTrustBoundary(t *testing.T) {
	t.Parallel()
	authority := launcherDesktopAuthority(t, runtimeinstall.PlatformWindows)
	catalog := desktopHelperCatalogResource(t, runtimeinstall.PlatformWindows, authority.Architecture())
	helper := nativeDesktopHelperResource(t, "windows", authority.Architecture().String())
	prerequisites, certificates := desktopHelperPrerequisiteResources(t, authority.Architecture(), helper)
	validRelease := nativeDesktopReleaseAuthority{
		manifestDigest: releaseinventory.DigestBytes([]byte("release")), catalog: catalog, helper: helper,
		prerequisites: prerequisites, certificates: certificates,
	}
	validEnvelope := &nativeDesktopEnvelopeStub{
		release: []byte(`{}`), catalog: []byte(`{}`), plan: []byte(`{}`),
		catalogID: catalog.ID(), helperID: helper.ID(),
	}
	private := errors.New("private verifier failure")
	tests := map[string]struct {
		release  nativeDesktopReleaseAuthorityVerifier
		catalog  nativeDesktopCatalogAuthorityVerifier
		self     nativeDesktopHelperSelfVerifier
		envelope runtimeprovision.DesktopMutationRequestEnvelope
	}{
		"release error": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease, err: private},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: authority}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}, envelope: validEnvelope},
		"catalog error": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: authority, err: private}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}, envelope: validEnvelope},
		"self error": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: authority}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest()), err: private}, envelope: validEnvelope},
		"wrong catalog platform": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}, envelope: validEnvelope},
		"wrong helper digest": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: authority}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Sum([]byte("foreign"))}, envelope: validEnvelope},
		"empty envelope": {release: &nativeDesktopReleaseAuthorityStub{authority: validRelease},
			catalog: &nativeDesktopCatalogAuthorityStub{authority: authority}, self: &nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}, envelope: &nativeDesktopEnvelopeStub{}},
	}
	for name, test := range tests {
		verifier, constructError := newNativeDesktopMutationAuthorityVerifier(test.release, test.catalog, test.self)
		if constructError != nil {
			t.Fatalf("%s constructor: %v", name, constructError)
		}
		if evidence, verifyError := verifier.VerifyDesktopMutationAuthority(t.Context(), test.envelope); verifyError == nil ||
			!evidence.HelperDigest().IsZero() || errors.Is(verifyError, private) {
			t.Fatalf("%s evidence=%+v error=%v", name, evidence, verifyError)
		}
	}
	for name, constructor := range map[string]func() (*nativeDesktopMutationAuthorityVerifier, error){
		"release": func() (*nativeDesktopMutationAuthorityVerifier, error) {
			return newNativeDesktopMutationAuthorityVerifier(nil, &nativeDesktopCatalogAuthorityStub{}, &nativeDesktopHelperSelfStub{})
		},
		"catalog": func() (*nativeDesktopMutationAuthorityVerifier, error) {
			return newNativeDesktopMutationAuthorityVerifier(&nativeDesktopReleaseAuthorityStub{}, nil, &nativeDesktopHelperSelfStub{})
		},
		"self": func() (*nativeDesktopMutationAuthorityVerifier, error) {
			return newNativeDesktopMutationAuthorityVerifier(&nativeDesktopReleaseAuthorityStub{}, &nativeDesktopCatalogAuthorityStub{}, nil)
		},
	} {
		if candidate, err := constructor(); candidate != nil || err == nil {
			t.Fatalf("nil %s accepted", name)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	verifier, _ := newNativeDesktopMutationAuthorityVerifier(
		&nativeDesktopReleaseAuthorityStub{authority: validRelease},
		&nativeDesktopCatalogAuthorityStub{authority: authority},
		&nativeDesktopHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())},
	)
	if _, err := verifier.VerifyDesktopMutationAuthority(cancelled, validEnvelope); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func desktopHelperPrerequisiteResources(
	t testing.TB,
	architecture runtimeinstall.Architecture,
	helper releaseinventory.Resource,
) ([]releaseinventory.Resource, map[string]releaseinventory.Digest) {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("windows", architecture.String())
	if err != nil {
		t.Fatal(err)
	}
	newResource := func(
		id string,
		kind releaseinventory.ResourceKind,
		purpose releaseinventory.ResourcePurpose,
		media string,
		path string,
		publisher bool,
	) releaseinventory.Resource {
		input := releaseinventory.ResourceInput{
			ID: id, Kind: kind, Purpose: purpose, MediaType: media, Platform: platform,
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: 4096,
			SourceRef:               "bundle://runtime/windows/" + path,
			SourceAllowlist:         []string{"bundle://runtime/windows/" + path},
			CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
			ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
			VulnerabilityResourceID: id + "-vulnerability",
		}
		if publisher {
			input.NativePublisherIdentity = "microsoft.windows-subsystem-for-linux"
			input.NativePublisherPolicyID = "microsoft-wsl-native-2026"
		}
		resource, err := releaseinventory.NewResource(input)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	installer := newResource(
		"wsl-msi-windows-amd64", releaseinventory.ResourceKindRuntimeInstaller,
		releaseinventory.ResourcePurposeRuntimeInstaller, releaseinventory.MediaTypeRuntimeInstaller,
		"wsl.2.6.3.0.x64.msi", true,
	)
	distribution := newResource(
		"ubuntu-wsl-windows-amd64", releaseinventory.ResourceKindRuntimeDistribution,
		releaseinventory.ResourcePurposeRuntimeDistribution, releaseinventory.MediaTypeRuntimeDistribution,
		"ubuntu-24.04.wsl", false,
	)
	return []releaseinventory.Resource{installer, distribution}, map[string]releaseinventory.Digest{
		helper.ID():    releaseinventory.DigestBytes([]byte("helper certificate")),
		installer.ID(): releaseinventory.DigestBytes([]byte("wsl certificate")),
	}
}

type nativeDesktopReleaseAuthorityStub struct {
	authority nativeDesktopReleaseAuthority
	err       error
	calls     int
}

func (s *nativeDesktopReleaseAuthorityStub) VerifyDesktopReleaseAuthority(
	context.Context, []byte, string, string,
) (nativeDesktopReleaseAuthority, error) {
	s.calls++
	return s.authority, s.err
}

type nativeDesktopCatalogAuthorityStub struct {
	authority runtimeport.DesktopAuthority
	resource  releaseinventory.Resource
	err       error
	calls     int
}

func (s *nativeDesktopCatalogAuthorityStub) VerifyDesktopCatalogAuthority(
	_ context.Context,
	_ []byte,
	resource releaseinventory.Resource,
	_ []byte,
) (runtimeport.DesktopAuthority, error) {
	s.calls++
	s.resource = resource
	return s.authority, s.err
}

type nativeDesktopHelperSelfStub struct {
	digest   runtimeinstall.Hash
	resource releaseinventory.Resource
	err      error
	calls    int
}

type nativeDesktopInventoryApplicationStub struct {
	inventory appreleaseverify.VerifiedInventory
	err       error
}

type nativeDesktopResourceAuthorizerStub map[string]bool

func (s nativeDesktopResourceAuthorizerStub) Authorizes(resource releaseinventory.Resource) bool {
	return s[resource.ID()]
}

func (s *nativeDesktopInventoryApplicationStub) Verify(
	context.Context,
	releaseinventory.SignedManifest,
) (appreleaseverify.VerifiedInventory, error) {
	return s.inventory, s.err
}

type nativeDesktopCatalogApplicationStub struct {
	catalog runtimecatalogapp.VerifiedCatalog
	err     error
}

func (s *nativeDesktopCatalogApplicationStub) Verify(
	context.Context,
	runtimecatalogapp.Request,
) (runtimecatalogapp.VerifiedCatalog, error) {
	return s.catalog, s.err
}

type nativeDesktopCatalogHostStub struct {
	binding runtimecatalogapp.DesktopHostBinding
	err     error
}

func (s *nativeDesktopCatalogHostStub) CurrentDesktopHostBinding(
	context.Context,
	runtimecatalog.Digest,
	string,
) (runtimecatalogapp.DesktopHostBinding, error) {
	return s.binding, s.err
}

type nativeDesktopCatalogTrustStub struct {
	digest runtimecatalog.Digest
	err    error
}

func (s *nativeDesktopCatalogTrustStub) NativeTrustDigest(
	runtimecatalog.PublisherPolicy,
) (runtimecatalog.Digest, error) {
	return s.digest, s.err
}

type nativeDesktopVerifiedCatalogPorts struct {
	host runtimecatalog.Host
	now  time.Time
}

func (p *nativeDesktopVerifiedCatalogPorts) Now() time.Time { return p.now }

func (p *nativeDesktopVerifiedCatalogPorts) CurrentHost(context.Context) (runtimecatalog.Host, error) {
	return p.host, nil
}

func (*nativeDesktopVerifiedCatalogPorts) VerifyManifestSignature(
	context.Context,
	runtimecatalog.SignedManifest,
) error {
	return nil
}

func (*nativeDesktopVerifiedCatalogPorts) VerifyNativePublisherPolicy(
	context.Context,
	runtimecatalog.PublisherPolicy,
) error {
	return nil
}

func (*nativeDesktopVerifiedCatalogPorts) LoadCatalogAnchor(
	context.Context,
	string,
) (runtimecatalogapp.CatalogAnchor, error) {
	return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorNotFound
}

func (*nativeDesktopVerifiedCatalogPorts) CompareAndSwapCatalogAnchor(
	context.Context,
	*runtimecatalogapp.CatalogAnchor,
	runtimecatalogapp.CatalogAnchor,
) error {
	return nil
}

func (s *nativeDesktopHelperSelfStub) VerifyDesktopHelperSelf(
	_ context.Context,
	resource releaseinventory.Resource,
	_ runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	s.calls++
	s.resource = resource
	return s.digest, s.err
}

type nativeDesktopEnvelopeStub struct {
	release, catalog, plan []byte
	catalogID, helperID    string
}

func (*nativeDesktopEnvelopeStub) BindAuthority(runtimeport.DesktopAuthority) (runtimeport.DesktopMutationRequest, error) {
	return runtimeport.DesktopMutationRequest{}, nil
}
func (*nativeDesktopEnvelopeStub) Artifact() (runtimeprovision.DesktopMutationArtifactBinding, bool) {
	return runtimeprovision.DesktopMutationArtifactBinding{}, false
}
func (s *nativeDesktopEnvelopeStub) SignedRelease() []byte { return append([]byte(nil), s.release...) }
func (s *nativeDesktopEnvelopeStub) SignedRuntimeCatalog() []byte {
	return append([]byte(nil), s.catalog...)
}
func (s *nativeDesktopEnvelopeStub) CanonicalPlan() []byte            { return append([]byte(nil), s.plan...) }
func (s *nativeDesktopEnvelopeStub) RuntimeCatalogResourceID() string { return s.catalogID }
func (s *nativeDesktopEnvelopeStub) HelperResourceID() string         { return s.helperID }

func desktopHelperCatalogResource(
	t testing.TB,
	platform runtimeinstall.Platform,
	architecture runtimeinstall.Architecture,
) releaseinventory.Resource {
	t.Helper()
	cell, err := releaseinventory.NewPlatform(platform.String(), architecture.String())
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "desktop-runtime-catalog-" + platform.String(), Kind: releaseinventory.ResourceKindRuntimeCatalog,
		Purpose: releaseinventory.ResourcePurposeRuntimeCatalog, MediaType: releaseinventory.MediaTypeRuntimeCatalog,
		Platform: cell, Digest: releaseinventory.DigestBytes([]byte("catalog-" + platform.String())), Size: 1024,
		SourceRef: "bundle://desktop-runtime-catalog", SourceAllowlist: []string{"bundle://desktop-runtime-catalog"},
		CycloneDXSBOMResourceID: "catalog-cyclonedx", SPDXSBOMResourceID: "catalog-spdx",
		ProvenanceResourceID: "catalog-provenance", LicenseResourceID: "catalog-license",
		VulnerabilityResourceID: "catalog-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
