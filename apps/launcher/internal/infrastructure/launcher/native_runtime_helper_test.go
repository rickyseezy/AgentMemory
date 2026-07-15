package launcher

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001NativeDesktopHelperTrustProjectsExactVerifiedReleaseResource(t *testing.T) {
	t.Parallel()
	manifest := releaseinventory.DigestBytes([]byte("signed release manifest"))
	verifier := &nativeDesktopHelperReleaseStub{}
	resources := []releaseinventory.Resource{
		nativeDesktopHelperResource(t, "darwin", "arm64"),
		nativeDesktopHelperResource(t, "windows", "amd64"),
	}
	certificates := nativeDesktopHelperCertificates(resources)
	resolver, err := newNativeDesktopHelperAuthorityResolver(
		verifier, releaseinventory.SignedManifest{}, manifest, certificates, resources,
	)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &nativeDesktopHelperPublisherVerifier{resolver: resolver}
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		desktop := launcherDesktopAuthority(t, platform)
		resource, resourceError := resolver.helperFor(platform, desktop.Architecture())
		helper, err := resolver.ResolveDesktopHelperAuthority(t.Context(), desktop)
		if resourceError != nil || err != nil || !helper.ValidFor(desktop) ||
			helper.ReleaseManifestDigest() != runtimeinstall.Hash(manifest) ||
			helper.PublisherCertificate() != runtimeinstall.Hash(certificates[resource.ID()]) ||
			helper.SHA256() != runtimeinstall.Sum([]byte("helper-"+platform.String())) {
			t.Fatalf("platform=%s helper=%+v error=%v", platform, helper, err)
		}
		if err := publisher.VerifyDesktopHelperPublisher(t.Context(), helper); err != nil {
			t.Fatalf("platform=%s publisher error=%v", platform, err)
		}
		if platform == runtimeinstall.PlatformDarwin && helper.CanonicalPath() !=
			"/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper" {
			t.Fatalf("Darwin helper path=%q", helper.CanonicalPath())
		}
		if platform == runtimeinstall.PlatformWindows && helper.CanonicalPath() !=
			`C:\Program Files\AgentMemory\bin\agentmemory-runtime-helper.exe` {
			t.Fatalf("Windows helper path=%q", helper.CanonicalPath())
		}
	}
	if verifier.calls != 4 {
		t.Fatalf("release verification calls=%d", verifier.calls)
	}
}

func TestPF001NativeDesktopHelperTrustFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	resource := nativeDesktopHelperResource(t, "darwin", "arm64")
	manifest := releaseinventory.DigestBytes([]byte("signed release manifest"))
	certificate := releaseinventory.DigestBytes([]byte("helper signer certificate"))
	certificates := map[string]releaseinventory.Digest{resource.ID(): certificate}
	verifier := &nativeDesktopHelperReleaseStub{}
	for name, test := range map[string]struct {
		verifier     nativeDesktopHelperReleaseVerifier
		manifest     releaseinventory.Digest
		certificates map[string]releaseinventory.Digest
		resources    []releaseinventory.Resource
	}{
		"nil verifier":     {manifest: manifest, certificates: certificates, resources: []releaseinventory.Resource{resource}},
		"zero manifest":    {verifier: verifier, certificates: certificates, resources: []releaseinventory.Resource{resource}},
		"zero certificate": {verifier: verifier, manifest: manifest, certificates: map[string]releaseinventory.Digest{resource.ID(): {}}, resources: []releaseinventory.Resource{resource}},
		"no helper":        {verifier: verifier, manifest: manifest, certificates: certificates},
		"duplicate helper": {verifier: verifier, manifest: manifest, certificates: certificates,
			resources: []releaseinventory.Resource{resource, resource}},
	} {
		resolver, err := newNativeDesktopHelperAuthorityResolver(
			test.verifier, releaseinventory.SignedManifest{}, test.manifest, test.certificates, test.resources,
		)
		if name == "duplicate helper" {
			if err != nil {
				t.Fatalf("duplicate is rejected during selection, not construction: %v", err)
			}
			if _, err := resolver.ResolveDesktopHelperAuthority(t.Context(), launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)); err == nil {
				t.Fatal("duplicate helper selection accepted")
			}
			continue
		}
		if resolver != nil || err == nil {
			t.Fatalf("%s resolver=%v error=%v", name, resolver, err)
		}
	}
	resolver, err := newNativeDesktopHelperAuthorityResolver(
		verifier, releaseinventory.SignedManifest{}, manifest, certificates, []releaseinventory.Resource{resource},
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier.err = errors.New("private release failure")
	if _, err := resolver.ResolveDesktopHelperAuthority(t.Context(), launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)); !errors.Is(err, runtimeport.ErrDesktopMutationUnavailable) {
		t.Fatalf("release failure error=%v", err)
	}
	verifier.err = nil
	if _, err := resolver.ResolveDesktopHelperAuthority(t.Context(), launcherDesktopAuthority(t, runtimeinstall.PlatformWindows)); err == nil {
		t.Fatal("missing Windows helper accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.ResolveDesktopHelperAuthority(cancelled, launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolver error=%v", err)
	}
	if _, _, err := newNativeDesktopHelperTrust(nil, releaseinventory.SignedManifest{}); err == nil {
		t.Fatal("nil release trust accepted")
	}
	if err := (*nativeDesktopHelperPublisherVerifier)(nil).VerifyDesktopHelperPublisher(t.Context(), runtimeport.DesktopHelperAuthority{}); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil publisher error=%v", err)
	}
}

type nativeDesktopHelperReleaseStub struct {
	calls int
	err   error
}

func (s *nativeDesktopHelperReleaseStub) VerifyReleaseResource(
	context.Context,
	releaseinventory.SignedManifest,
	releaseinventory.Resource,
) error {
	s.calls++
	return s.err
}

func nativeDesktopHelperResource(t testing.TB, operatingSystem, architecture string) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform(operatingSystem, architecture)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID:   "runtime-helper-" + operatingSystem + "-" + architecture,
		Kind: releaseinventory.ResourceKindHelper, Purpose: releaseinventory.ResourcePurposeNativeHelper,
		MediaType: releaseinventory.MediaTypeNativeExecutable, Platform: platform,
		Digest: releaseinventory.DigestBytes([]byte("helper-" + operatingSystem)), Size: 4096,
		SourceRef:               "bundle://runtime-helper-" + operatingSystem,
		SourceAllowlist:         []string{"bundle://runtime-helper-" + operatingSystem},
		CycloneDXSBOMResourceID: "helper-cyclonedx", SPDXSBOMResourceID: "helper-spdx",
		ProvenanceResourceID: "helper-provenance", LicenseResourceID: "helper-license",
		VulnerabilityResourceID: "helper-vulnerability", NativePublisherIdentity: "agentmemory.publisher",
		NativePublisherPolicyID: "agentmemory-native-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func nativeDesktopHelperCertificates(resources []releaseinventory.Resource) map[string]releaseinventory.Digest {
	result := make(map[string]releaseinventory.Digest, len(resources))
	for _, resource := range resources {
		result[resource.ID()] = releaseinventory.DigestBytes([]byte("certificate-" + resource.ID()))
	}
	return result
}

func launcherDesktopAuthority(t testing.TB, platform runtimeinstall.Platform) runtimeport.DesktopAuthority {
	t.Helper()
	architecture := runtimeinstall.ArchitectureARM64
	input := runtimeport.DesktopAuthorityInput{
		PlanDigest:    runtimeinstall.Sum([]byte("desktop-plan-" + platform.String())),
		CatalogDigest: runtimeinstall.Sum([]byte("desktop-catalog-" + platform.String())),
		Platform:      platform, Architecture: architecture, PrincipalID: "uid:501", UserName: "agentmemory",
		MachineDigest: runtimeinstall.Sum([]byte("desktop-machine")), HomeDirectory: "/Users/agentmemory",
		OSProduct: "macos", MinimumOSVersion: "15.0", MaximumOSVersion: "15.9.9",
		MinimumBuild: 24_000, MaximumBuild: 24_999, MinimumCPUs: 4,
		MinimumTotalMemory: 16 << 30, MinimumAvailableMemory: 8 << 30, MinimumFreeDisk: 30 << 30,
		RuntimeVersion: "4.70.0", EngineVersion: "29.6.1", ComposeVersion: "5.1.4",
		Endpoint:       "unix:///Users/agentmemory/.docker/run/docker.sock",
		ArtifactPath:   "/Users/agentmemory/Library/Caches/AgentMemory/runtime/Docker.dmg",
		ArtifactSHA256: runtimeinstall.Sum([]byte("desktop artifact")), ArtifactBytes: 500 << 20,
		ArtifactSourceURL: "https://desktop.docker.com/mac/main/arm64/Docker.dmg",
		Publisher: runtimeport.DesktopPublisherInput{
			Kind:               runtimeport.DesktopPublisherAppleNotarized,
			Identity:           "developer-id-application-docker-inc-9bnsxjn65r",
			SigningKeyIdentity: "apple-developer-id-9bnsxjn65r", PackageIdentity: "com.docker.docker",
			CertificateSHA256: runtimeinstall.Sum([]byte("docker certificate")),
		},
		Terms: runtimeport.DesktopTermsInput{
			ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
			Digest: runtimeinstall.Sum([]byte("desktop terms")),
		},
		InstallerArguments:    []string{"--accept-license", "--user=agentmemory"},
		ApplicationPath:       "/Applications/Docker.app",
		ApplicationExecutable: "/Applications/Docker.app/Contents/MacOS/Docker Desktop",
		DockerCLIPath:         "/Applications/Docker.app/Contents/Resources/bin/docker",
		ComposePluginPath:     "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
		DockerCLISHA256:       runtimeinstall.Sum([]byte("desktop docker cli")),
		ComposePluginSHA256:   runtimeinstall.Sum([]byte("desktop compose plugin")),
		ProbeImage:            "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + runtimeinstall.Sum([]byte("probe")).String(),
		ProbeImageDigest:      runtimeinstall.Sum([]byte("probe")), ProbeContractVersion: "1",
		CapabilityPolicyDigest: runtimeinstall.Sum([]byte("capability")),
	}
	if platform == runtimeinstall.PlatformWindows {
		input.Architecture = runtimeinstall.ArchitectureAMD64
		input.PrincipalID, input.UserName = "sid:S-1-5-21-1000-1001-1002-1003", "Agent User"
		input.HomeDirectory, input.OSProduct = `C:\Users\Agent User`, "windows-11"
		input.MinimumOSVersion, input.MaximumOSVersion = "10.0.0", "10.0.0"
		input.MinimumBuild, input.MaximumBuild = 22_631, 26_199
		input.Endpoint = "npipe:////./pipe/docker_engine"
		input.ArtifactPath = `C:\Users\Agent User\AppData\Local\AgentMemory\runtime\Docker Desktop Installer.exe`
		input.ArtifactSourceURL = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
		input.Publisher = runtimeport.DesktopPublisherInput{Kind: runtimeport.DesktopPublisherAuthenticode,
			Identity: "microsoft-authenticode-docker-inc", SigningKeyIdentity: "docker-authenticode-2026",
			PackageIdentity: "com.docker.docker", CertificateSHA256: runtimeinstall.Sum([]byte("docker certificate"))}
		input.InstallerArguments = []string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"}
		root := input.HomeDirectory + `\AppData\Local\Programs\DockerDesktop`
		input.ApplicationPath, input.ApplicationExecutable = root, root+`\Docker Desktop.exe`
		input.DockerCLIPath, input.ComposePluginPath = root+`\resources\bin\docker.exe`, root+`\resources\cli-plugins\docker-compose.exe`
		input.RebootExitCodes = []uint32{1641, 3010}
		input.WindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}
		input.MinimumWSLVersion = "2.1.5"
	}
	authority, err := runtimeport.NewDesktopAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
