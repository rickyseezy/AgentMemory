package runtimecatalog

import "testing"

func TestDesktopExecutionPolicyRoundTripsCompleteSignedAuthority(t *testing.T) {
	t.Parallel()
	manifest := mustManifest(t, validManifestInput(t))
	policy, present := manifest.DesktopExecution()
	if !present || policy.MinimumAvailableMemory() != 4_000_000_000 ||
		policy.ArtifactFileName() != "Docker.dmg" || policy.ProbeContractVersion() != "1" ||
		policy.DockerCLISHA256().IsZero() || policy.ComposePluginSHA256().IsZero() ||
		policy.ProbeImageDigest().IsZero() || policy.CapabilityPolicyDigest().IsZero() ||
		policy.MinimumWSLVersion() != "" {
		t.Fatalf("desktop policy=%+v present=%t", policy, present)
	}
	encoded, err := EncodeManifestV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifestV1(encoded)
	decodedPolicy, decodedPresent := decoded.DesktopExecution()
	if err != nil || !decodedPresent || !decoded.Digest().Equal(manifest.Digest()) ||
		decodedPolicy.ProbeImage() != policy.ProbeImage() ||
		decodedPolicy.ArtifactFileName() != policy.ArtifactFileName() ||
		!decodedPolicy.DockerCLISHA256().Equal(policy.DockerCLISHA256()) ||
		!decodedPolicy.ComposePluginSHA256().Equal(policy.ComposePluginSHA256()) ||
		len(decodedPolicy.WindowsFeatures()) != len(policy.WindowsFeatures()) {
		t.Fatalf("decoded policy=%+v present=%t error=%v", decodedPolicy, decodedPresent, err)
	}
}

func TestDesktopExecutionPolicyRejectsEveryUnsignedOrCrossPlatformBoundary(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*ManifestInput){
		"memory": func(value *ManifestInput) { value.DesktopExecution.MinimumAvailableMemory = 0 },
		"memory above total": func(value *ManifestInput) {
			value.DesktopExecution.MinimumAvailableMemory = value.Platform.MinimumMemoryBytes + 1
		},
		"artifact":           func(value *ManifestInput) { value.DesktopExecution.ArtifactFileName = "Docker.exe" },
		"artifact traversal": func(value *ManifestInput) { value.DesktopExecution.ArtifactFileName = "../Docker.dmg" },
		"docker cli digest":  func(value *ManifestInput) { value.DesktopExecution.DockerCLISHA256 = Digest{} },
		"compose digest":     func(value *ManifestInput) { value.DesktopExecution.ComposePluginSHA256 = Digest{} },
		"aliased tools": func(value *ManifestInput) {
			value.DesktopExecution.ComposePluginSHA256 = value.DesktopExecution.DockerCLISHA256
		},
		"probe tag": func(value *ManifestInput) {
			value.DesktopExecution.ProbeImage = "docker.io/rickyseezy/agentmemory-runtime-probe:latest"
		},
		"probe digest":   func(value *ManifestInput) { value.DesktopExecution.ProbeImageDigest = Digest{} },
		"probe contract": func(value *ManifestInput) { value.DesktopExecution.ProbeContractVersion = "2" },
		"capabilities": func(value *ManifestInput) {
			value.DesktopExecution.CapabilityPolicyDigest = DigestBytes([]byte("foreign"))
		},
		"multiple sources": func(value *ManifestInput) {
			value.Artifact.Sources = append(value.Artifact.Sources, OfficialSourceInput{
				Scheme: "https", Host: "desktop.docker.com", PathPrefix: "/mac/main/arm64-secondary/",
			})
		},
		"mac wsl": func(value *ManifestInput) { value.DesktopExecution.MinimumWSLVersion = "2.1.5" },
		"mac wsl distribution": func(value *ManifestInput) {
			value.DesktopExecution.WSLDistributionName = "Ubuntu-24.04"
		},
	} {
		candidate := validManifestInput(t)
		mutate(&candidate)
		if manifest, err := NewManifest(candidate); err == nil || manifest.Valid() {
			t.Fatalf("%s accepted", name)
		}
	}
	linux := validManifestInput(t)
	linux.Platform.OperatingSystem = OSKindLinux
	linux.Platform.Architecture = ArchitectureX8664
	linux.Platform.Edition = "workstation"
	linux.Platform.Distribution = "ubuntu"
	linux.Runtime.Product = RuntimeProductDockerEngine
	linux.Runtime.Components = append(linux.Runtime.Components, RuntimeComponentInput{Name: ComponentRootlessExtras, Version: "28.3.2"})
	linux.Artifact = linuxArtifactPolicyInput(t)
	linux.LinuxExecution = linuxExecutionPolicyInput(t, linux.Artifact)
	linux.Install.Executable = InstallerExecutableRootlessSetup
	linux.Install.ServiceIdentity = "docker.service"
	linux.Install.OwnershipChanges = []string{"repository:docker-stable", "service:docker.service"}
	linux.Prerequisites = []PrerequisiteInput{
		{Operation: PrerequisiteConfigureOfficialRepository, RepositoryID: "docker-stable"},
		{Operation: PrerequisiteConfigureSubordinateIDs, SubordinateIDCount: 65536},
		{Operation: PrerequisiteEnableUserService, ServiceID: "docker.service"},
		{Operation: PrerequisiteInstallVerifiedPackage, PackageIDs: []string{
			"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli",
			"docker-ce-rootless-extras", "docker-compose-plugin", "uidmap",
		}},
	}
	linux.CapabilityProbes = linuxCapabilities()
	linux.Terms.Presentation = TermsPresentationAgentMemory
	if manifest, err := NewManifest(linux); err == nil || manifest.Valid() {
		t.Fatal("Linux cell accepted desktop execution authority")
	}
}

func TestDesktopExecutionPolicyBindsExactOfflineWSLDistribution(t *testing.T) {
	t.Parallel()
	windows := validManifestInput(t)
	windows.CatalogID = "docker-desktop-windows-x86-64"
	windows.Platform.OperatingSystem = OSKindWindows
	windows.Platform.Architecture = ArchitectureX8664
	windows.Platform.Distribution = "windows"
	windows.Artifact.Publisher.Verification = NativeVerificationAuthenticode
	windows.Artifact.Publisher.Identity = "microsoft-authenticode-docker-inc"
	windows.Artifact.Publisher.SigningKeyIdentity = "docker-authenticode-2026"
	windows.Install.Executable = InstallerExecutableWindowsHelper
	windows.Install.RebootExitCodes = []uint32{1641, 3010}
	windows.Artifact.Sources[0] = OfficialSourceInput{
		Scheme: "https", Host: "desktop.docker.com", PathPrefix: "/win/main/amd64/",
	}
	windows.DesktopExecution.ArtifactFileName = "Docker Desktop Installer.exe"
	windows.DesktopExecution.MinimumWSLVersion = "2.1.5"
	windows.DesktopExecution.WSLDistributionName = "Ubuntu-24.04"
	windows.DesktopExecution.WindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}

	manifest := mustManifest(t, windows)
	policy, present := manifest.DesktopExecution()
	if !present || policy.WSLDistributionName() != "Ubuntu-24.04" {
		t.Fatalf("desktop execution policy=%+v present=%t", policy, present)
	}
	encoded, err := EncodeManifestV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifestV1(encoded)
	decodedPolicy, present := decoded.DesktopExecution()
	if err != nil || !present || decodedPolicy.WSLDistributionName() != "Ubuntu-24.04" ||
		!decoded.Digest().Equal(manifest.Digest()) {
		t.Fatalf("decoded policy=%+v present=%t error=%v", decodedPolicy, present, err)
	}
	for _, value := range []string{"", "ubuntu-24.04", "Ubuntu Latest", "../Ubuntu-24.04"} {
		candidate := windows
		candidate.DesktopExecution.WSLDistributionName = value
		if manifest, err := NewManifest(candidate); err == nil || manifest.Valid() {
			t.Fatalf("unsafe WSL distribution %q accepted", value)
		}
	}
}

func TestDesktopManifestRequiresLauncherTermsDecisionBeforeAcceptLicense(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*ManifestInput){
		"mandatory vendor UI": func(value *ManifestInput) {
			value.Install.VendorUIMandatory = true
		},
		"native-only terms": func(value *ManifestInput) {
			value.Terms.Presentation = TermsPresentationNative
		},
		"duplicated launcher and vendor terms": func(value *ManifestInput) {
			value.Terms.Presentation = TermsPresentationAgentMemoryThenNative
		},
	} {
		candidate := validManifestInput(t)
		mutate(&candidate)
		if manifest, err := NewManifest(candidate); err == nil || manifest.Valid() {
			t.Fatalf("%s accepted", name)
		}
	}
}
