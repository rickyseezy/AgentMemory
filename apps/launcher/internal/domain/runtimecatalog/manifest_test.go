package runtimecatalog

import (
	"errors"
	"testing"
	"time"
)

func TestNewManifestBuildsCompleteImmutableCatalogCell(t *testing.T) {
	t.Parallel()

	input := validManifestInput(t)
	manifest, err := NewManifest(input)
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}

	if manifest.SchemaVersion() != SupportedSchemaVersion || manifest.CatalogID() != "docker-desktop-macos-arm64" {
		t.Fatalf("manifest identity = (%d, %q)", manifest.SchemaVersion(), manifest.CatalogID())
	}
	if manifest.CatalogSequence() != 42 ||
		manifest.SigningKeyID() != "agentmemory-runtime-root-2026" {
		t.Fatalf("manifest signing identity = (%d, %q)", manifest.CatalogSequence(), manifest.SigningKeyID())
	}
	if manifest.Runtime().ComposeVersion() != "2.39.1" || manifest.Runtime().Components()[0].Version() != "28.3.2" {
		t.Fatalf("runtime version projection is incomplete")
	}
	if manifest.Artifact().DownloadBytes() != 700_000_000 || manifest.Artifact().SHA256().IsZero() {
		t.Fatalf("artifact projection is incomplete")
	}
	if manifest.Terms().ID() != "docker-subscription-service-agreement" || manifest.Terms().URL().Host() != "www.docker.com" {
		t.Fatalf("terms projection is incomplete")
	}
	if manifest.Digest().IsZero() || len(manifest.CanonicalBytes()) == 0 {
		t.Fatalf("manifest canonical identity is empty")
	}

	components := manifest.Runtime().Components()
	components[0] = RuntimeComponent{}
	if manifest.Runtime().Components()[0].Name() != ComponentEngine {
		t.Fatal("runtime components leaked mutable storage")
	}
	bytes := manifest.CanonicalBytes()
	bytes[0] = '['
	if manifest.CanonicalBytes()[0] != '{' {
		t.Fatal("canonical bytes leaked mutable storage")
	}
}

func TestManifestAuthorizesOnlyClosedSourcesAndOfflinePolicy(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validManifestInput(t))
	official := mustSource(t, "https", "desktop.docker.com", "/mac/main/arm64/")
	unofficial := mustSource(t, "https", "mirror.example.com", "/docker/")

	tests := []struct {
		name   string
		mode   SourceMode
		source *SourceLocation
		want   error
	}{
		{name: "online exact official prefix", mode: SourceModeOnline, source: &official},
		{name: "online missing source", mode: SourceModeOnline, want: ErrSourceDenied},
		{name: "online unofficial", mode: SourceModeOnline, source: &unofficial, want: ErrSourceDenied},
		{name: "offline bundle allowed", mode: SourceModeOfflineBundle},
		{name: "offline selected artifact disallowed by bundle-only policy", mode: SourceModeOfflineUserSelected, want: ErrSourceDenied},
		{name: "unknown mode", mode: SourceModeUnknown, want: ErrSourceDenied},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := manifest.AuthorizeSource(test.mode, test.source)
			if !errors.Is(err, test.want) {
				t.Fatalf("AuthorizeSource() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestManifestAuthorizesUserSelectedOfflineArtifactOnlyWhenRedistributionIsDenied(t *testing.T) {
	t.Parallel()

	input := validManifestInput(t)
	input.Artifact.OfflinePolicy = OfflinePolicyUserSelectedOfficial
	input.Artifact.RedistributionPermitted = false
	manifest := mustManifest(t, input)
	if err := manifest.AuthorizeSource(SourceModeOfflineUserSelected, nil); err != nil {
		t.Fatalf("AuthorizeSource(user-selected official) error = %v", err)
	}
	if !errors.Is(manifest.AuthorizeSource(SourceModeOfflineBundle, nil), ErrSourceDenied) {
		t.Fatal("non-redistributable artifact was authorized for offline bundling")
	}
}

func TestManifestProjectsEverySignedExecutionBoundaryDefensively(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validManifestInput(t))
	platform := manifest.Platform()
	if platform.OperatingSystem() != OSKindMacOS || platform.Architecture() != ArchitectureARM64 ||
		platform.Edition() != "desktop" || platform.Distribution() != "macos" ||
		platform.MinimumOSVersion() != "14.0.0" || platform.MaximumOSVersion() != "15.9.9" ||
		platform.MinimumBuild() != 23000 || platform.MaximumBuild() != 25000 ||
		platform.MinimumCPUCores() != 4 || platform.MinimumMemoryBytes() != 8_589_934_592 ||
		platform.MinimumFreeDiskBytes() != 32_212_254_720 || !platform.VirtualizationRequired() {
		t.Fatal("platform projection omitted a signed boundary")
	}
	host := mustHost(t, HostInput{
		OperatingSystem: OSKindMacOS, Architecture: ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 16_000_000_000, FreeDiskBytes: 100_000_000_000, Virtualization: true,
	})
	if host.OperatingSystem() != OSKindMacOS || host.Architecture() != ArchitectureARM64 ||
		host.OSVersion() != "15.5.0" || host.Build() != 24000 {
		t.Fatal("host projection omitted an identity boundary")
	}

	runtimePolicy := manifest.Runtime()
	if runtimePolicy.Product() != RuntimeProductDockerDesktop || runtimePolicy.Channel() != StableChannel ||
		runtimePolicy.Version() != "28.3.2" {
		t.Fatal("runtime projection omitted an exact version boundary")
	}
	compose, err := runtimePolicy.RuntimeComponentFor(ComponentCompose)
	if err != nil || compose.Version() != "2.39.1" {
		t.Fatalf("RuntimeComponentFor(compose) = (%v, %v)", compose, err)
	}
	if _, err := runtimePolicy.RuntimeComponentFor(ComponentRootlessExtras); err == nil {
		t.Fatal("undeclared component was returned")
	}

	artifact := manifest.Artifact()
	if artifact.ExpandedBytes() != 2_000_000_000 || artifact.ReserveBytes() != 3_000_000_000 ||
		artifact.ProxyMode() != ProxyModeSystem || artifact.OfflinePolicy() != OfflinePolicyBundled ||
		!artifact.RedistributionPermitted() || len(artifact.Sources()) != 1 {
		t.Fatal("artifact projection omitted an acquisition boundary")
	}
	publisher := artifact.Publisher()
	if publisher.Verification() != NativeVerificationAppleNotarized ||
		publisher.Identity() != "developer-id-application-docker-inc-9bnsxjn65r" ||
		publisher.SigningKeyIdentity() != "apple-developer-id-9bnsxjn65r" ||
		publisher.PackageIdentity() != "com.docker.docker" || !publisher.valid(OSKindMacOS) {
		t.Fatal("publisher projection omitted a trust boundary")
	}
	source := artifact.Sources()[0]
	if source.Scheme() != "https" || source.Host() != "desktop.docker.com" ||
		source.PathPrefix() != "/mac/main/arm64/" {
		t.Fatal("source projection omitted an allowlist boundary")
	}

	install := manifest.Install()
	if install.Executable() != InstallerExecutableMacOSInstaller ||
		install.ServiceIdentity() != "com.docker.backend" ||
		install.RollbackStrategy() != RollbackStrategyPreserve || install.VendorUIMandatory() ||
		len(install.RebootExitCodes()) != 0 || len(install.OwnershipChanges()) != 2 {
		t.Fatal("installer projection omitted an execution boundary")
	}
	arguments := install.Arguments()
	if arguments[0].Kind() != ArgumentKindLiteral || arguments[0].Value() != "install" ||
		arguments[1].Kind() != ArgumentKindArtifactPath || arguments[1].Value() != "" {
		t.Fatal("argument template projection is incomplete")
	}
	arguments[0] = ArgumentTemplate{}
	if install.Arguments()[0].Kind() != ArgumentKindLiteral {
		t.Fatal("argument template leaked mutable storage")
	}
	ownership := install.OwnershipChanges()
	ownership[0] = "changed:value"
	if install.OwnershipChanges()[0] != "application:com.docker.docker" {
		t.Fatal("ownership projection leaked mutable storage")
	}

	prerequisites := manifest.Prerequisites()
	if prerequisites[0].Operation() != PrerequisiteInstallVerifiedPackage ||
		prerequisites[0].FeatureID() != "" || prerequisites[0].RepositoryID() != "" ||
		prerequisites[0].ServiceID() != "" || prerequisites[0].SubordinateIDCount() != 0 ||
		len(prerequisites[0].PackageIDs()) != 1 {
		t.Fatal("typed prerequisite projection is incomplete")
	}
	packages := prerequisites[0].PackageIDs()
	packages[0] = "changed"
	if prerequisites[0].PackageIDs()[0] != "com.docker.docker" {
		t.Fatal("prerequisite packages leaked mutable storage")
	}
	capabilities := manifest.CapabilityProbes()
	capabilities[0] = CapabilityCloudOffloadOff
	if manifest.CapabilityProbes()[0] != CapabilityBindReadOnly {
		t.Fatal("capability probes leaked mutable storage")
	}
	terms := manifest.Terms()
	if terms.Version() != "2025.07.02" || terms.Digest().IsZero() ||
		terms.Presentation() != TermsPresentationAgentMemory ||
		manifest.SupportExpiresAt() != time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC) ||
		!manifest.SupportedAt(time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)) ||
		manifest.SupportedAt(time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("terms or support projection is incomplete")
	}
}

func TestCatalogSupportsClosedWindowsAndLinuxPolicyVariants(t *testing.T) {
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
	windows.DesktopExecution.WindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}
	windowsManifest := mustManifest(t, windows)
	if windowsManifest.Artifact().Publisher().Verification() != NativeVerificationAuthenticode {
		t.Fatal("Windows native trust policy was not preserved")
	}

	linux := validManifestInput(t)
	linux.CatalogID = "docker-engine-linux-x86-64"
	linux.Platform.OperatingSystem = OSKindLinux
	linux.Platform.Architecture = ArchitectureX8664
	linux.Platform.Edition = "workstation"
	linux.Platform.Distribution = "ubuntu"
	linux.Runtime.Product = RuntimeProductDockerEngine
	linux.Runtime.Components = append(linux.Runtime.Components, RuntimeComponentInput{
		Name: ComponentRootlessExtras, Version: "28.3.2",
	})
	linux.Artifact = linuxArtifactPolicyInput(t)
	linux.DesktopExecution = DesktopExecutionPolicyInput{}
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
	linuxManifest := mustManifest(t, linux)
	linuxExecution, present := linuxManifest.LinuxExecution()
	if linuxManifest.Runtime().Product() != RuntimeProductDockerEngine ||
		linuxManifest.Artifact().Publisher().Verification() != NativeVerificationPackageSignature ||
		!present || linuxExecution.PackageSetDigest().IsZero() {
		t.Fatal("Linux runtime policy was not preserved")
	}
	raw, err := EncodeManifestV1(linuxManifest)
	if err != nil {
		t.Fatalf("EncodeManifestV1(Linux) error = %v", err)
	}
	decoded, err := DecodeManifestV1(raw)
	decodedExecution, decodedPresent := decoded.LinuxExecution()
	if err != nil || !decodedPresent || !decoded.Digest().Equal(linuxManifest.Digest()) ||
		!decodedExecution.PackageSetDigest().Equal(linuxExecution.PackageSetDigest()) ||
		len(decodedExecution.Repository().VerificationArtifacts()) != 3 ||
		len(decodedExecution.VerificationRepositories()) != 1 ||
		!decodedExecution.Repository().MetadataDigest().Equal(linuxExecution.Repository().MetadataDigest()) {
		t.Fatalf("DecodeManifestV1(Linux) = present:%v error:%v", decodedPresent, err)
	}
}

func TestPrerequisiteOperationsRequireTheirExactTypedPayload(t *testing.T) {
	t.Parallel()

	valid := []PrerequisiteInput{
		{Operation: PrerequisiteConfigureOfficialRepository, RepositoryID: "docker-stable"},
		{Operation: PrerequisiteEnableWSLFeature, FeatureID: "virtual-machine-platform"},
		{Operation: PrerequisiteInstallVerifiedPackage, PackageIDs: []string{"docker-ce"}},
		{Operation: PrerequisiteInstallWSLKernelUpdate, PackageIDs: []string{"wsl-kernel"}},
		{Operation: PrerequisiteConfigureSubordinateIDs, SubordinateIDCount: 65536},
		{Operation: PrerequisiteEnableUserService, ServiceID: "docker-user"},
	}
	for _, input := range valid {
		input := input
		t.Run(string(input.Operation), func(t *testing.T) {
			t.Parallel()
			if _, err := newPrerequisite(input); err != nil {
				t.Fatalf("newPrerequisite() error = %v", err)
			}
			input.FeatureID = "unexpected"
			if input.Operation == PrerequisiteEnableWSLFeature {
				input.RepositoryID = "unexpected"
			}
			if _, err := newPrerequisite(input); !errors.Is(err, ErrManifestIntegrity) {
				t.Fatalf("newPrerequisite(extra field) error = %v", err)
			}
		})
	}
}

func TestPlatformPolicyMatchesEveryCertifiedBoundary(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validManifestInput(t))
	valid := mustHost(t, HostInput{
		OperatingSystem: OSKindMacOS,
		Architecture:    ArchitectureARM64,
		Edition:         "desktop",
		Distribution:    "macos",
		OSVersion:       "15.5.0",
		Build:           24000,
		CPUCores:        8,
		MemoryBytes:     16_000_000_000,
		FreeDiskBytes:   100_000_000_000,
		Virtualization:  true,
	})
	if err := manifest.Platform().Supports(valid); err != nil {
		t.Fatalf("Supports(valid) error = %v", err)
	}

	mutations := []struct {
		name string
		edit func(HostInput) HostInput
	}{
		{name: "operating system", edit: func(v HostInput) HostInput { v.OperatingSystem = OSKindWindows; return v }},
		{name: "architecture", edit: func(v HostInput) HostInput { v.Architecture = ArchitectureX8664; return v }},
		{name: "edition", edit: func(v HostInput) HostInput { v.Edition = "server"; return v }},
		{name: "distribution", edit: func(v HostInput) HostInput { v.Distribution = "darwin"; return v }},
		{name: "minimum version", edit: func(v HostInput) HostInput { v.OSVersion = "13.9.9"; return v }},
		{name: "maximum version", edit: func(v HostInput) HostInput { v.OSVersion = "16.0.0"; return v }},
		{name: "minimum build", edit: func(v HostInput) HostInput { v.Build = 22999; return v }},
		{name: "maximum build", edit: func(v HostInput) HostInput { v.Build = 25001; return v }},
		{name: "cpu", edit: func(v HostInput) HostInput { v.CPUCores = 3; return v }},
		{name: "memory", edit: func(v HostInput) HostInput { v.MemoryBytes = 7_999_999_999; return v }},
		{name: "disk", edit: func(v HostInput) HostInput { v.FreeDiskBytes = 29_999_999_999; return v }},
		{name: "virtualization", edit: func(v HostInput) HostInput { v.Virtualization = false; return v }},
	}
	base := HostInput{
		OperatingSystem: OSKindMacOS, Architecture: ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 16_000_000_000, FreeDiskBytes: 100_000_000_000, Virtualization: true,
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			host := mustHost(t, mutation.edit(base))
			if !errors.Is(manifest.Platform().Supports(host), ErrUnsupportedHost) {
				t.Fatalf("Supports(mutated host) did not fail closed")
			}
		})
	}
}

func TestNewManifestRejectsEveryMaterialInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*ManifestInput)
	}{
		{name: "schema", edit: func(v *ManifestInput) { v.SchemaVersion = 2 }},
		{name: "catalog id", edit: func(v *ManifestInput) { v.CatalogID = "" }},
		{name: "sequence", edit: func(v *ManifestInput) { v.CatalogSequence = 0 }},
		{name: "signing key", edit: func(v *ManifestInput) { v.SigningKeyID = "" }},
		{name: "support expiry", edit: func(v *ManifestInput) { v.SupportExpiresAt = time.Time{} }},
		{name: "platform", edit: func(v *ManifestInput) { v.Platform.MinimumOSVersion = "16.0.0" }},
		{name: "runtime channel", edit: func(v *ManifestInput) { v.Runtime.Channel = "latest" }},
		{name: "compose version", edit: func(v *ManifestInput) { v.Runtime.ComposeVersion = "latest" }},
		{name: "non-stable runtime version", edit: func(v *ManifestInput) { v.Runtime.Version = "28.3" }},
		{name: "duplicate component", edit: func(v *ManifestInput) { v.Runtime.Components = append(v.Runtime.Components, v.Runtime.Components[0]) }},
		{name: "artifact size", edit: func(v *ManifestInput) { v.Artifact.DownloadBytes = 0 }},
		{name: "desktop acquisition safety", edit: func(v *ManifestInput) { v.DesktopExecution.AcquisitionSafetyBytes = 0 }},
		{name: "desktop rollback headroom", edit: func(v *ManifestInput) { v.DesktopExecution.RollbackHeadroomBytes = 0 }},
		{name: "desktop capacity sum", edit: func(v *ManifestInput) { v.DesktopExecution.RollbackHeadroomBytes++ }},
		{name: "publisher", edit: func(v *ManifestInput) { v.Artifact.Publisher.Identity = "" }},
		{name: "source", edit: func(v *ManifestInput) { v.Artifact.Sources[0].Scheme = "http" }},
		{name: "source prefix boundary", edit: func(v *ManifestInput) { v.Artifact.Sources[0].PathPrefix = "/mac/main/arm64" }},
		{name: "encoded source path", edit: func(v *ManifestInput) { v.Artifact.Sources[0].PathPrefix = "/mac/%2e%2e/" }},
		{name: "redistribution", edit: func(v *ManifestInput) { v.Artifact.RedistributionPermitted = false }},
		{name: "installer executable", edit: func(v *ManifestInput) { v.Install.Executable = "sh" }},
		{name: "cross-platform installer", edit: func(v *ManifestInput) { v.Install.Executable = InstallerExecutableWindowsHelper }},
		{name: "argument placeholder value", edit: func(v *ManifestInput) { v.Install.Arguments[1].Value = "/tmp/file" }},
		{name: "reboot code ordering", edit: func(v *ManifestInput) { v.Install.RebootExitCodes = []uint32{3010, 1641} }},
		{name: "prerequisite operation", edit: func(v *ManifestInput) { v.Prerequisites[0].Operation = "run_command" }},
		{name: "capability", edit: func(v *ManifestInput) { v.CapabilityProbes[0] = "run_anything" }},
		{name: "required capability", edit: func(v *ManifestInput) { v.CapabilityProbes = v.CapabilityProbes[1:] }},
		{name: "terms", edit: func(v *ManifestInput) { v.Terms.Digest = Digest{} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validManifestInput(t)
			test.edit(&input)
			if _, err := NewManifest(input); !errors.Is(err, ErrManifestIntegrity) {
				t.Fatalf("NewManifest() error = %v, want integrity error", err)
			}
		})
	}
}

type testReporter interface {
	Helper()
	Fatalf(string, ...any)
}

func validManifestInput(t testReporter) ManifestInput {
	t.Helper()
	artifactDigest := DigestBytes([]byte("docker-desktop-artifact"))
	termsDigest := DigestBytes([]byte("docker terms"))
	probeDigest := DigestBytes([]byte("probe image"))
	capabilities := []CapabilityProbe{
		CapabilityBindReadOnly, CapabilityComposeVersion, CapabilityEngineAPI,
		CapabilityLinuxContainers, CapabilityLocalEndpoint, CapabilityNetworkIsolation,
		CapabilityNoTCPListener, CapabilitySecurityMode, CapabilityVolumePersistence,
	}
	return ManifestInput{
		SchemaVersion:    SupportedSchemaVersion,
		CatalogID:        "docker-desktop-macos-arm64",
		CatalogSequence:  42,
		SigningKeyID:     "agentmemory-runtime-root-2026",
		SupportExpiresAt: time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC),
		Platform: PlatformPolicyInput{
			OperatingSystem: OSKindMacOS, Architecture: ArchitectureARM64,
			Edition: "desktop", Distribution: "macos",
			MinimumOSVersion: "14.0.0", MaximumOSVersion: "15.9.9",
			MinimumBuild: 23000, MaximumBuild: 25000,
			MinimumCPUCores: 4, MinimumMemoryBytes: 8_589_934_592,
			MinimumFreeDiskBytes: 32_212_254_720, VirtualizationRequired: true,
		},
		Runtime: RuntimePolicyInput{
			Product: RuntimeProductDockerDesktop, Channel: StableChannel,
			Version: "28.3.2", ComposeVersion: "2.39.1",
			Components: []RuntimeComponentInput{
				{Name: ComponentEngine, Version: "28.3.2"},
				{Name: ComponentCLI, Version: "28.3.2"},
				{Name: ComponentContainerd, Version: "1.7.27"},
				{Name: ComponentBuildx, Version: "0.25.0"},
				{Name: ComponentCompose, Version: "2.39.1"},
			},
		},
		Artifact: ArtifactPolicyInput{
			DownloadBytes: 700_000_000, ExpandedBytes: 2_000_000_000,
			ReserveBytes: 3_000_000_000, SHA256: artifactDigest,
			Sources: []OfficialSourceInput{
				{Scheme: "https", Host: "desktop.docker.com", PathPrefix: "/mac/main/arm64/"},
			},
			ProxyMode: ProxyModeSystem, OfflinePolicy: OfflinePolicyBundled,
			RedistributionPermitted: true,
			Publisher: PublisherPolicyInput{
				Verification:       NativeVerificationAppleNotarized,
				Identity:           "developer-id-application-docker-inc-9bnsxjn65r",
				SigningKeyIdentity: "apple-developer-id-9bnsxjn65r",
				PackageIdentity:    "com.docker.docker",
			},
		},
		Install: InstallerPolicyInput{
			Executable: InstallerExecutableMacOSInstaller,
			Arguments: []ArgumentTemplateInput{
				{Kind: ArgumentKindLiteral, Value: "install"},
				{Kind: ArgumentKindArtifactPath},
				{Kind: ArgumentKindPlanDigest},
			},
			RebootExitCodes:   nil,
			ServiceIdentity:   "com.docker.backend",
			RollbackStrategy:  RollbackStrategyPreserve,
			OwnershipChanges:  []string{"application:com.docker.docker", "service:com.docker.backend"},
			VendorUIMandatory: false,
		},
		DesktopExecution: DesktopExecutionPolicyInput{
			AcquisitionSafetyBytes: 100_000_000,
			MinimumAvailableMemory: 4_000_000_000, ArtifactFileName: "Docker.dmg",
			DockerCLISHA256:     DigestBytes([]byte("docker cli")),
			ComposePluginSHA256: DigestBytes([]byte("compose plugin")),
			ProbeImage:          "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probeDigest.Hex(),
			ProbeImageDigest:    probeDigest, ProbeContractVersion: "1",
			CapabilityPolicyDigest: RuntimeCapabilityPolicyDigest(capabilities),
			RollbackHeadroomBytes:  200_000_000,
		},
		Prerequisites: []PrerequisiteInput{
			{Operation: PrerequisiteInstallVerifiedPackage, PackageIDs: []string{"com.docker.docker"}},
		},
		CapabilityProbes: capabilities,
		Terms: TermsPolicyInput{
			ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL:    OfficialSourceInput{Scheme: "https", Host: "www.docker.com", PathPrefix: "/legal/docker-subscription-service-agreement"},
			Digest: termsDigest, Presentation: TermsPresentationAgentMemory,
		},
	}
}

func mustManifest(t testReporter, input ManifestInput) Manifest {
	t.Helper()
	manifest, err := NewManifest(input)
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	return manifest
}

func mustSource(t *testing.T, scheme string, host string, path string) SourceLocation {
	t.Helper()
	source, err := NewSourceLocation(OfficialSourceInput{Scheme: scheme, Host: host, PathPrefix: path})
	if err != nil {
		t.Fatalf("NewSourceLocation() error = %v", err)
	}
	return source
}

func mustHost(t *testing.T, input HostInput) Host {
	t.Helper()
	host, err := NewHost(input)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	return host
}
