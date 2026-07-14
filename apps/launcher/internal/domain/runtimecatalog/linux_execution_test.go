package runtimecatalog

import (
	"errors"
	"testing"
)

func TestLinuxExecutionPolicyBindsCompleteRetainedPackageSet(t *testing.T) {
	t.Parallel()

	artifact := linuxArtifactPolicyInput(t)
	validatedArtifact, err := newArtifactPolicy(artifact, OSKindLinux)
	if err != nil {
		t.Fatalf("newArtifactPolicy() error = %v", err)
	}
	policy, err := newLinuxExecutionPolicy(linuxExecutionPolicyInput(t, artifact), validatedArtifact)
	if err != nil {
		t.Fatalf("newLinuxExecutionPolicy() error = %v", err)
	}
	if policy.PackageManager() != LinuxPackageManagerAPT || policy.Codename() != "noble" ||
		policy.Repository().ID() != "docker-stable" || len(policy.Packages()) != 7 ||
		policy.Packages()[0].Name() != "containerd.io" ||
		policy.Packages()[6].Name() != "uidmap" || policy.SubordinateIDCount() != 65536 ||
		policy.ProbeContractVersion() != "1" || !policy.ValidFor(validatedArtifact) {
		t.Fatal("Linux execution projection is incomplete")
	}

	packages := policy.Packages()
	packages[0] = LinuxPackage{}
	if policy.Packages()[0].Name() != "containerd.io" {
		t.Fatal("Linux package projection leaked mutable storage")
	}
}

func TestLinuxExecutionPolicyRejectsMutableOrIncompleteAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*LinuxExecutionPolicyInput)
	}{
		{name: "manager", edit: func(v *LinuxExecutionPolicyInput) { v.PackageManager = "shell" }},
		{name: "manager version", edit: func(v *LinuxExecutionPolicyInput) { v.PackageManagerVersion = "latest" }},
		{name: "codename", edit: func(v *LinuxExecutionPolicyInput) { v.Codename = "" }},
		{name: "kernel", edit: func(v *LinuxExecutionPolicyInput) { v.MinimumKernel = "" }},
		{name: "available memory", edit: func(v *LinuxExecutionPolicyInput) { v.MinimumAvailableMemory = 0 }},
		{name: "repository host", edit: func(v *LinuxExecutionPolicyInput) { v.Repository.URL.Host = "mirror.invalid" }},
		{name: "repository suite", edit: func(v *LinuxExecutionPolicyInput) { v.Repository.Suite = "jammy" }},
		{name: "repository key", edit: func(v *LinuxExecutionPolicyInput) { v.Repository.SigningKeyFingerprint = "bad" }},
		{name: "package omitted", edit: func(v *LinuxExecutionPolicyInput) { v.Packages = v.Packages[:6] }},
		{name: "mutable package version", edit: func(v *LinuxExecutionPolicyInput) { v.Packages[0].Version = "latest" }},
		{name: "package digest", edit: func(v *LinuxExecutionPolicyInput) { v.Packages[0].SHA256 = Digest{} }},
		{name: "package source", edit: func(v *LinuxExecutionPolicyInput) { v.Packages[0].Source.Host = "mirror.invalid" }},
		{name: "package set digest", edit: func(v *LinuxExecutionPolicyInput) { v.PackageSetDigest = DigestBytes([]byte("different")) }},
		{name: "rollback headroom", edit: func(v *LinuxExecutionPolicyInput) { v.RollbackHeadroomBytes = 0 }},
		{name: "capacity mismatch", edit: func(v *LinuxExecutionPolicyInput) { v.AcquisitionSafetyBytes++ }},
		{name: "service", edit: func(v *LinuxExecutionPolicyInput) { v.ServiceID = "docker-root.service" }},
		{name: "rootless path", edit: func(v *LinuxExecutionPolicyInput) { v.RootlessToolPath = "/tmp/setup.sh" }},
		{name: "probe tag", edit: func(v *LinuxExecutionPolicyInput) {
			v.ProbeImage = "docker.io/rickyseezy/agentmemory-runtime-probe:latest"
		}},
		{name: "probe contract", edit: func(v *LinuxExecutionPolicyInput) { v.ProbeContractVersion = "2" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			artifact := linuxArtifactPolicyInput(t)
			validatedArtifact, artifactError := newArtifactPolicy(artifact, OSKindLinux)
			if artifactError != nil {
				t.Fatalf("newArtifactPolicy() error = %v", artifactError)
			}
			input := linuxExecutionPolicyInput(t, artifact)
			test.edit(&input)
			if _, err := newLinuxExecutionPolicy(input, validatedArtifact); !errors.Is(err, ErrManifestIntegrity) {
				t.Fatalf("newLinuxExecutionPolicy() error = %v, want integrity", err)
			}
		})
	}
}

func TestNonLinuxCatalogRejectsLinuxExecutionAuthority(t *testing.T) {
	t.Parallel()

	input := validManifestInput(t)
	input.LinuxExecution = linuxExecutionPolicyInput(t, linuxArtifactPolicyInput(t))
	if _, err := NewManifest(input); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("NewManifest() error = %v, want integrity", err)
	}
}

func linuxArtifactPolicyInput(t testReporter) ArtifactPolicyInput {
	t.Helper()
	packages := linuxPackagesInput()
	return ArtifactPolicyInput{
		DownloadBytes: packageBytes(packages),
		ExpandedBytes: packageBytes(packages) + 200_000_000,
		ReserveBytes:  packageBytes(packages) + 400_000_000,
		SHA256:        LinuxPackageSetDigest(packages),
		Sources:       []OfficialSourceInput{{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/dists/noble/pool/stable/amd64/"}},
		ProxyMode:     ProxyModeSystem,
		OfflinePolicy: OfflinePolicyUserSelectedOfficial,
		Publisher: PublisherPolicyInput{
			Verification: NativeVerificationPackageSignature, Identity: "docker-apt-repository",
			SigningKeyIdentity: "docker-release-key-2026", PackageIdentity: "docker-engine-package-set",
		},
	}
}

func linuxExecutionPolicyInput(t testReporter, artifact ArtifactPolicyInput) LinuxExecutionPolicyInput {
	t.Helper()
	packages := linuxPackagesInput()
	return LinuxExecutionPolicyInput{
		PackageManager: LinuxPackageManagerAPT, PackageManagerVersion: "2.7.14build2",
		Codename: "noble", MinimumKernel: "6.8.0", MinimumAvailableMemory: 4_000_000_000,
		Repository: LinuxRepositoryInput{
			ID:    "docker-stable",
			URL:   OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/"},
			Suite: "noble", Component: "stable",
			SigningKeyFingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
			SigningKeyDigest:      DigestBytes([]byte("docker apt key")),
			ConfigurationDigest:   DigestBytes([]byte("docker apt source configuration")),
			MetadataDigest:        DigestBytes([]byte("docker apt repository metadata")),
		},
		Packages: packages, PackageSetDigest: artifact.SHA256,
		RollbackHeadroomBytes: 200_000_000, AcquisitionSafetyBytes: 200_000_000,
		SubordinateIDCount: 65536, SELinuxEnforcingSupported: true,
		ServiceID: "docker.service", ServiceUnitDigest: DigestBytes([]byte("docker user service")),
		RootlessToolPath:   "/usr/bin/dockerd-rootless-setuptool.sh",
		RootlessToolDigest: DigestBytes([]byte("rootless setup tool")),
		ProbeImage:         "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + DigestBytes([]byte("probe image")).Hex(),
		ProbeImageDigest:   DigestBytes([]byte("probe image")), ProbeContractVersion: "1",
		CapabilityPolicyDigest: LinuxCapabilityPolicyDigest(linuxCapabilities()),
	}
}

func linuxCapabilities() []CapabilityProbe {
	return []CapabilityProbe{
		CapabilityBindReadOnly, CapabilityComposeVersion, CapabilityEngineAPI,
		CapabilityLinuxContainers, CapabilityLocalEndpoint, CapabilityNetworkIsolation,
		CapabilityNoTCPListener, CapabilityRootless, CapabilitySecurityMode,
		CapabilityVolumePersistence,
	}
}

func linuxPackagesInput() []LinuxPackageInput {
	base := "/linux/ubuntu/dists/noble/pool/stable/amd64/"
	return []LinuxPackageInput{
		linuxPackage("containerd.io", "1.7.27-1", LinuxPackagePurposeRuntime, 90_000_000, base+"containerd.io_1.7.27-1_amd64.deb"),
		linuxPackage("docker-buildx-plugin", "0.25.0-1~ubuntu.24.04~noble", LinuxPackagePurposeRuntime, 40_000_000, base+"docker-buildx-plugin_0.25.0-1_amd64.deb"),
		linuxPackage("docker-ce", "5:28.3.2-1~ubuntu.24.04~noble", LinuxPackagePurposeRuntime, 25_000_000, base+"docker-ce_28.3.2-1_amd64.deb"),
		linuxPackage("docker-ce-cli", "5:28.3.2-1~ubuntu.24.04~noble", LinuxPackagePurposeRuntime, 16_000_000, base+"docker-ce-cli_28.3.2-1_amd64.deb"),
		linuxPackage("docker-ce-rootless-extras", "5:28.3.2-1~ubuntu.24.04~noble", LinuxPackagePurposeRuntime, 6_000_000, base+"docker-ce-rootless-extras_28.3.2-1_amd64.deb"),
		linuxPackage("docker-compose-plugin", "2.39.1-1~ubuntu.24.04~noble", LinuxPackagePurposeRuntime, 14_000_000, base+"docker-compose-plugin_2.39.1-1_amd64.deb"),
		linuxPackage("uidmap", "1:4.13+dfsg1-4ubuntu3.2", LinuxPackagePurposePrerequisite, 200_000, base+"uidmap_4.13-4_amd64.deb"),
	}
}

func linuxPackage(name, version string, purpose LinuxPackagePurpose, size uint64, path string) LinuxPackageInput {
	return LinuxPackageInput{
		Name: name, Version: version, Purpose: purpose, DownloadBytes: size,
		SHA256:              DigestBytes([]byte(name + " artifact")),
		NativeReceiptDigest: DigestBytes([]byte(name + " native receipt")),
		Source:              OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: path},
	}
}

func packageBytes(packages []LinuxPackageInput) uint64 {
	var total uint64
	for _, pkg := range packages {
		total += pkg.DownloadBytes
	}
	return total
}
