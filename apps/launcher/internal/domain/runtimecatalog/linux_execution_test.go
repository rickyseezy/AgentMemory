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
		len(policy.VerificationRepositories()) != 1 ||
		len(policy.Repository().VerificationArtifacts()) != 3 ||
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
	verification := policy.Repository().VerificationArtifacts()
	verification[0] = LinuxRepositoryArtifact{}
	if policy.Repository().VerificationArtifacts()[0].Role() != LinuxRepositoryArtifactSigningKey {
		t.Fatal("Linux repository projection leaked mutable storage")
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
		{name: "repository metadata authentication", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.MetadataAuthentication = LinuxRepositoryMetadataAuthenticationPackageSignatures
		}},
		{name: "repository artifact omitted", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.VerificationArtifacts = v.Repository.VerificationArtifacts[:2]
		}},
		{name: "repository artifact role", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.VerificationArtifacts[1].Role = LinuxRepositoryArtifactPackageIndex
		}},
		{name: "repository artifact size", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.VerificationArtifacts[0].DownloadBytes = 2 << 20
		}},
		{name: "repository artifact mirror", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.VerificationArtifacts[1].Source.Host = "mirror.invalid"
		}},
		{name: "repository artifact path", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.VerificationArtifacts[1].Source.PathPrefix = "/linux/ubuntu/dists/noble/Release"
		}},
		{name: "repository key digest", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.SigningKeyDigest = DigestBytes([]byte("other key"))
		}},
		{name: "repository metadata digest", edit: func(v *LinuxExecutionPolicyInput) {
			v.Repository.MetadataDigest = DigestBytes([]byte("other metadata"))
		}},
		{name: "distribution repository omitted", edit: func(v *LinuxExecutionPolicyInput) {
			v.VerificationRepositories = nil
		}},
		{name: "prerequisite uses docker repository", edit: func(v *LinuxExecutionPolicyInput) {
			v.Packages[6].RepositoryID = "docker-stable"
			v.Packages[6].NativeReceiptDigest = LinuxNativePackageReceiptDigest(v.PackageManager, v.Packages[6])
		}},
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

func TestLinuxExecutionPolicyAcceptsExactDNFTrustChain(t *testing.T) {
	t.Parallel()
	input, artifact := linuxDNFExecutionPolicyInput()
	validatedArtifact, err := newArtifactPolicy(artifact, OSKindLinux)
	if err != nil {
		t.Fatal(err)
	}
	primary, primaryError := newLinuxRepository(input.Repository, input.Codename, input.PackageManager, true)
	if primaryError != nil {
		t.Fatalf("primary repository error = %v", primaryError)
	}
	if _, repositoryError := newLinuxVerificationRepositories(
		input.VerificationRepositories, input.Codename, input.PackageManager, primary, validatedArtifact,
	); repositoryError != nil {
		t.Fatalf("verification repository error = %v", repositoryError)
	}
	policy, err := newLinuxExecutionPolicy(input, validatedArtifact)
	if err != nil {
		t.Fatalf("newLinuxExecutionPolicy() error = %v", err)
	}
	verification := policy.Repository().VerificationArtifacts()
	if policy.PackageManager() != LinuxPackageManagerDNF || len(verification) != 4 ||
		verification[2].Role() != LinuxRepositoryArtifactMetadataSignature ||
		policy.Packages()[6].Name() != "shadow-utils" || !policy.ValidFor(validatedArtifact) {
		t.Fatal("DNF trust chain projection is incomplete")
	}

	input.Repository.VerificationArtifacts[2].Source.PathPrefix = "/linux/fedora/42/x86_64/stable/repodata/other.asc"
	input.Repository.MetadataDigest = LinuxRepositoryMetadataDigest(input.Repository.VerificationArtifacts)
	if _, err := newLinuxExecutionPolicy(input, validatedArtifact); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("detached metadata signature substitution error = %v", err)
	}

	input, artifact = linuxDNFExecutionPolicyInput()
	validatedArtifact, err = newArtifactPolicy(artifact, OSKindLinux)
	if err != nil {
		t.Fatal(err)
	}
	input.Repository.MetadataAuthentication = LinuxRepositoryMetadataAuthenticationPackageSignatures
	if _, err = newLinuxExecutionPolicy(input, validatedArtifact); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("detached signature policy downgrade error = %v", err)
	}
	input, artifact = linuxDNFExecutionPolicyInput()
	validatedArtifact, err = newArtifactPolicy(artifact, OSKindLinux)
	if err != nil {
		t.Fatal(err)
	}
	input.VerificationRepositories[0].MetadataAuthentication = LinuxRepositoryMetadataAuthenticationDetached
	if _, err = newLinuxExecutionPolicy(input, validatedArtifact); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("invented distribution metadata signature policy error = %v", err)
	}
}

func TestLinuxExecutionPolicyRejectsTrustResourcesOutsideSignedSourcePolicy(t *testing.T) {
	t.Parallel()

	artifact := linuxArtifactPolicyInput(t)
	artifact.Sources = []OfficialSourceInput{{
		Scheme: "https", Host: "download.docker.com",
		PathPrefix: "/linux/ubuntu/dists/noble/pool/stable/amd64/",
	}}
	validatedArtifact, err := newArtifactPolicy(artifact, OSKindLinux)
	if err != nil {
		t.Fatalf("newArtifactPolicy() error = %v", err)
	}
	if _, err = newLinuxExecutionPolicy(
		linuxExecutionPolicyInput(t, artifact), validatedArtifact,
	); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("newLinuxExecutionPolicy() error = %v, want integrity", err)
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
	verification := linuxAPTRepositoryArtifacts()
	distributionVerification := linuxAPTDistributionRepositoryArtifacts()
	download := packageBytes(packages) + repositoryInputBytes(verification) + repositoryInputBytes(distributionVerification)
	return ArtifactPolicyInput{
		DownloadBytes: download,
		ExpandedBytes: download + 200_000_000,
		ReserveBytes:  download + 400_000_000,
		SHA256:        LinuxPackageSetDigest(packages),
		Sources: []OfficialSourceInput{
			{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/"},
			{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/"},
		},
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
	verification := linuxAPTRepositoryArtifacts()
	distributionVerification := linuxAPTDistributionRepositoryArtifacts()
	return LinuxExecutionPolicyInput{
		PackageManager: LinuxPackageManagerAPT, PackageManagerVersion: "2.7.14build2",
		Codename: "noble", MinimumKernel: "6.8.0", MinimumAvailableMemory: 4_000_000_000,
		Repository: LinuxRepositoryInput{
			ID:    "docker-stable",
			URL:   OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/"},
			Suite: "noble", Component: "stable",
			SigningKeyFingerprint:  "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
			SigningKeyDigest:       verification[0].SHA256,
			ConfigurationDigest:    DigestBytes([]byte("docker apt source configuration")),
			MetadataAuthentication: LinuxRepositoryMetadataAuthenticationInline,
			MetadataDigest:         LinuxRepositoryMetadataDigest(verification),
			VerificationArtifacts:  verification,
		},
		VerificationRepositories: []LinuxRepositoryInput{{
			ID:    "ubuntu-noble-updates",
			URL:   OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/"},
			Suite: "noble-updates", Component: "main",
			SigningKeyFingerprint:  "F6ECB3762474EDA9D21B7022871920D1991BC93C",
			SigningKeyDigest:       distributionVerification[0].SHA256,
			ConfigurationDigest:    DigestBytes([]byte("ubuntu archive source configuration")),
			MetadataAuthentication: LinuxRepositoryMetadataAuthenticationInline,
			MetadataDigest:         LinuxRepositoryMetadataDigest(distributionVerification),
			VerificationArtifacts:  distributionVerification,
		}},
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

func linuxAPTRepositoryArtifacts() []LinuxRepositoryArtifactInput {
	base := OfficialSourceInput{Scheme: "https", Host: "download.docker.com"}
	return []LinuxRepositoryArtifactInput{
		{Role: LinuxRepositoryArtifactSigningKey, DownloadBytes: 4_000, SHA256: DigestBytes([]byte("docker apt key")),
			Source: OfficialSourceInput{Scheme: base.Scheme, Host: base.Host, PathPrefix: "/linux/ubuntu/gpg"}},
		{Role: LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 50_000, SHA256: DigestBytes([]byte("docker apt InRelease")),
			Source: OfficialSourceInput{Scheme: base.Scheme, Host: base.Host, PathPrefix: "/linux/ubuntu/dists/noble/InRelease"}},
		{Role: LinuxRepositoryArtifactPackageIndex, DownloadBytes: 200_000, SHA256: DigestBytes([]byte("docker apt Packages")),
			Source: OfficialSourceInput{Scheme: base.Scheme, Host: base.Host, PathPrefix: "/linux/ubuntu/dists/noble/stable/binary-amd64/Packages.gz"}},
	}
}

func linuxAPTDistributionRepositoryArtifacts() []LinuxRepositoryArtifactInput {
	return []LinuxRepositoryArtifactInput{
		{Role: LinuxRepositoryArtifactSigningKey, DownloadBytes: 20_000, SHA256: DigestBytes([]byte("ubuntu archive key")),
			Source: OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/project/ubuntu-archive-keyring.gpg"}},
		{Role: LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 250_000, SHA256: DigestBytes([]byte("ubuntu noble-updates InRelease")),
			Source: OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/dists/noble-updates/InRelease"}},
		{Role: LinuxRepositoryArtifactPackageIndex, DownloadBytes: 2_000_000, SHA256: DigestBytes([]byte("ubuntu noble-updates Packages")),
			Source: OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/dists/noble-updates/main/binary-amd64/Packages.xz"}},
	}
}

func repositoryInputBytes(artifacts []LinuxRepositoryArtifactInput) uint64 {
	var total uint64
	for _, artifact := range artifacts {
		total += artifact.DownloadBytes
	}
	return total
}

func linuxDNFExecutionPolicyInput() (LinuxExecutionPolicyInput, ArtifactPolicyInput) {
	verification := []LinuxRepositoryArtifactInput{
		{Role: LinuxRepositoryArtifactSigningKey, DownloadBytes: 4_000, SHA256: DigestBytes([]byte("dnf key")),
			Source: OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/gpg"}},
		{Role: LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 20_000, SHA256: DigestBytes([]byte("repomd")),
			Source: OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/42/x86_64/stable/repodata/repomd.xml"}},
		{Role: LinuxRepositoryArtifactMetadataSignature, DownloadBytes: 1_000, SHA256: DigestBytes([]byte("repomd signature")),
			Source: OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/42/x86_64/stable/repodata/repomd.xml.asc"}},
		{Role: LinuxRepositoryArtifactPackageIndex, DownloadBytes: 100_000, SHA256: DigestBytes([]byte("primary")),
			Source: OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/42/x86_64/stable/repodata/abc-primary.xml.gz"}},
	}
	distributionVerification := []LinuxRepositoryArtifactInput{
		{Role: LinuxRepositoryArtifactSigningKey, DownloadBytes: 8_000, SHA256: DigestBytes([]byte("fedora key")),
			Source: OfficialSourceInput{Scheme: "https", Host: "fedoraproject.org", PathPrefix: "/fedora.gpg"}},
		{Role: LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 30_000, SHA256: DigestBytes([]byte("fedora repomd")),
			Source: OfficialSourceInput{Scheme: "https", Host: "dl.fedoraproject.org", PathPrefix: "/pub/fedora/linux/updates/42/Everything/x86_64/repodata/repomd.xml"}},
		{Role: LinuxRepositoryArtifactPackageIndex, DownloadBytes: 200_000, SHA256: DigestBytes([]byte("fedora primary")),
			Source: OfficialSourceInput{Scheme: "https", Host: "dl.fedoraproject.org", PathPrefix: "/pub/fedora/linux/updates/42/Everything/x86_64/repodata/fedora-primary.xml.gz"}},
	}
	packages := linuxPackagesInput()
	base := "/linux/fedora/42/x86_64/stable/Packages/"
	for index := range packages {
		packages[index].RepositoryID = "docker-stable"
		packages[index].Source.Host = "download.docker.com"
		packages[index].Source.PathPrefix = base + packages[index].Name + ".rpm"
	}
	packages[6] = linuxPackage("shadow-utils", "2:4.15.1-12.fc42", LinuxPackagePurposePrerequisite, 200_000, base+"shadow-utils.rpm")
	packages[6].RepositoryID = "fedora-updates"
	packages[6].Source.Host = "dl.fedoraproject.org"
	packages[6].Source.PathPrefix = "/pub/fedora/linux/updates/42/Everything/x86_64/Packages/s/shadow-utils.rpm"
	for index := range packages {
		packages[index].NativeReceiptDigest = LinuxNativePackageReceiptDigest(LinuxPackageManagerDNF, packages[index])
	}
	download := packageBytes(packages) + repositoryInputBytes(verification) + repositoryInputBytes(distributionVerification)
	artifact := ArtifactPolicyInput{
		DownloadBytes: download, ExpandedBytes: download + 200_000_000, ReserveBytes: download + 400_000_000,
		SHA256: LinuxPackageSetDigest(packages),
		Sources: []OfficialSourceInput{
			{Scheme: "https", Host: "dl.fedoraproject.org", PathPrefix: "/pub/fedora/linux/"},
			{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/"},
			{Scheme: "https", Host: "fedoraproject.org", PathPrefix: "/"},
		},
		ProxyMode: ProxyModeSystem, OfflinePolicy: OfflinePolicyUserSelectedOfficial,
		Publisher: PublisherPolicyInput{
			Verification: NativeVerificationPackageSignature, Identity: "docker-rpm-repository",
			SigningKeyIdentity: "docker-release-key-2026", PackageIdentity: "docker-engine-package-set",
		},
	}
	input := LinuxExecutionPolicyInput{
		PackageManager: LinuxPackageManagerDNF, PackageManagerVersion: "5.2.15.0",
		Codename: "fedora-42", MinimumKernel: "6.14.0", MinimumAvailableMemory: 4_000_000_000,
		Repository: LinuxRepositoryInput{
			ID: "docker-stable", URL: OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/fedora/42/x86_64/stable/"},
			Suite: "fedora-42", Component: "stable", SigningKeyFingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
			SigningKeyDigest: verification[0].SHA256, ConfigurationDigest: DigestBytes([]byte("dnf config")),
			MetadataAuthentication: LinuxRepositoryMetadataAuthenticationDetached,
			MetadataDigest:         LinuxRepositoryMetadataDigest(verification), VerificationArtifacts: verification,
		},
		VerificationRepositories: []LinuxRepositoryInput{{
			ID:    "fedora-updates",
			URL:   OfficialSourceInput{Scheme: "https", Host: "dl.fedoraproject.org", PathPrefix: "/pub/fedora/linux/updates/42/Everything/x86_64/"},
			Suite: "fedora-42-updates", Component: "updates",
			SigningKeyFingerprint:  "B0F4950458F69E1150C6C5EDC8AC4916105EF944",
			SigningKeyDigest:       distributionVerification[0].SHA256,
			ConfigurationDigest:    DigestBytes([]byte("fedora updates config")),
			MetadataAuthentication: LinuxRepositoryMetadataAuthenticationPackageSignatures,
			MetadataDigest:         LinuxRepositoryMetadataDigest(distributionVerification),
			VerificationArtifacts:  distributionVerification,
		}},
		Packages: packages, PackageSetDigest: artifact.SHA256,
		RollbackHeadroomBytes: 200_000_000, AcquisitionSafetyBytes: 200_000_000,
		SubordinateIDCount: 65536, SELinuxEnforcingSupported: true,
		ServiceID: "docker.service", ServiceUnitDigest: DigestBytes([]byte("docker user service")),
		RootlessToolPath: "/usr/bin/dockerd-rootless-setuptool.sh", RootlessToolDigest: DigestBytes([]byte("rootless setup tool")),
		ProbeImage:       "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + DigestBytes([]byte("probe image")).Hex(),
		ProbeImageDigest: DigestBytes([]byte("probe image")), ProbeContractVersion: "1",
		CapabilityPolicyDigest: LinuxCapabilityPolicyDigest(linuxCapabilities()),
	}
	return input, artifact
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
		linuxPackage("uidmap", "1:4.13+dfsg1-4ubuntu3.2", LinuxPackagePurposePrerequisite, 200_000, "/ubuntu/pool/main/s/shadow/uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb"),
	}
}

func linuxPackage(name, version string, purpose LinuxPackagePurpose, size uint64, path string) LinuxPackageInput {
	host := "download.docker.com"
	repositoryID := "docker-stable"
	if purpose == LinuxPackagePurposePrerequisite {
		host = "archive.ubuntu.com"
		repositoryID = "ubuntu-noble-updates"
	}
	input := LinuxPackageInput{
		Name: name, Version: version, Purpose: purpose, RepositoryID: repositoryID, DownloadBytes: size,
		SHA256: DigestBytes([]byte(name + " artifact")),
		Source: OfficialSourceInput{Scheme: "https", Host: host, PathPrefix: path},
	}
	input.NativeReceiptDigest = LinuxNativePackageReceiptDigest(LinuxPackageManagerAPT, input)
	return input
}

func packageBytes(packages []LinuxPackageInput) uint64 {
	var total uint64
	for _, pkg := range packages {
		total += pkg.DownloadBytes
	}
	return total
}
