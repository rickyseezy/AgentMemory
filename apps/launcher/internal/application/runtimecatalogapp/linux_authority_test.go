package runtimecatalogapp

import (
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestVerifiedCatalogProjectsExactLinuxAuthority(t *testing.T) {
	t.Parallel()

	catalog := verifiedLinuxCatalog(t)
	plan := linuxCatalogPlan(t, catalog)
	host := linuxHostBinding(t, "24.04")
	authority, err := catalog.LinuxAuthority(plan.CanonicalBytes(), host)
	if err != nil {
		t.Fatalf("LinuxAuthority() error = %v", err)
	}
	if !authority.ValidFor(plan) || authority.PackageManager() != runtimeport.PackageManagerAPT ||
		authority.Repository().URL() != "https://download.docker.com/linux/ubuntu/" ||
		len(authority.Packages()) != 7 || authority.Packages()[6].Name() != "uidmap" ||
		authority.ArtifactDigest() != runtimeinstall.Hash(catalog.Manifest().Artifact().SHA256()) ||
		authority.TermsID() != "docker-subscription-service-agreement" ||
		authority.TermsURL() != "https://www.docker.com/legal/docker-subscription-service-agreement" ||
		authority.TermsPresentation() != "agentmemory" || authority.InvokingUID() != 1000 ||
		authority.Endpoint() != "unix:///run/user/1000/docker.sock" {
		t.Fatal("verified Linux authority projection is incomplete")
	}
}

func TestVerifiedCatalogProjectsLinuxPackagesIntoHardenedCASPlan(t *testing.T) {
	t.Parallel()

	catalog := verifiedLinuxCatalog(t)
	runtimePlan := linuxCatalogPlan(t, catalog)
	authority, err := catalog.LinuxAuthority(runtimePlan.CanonicalBytes(), linuxHostBinding(t, "24.04"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := catalog.LinuxArtifactPlan(authority)
	if err != nil {
		t.Fatalf("LinuxArtifactPlan() error = %v", err)
	}
	artifacts := plan.Artifacts()
	if len(artifacts) != 13 || artifacts[0].ID() != "repo-docker-stable-signing_key" ||
		!plan.Digest().Equal(releaseinventory.Digest(catalog.Manifest().Digest())) ||
		artifacts[0].Sources()[0] != "https://download.docker.com/linux/ubuntu/gpg" ||
		artifacts[3].ID() != "repo-ubuntu-noble-updates-signing_key" ||
		artifacts[6].ID() != "containerd.io" ||
		artifacts[6].Sources()[0] != "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/containerd.io.deb" ||
		len(artifacts[0].Chunks()) != 1 || artifacts[0].Chunks()[0].Size() != artifacts[0].Size() ||
		plan.Totals().DownloadBytes() != catalog.Manifest().Artifact().DownloadBytes() ||
		plan.Totals().ExpandedBytes() != 0 ||
		plan.Totals().RequiredBytes() != catalog.Manifest().Artifact().ReserveBytes() {
		t.Fatal("Linux CAS acquisition projection is incomplete")
	}

	otherCatalog := verifiedLinuxCatalog(t)
	otherCatalog.manifest = runtimecatalog.Manifest{}
	if projected, projectError := otherCatalog.LinuxArtifactPlan(authority); projectError == nil || len(projected.Artifacts()) != 0 {
		t.Fatal("substituted verified catalog projected package acquisition authority")
	}
	if projected, projectError := (VerifiedCatalog{}).LinuxArtifactPlan(authority); projectError == nil || len(projected.Artifacts()) != 0 {
		t.Fatal("unverified catalog projected package acquisition authority")
	}
}

func TestLinuxAuthorityRejectsCatalogPlanAndHostSubstitution(t *testing.T) {
	t.Parallel()

	catalog := verifiedLinuxCatalog(t)
	plan := linuxCatalogPlan(t, catalog)
	host := linuxHostBinding(t, "24.04")

	tests := []struct {
		name    string
		catalog VerifiedCatalog
		plan    []byte
		host    LinuxHostBinding
	}{
		{name: "unverified catalog", plan: plan.CanonicalBytes(), host: host},
		{name: "missing plan", catalog: catalog, host: host},
		{name: "different plan", catalog: catalog, plan: differentLinuxPlan(t).CanonicalBytes(), host: host},
		{name: "different release", catalog: catalog, plan: plan.CanonicalBytes(), host: linuxHostBinding(t, "22.04")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if authority, err := test.catalog.LinuxAuthority(test.plan, test.host); err == nil || authority.Valid() {
				t.Fatalf("LinuxAuthority() = valid authority, error %v", err)
			}
		})
	}
}

func TestLinuxHostBindingRejectsRootRemoteAndCrossUserState(t *testing.T) {
	t.Parallel()

	valid := LinuxHostBindingInput{
		VersionID: "24.04", InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
	}
	tests := []func(*LinuxHostBindingInput){
		func(v *LinuxHostBindingInput) { v.InvokingUID = 0 },
		func(v *LinuxHostBindingInput) { v.PrincipalID = "linux:uid:1001" },
		func(v *LinuxHostBindingInput) { v.MachineDigest = runtimeinstall.Hash{} },
		func(v *LinuxHostBindingInput) { v.RuntimeDirectory = "/run/user/1001" },
		func(v *LinuxHostBindingInput) { v.Endpoint = "tcp://127.0.0.1:2375" },
	}
	for index, edit := range tests {
		candidate := valid
		edit(&candidate)
		if _, err := NewLinuxHostBinding(candidate); err == nil {
			t.Fatalf("invalid host binding mutation %d succeeded", index)
		}
	}
	if binding, err := NewLinuxHostBinding(valid); err != nil || binding.input.InvokingUID != 1000 {
		t.Fatalf("NewLinuxHostBinding(valid) = %+v, %v", binding, err)
	}
}

func verifiedLinuxCatalog(t testing.TB) VerifiedCatalog {
	t.Helper()
	manifest := linuxManifest(t)
	return newVerifiedCatalog(
		manifest, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		runtimecatalog.SourceModeOfflineUserSelected, nil, false,
	)
}

func linuxCatalogPlan(t testing.TB, catalog VerifiedCatalog) runtimeinstall.Plan {
	t.Helper()
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatalf("CertifiedRuntime() error = %v", err)
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatalf("NewHostCapabilities() error = %v", err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), certified)
	if err != nil {
		t.Fatalf("NewPlanV1() error = %v", err)
	}
	return plan
}

func differentLinuxPlan(t testing.TB) runtimeinstall.Plan {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	certified, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "28.3.2",
		"stable", 42, runtimeinstall.Sum([]byte("different catalog")), runtimeinstall.Sum([]byte("different terms")),
		1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), certified)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func linuxHostBinding(t testing.TB, version string) LinuxHostBinding {
	t.Helper()
	binding, err := NewLinuxHostBinding(LinuxHostBindingInput{
		VersionID: version, InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
	})
	if err != nil {
		t.Fatalf("NewLinuxHostBinding() error = %v", err)
	}
	return binding
}

func linuxManifest(t testing.TB) runtimecatalog.Manifest {
	t.Helper()
	packages := linuxCatalogPackages()
	verification := linuxCatalogRepositoryArtifacts()
	distributionVerification := linuxCatalogDistributionRepositoryArtifacts()
	capabilities := []runtimecatalog.CapabilityProbe{
		runtimecatalog.CapabilityBindReadOnly, runtimecatalog.CapabilityComposeVersion,
		runtimecatalog.CapabilityEngineAPI, runtimecatalog.CapabilityLinuxContainers,
		runtimecatalog.CapabilityLocalEndpoint, runtimecatalog.CapabilityNetworkIsolation,
		runtimecatalog.CapabilityNoTCPListener, runtimecatalog.CapabilityRootless,
		runtimecatalog.CapabilitySecurityMode, runtimecatalog.CapabilityVolumePersistence,
	}
	packageSetDigest := runtimecatalog.LinuxPackageSetDigest(packages)
	var downloadBytes uint64
	packageIDs := make([]string, 0, len(packages))
	for _, pkg := range packages {
		downloadBytes += pkg.DownloadBytes
		packageIDs = append(packageIDs, pkg.Name)
	}
	for _, resource := range verification {
		downloadBytes += resource.DownloadBytes
	}
	for _, resource := range distributionVerification {
		downloadBytes += resource.DownloadBytes
	}
	input := runtimecatalog.ManifestInput{
		SchemaVersion: runtimecatalog.SupportedSchemaVersion, CatalogID: "docker-engine-ubuntu-noble-amd64",
		CatalogSequence: 42, SigningKeyID: "agentmemory-runtime-root-2026",
		SupportExpiresAt: time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC),
		Platform: runtimecatalog.PlatformPolicyInput{
			OperatingSystem: runtimecatalog.OSKindLinux, Architecture: runtimecatalog.ArchitectureX8664,
			Edition: "workstation", Distribution: "ubuntu", MinimumOSVersion: "24.4.0",
			MaximumOSVersion: "24.4.0", MinimumBuild: 1, MaximumBuild: 999999,
			MinimumCPUCores: 4, MinimumMemoryBytes: 16 << 30, MinimumFreeDiskBytes: 30 << 30,
			VirtualizationRequired: true,
		},
		Runtime: runtimecatalog.RuntimePolicyInput{
			Product: runtimecatalog.RuntimeProductDockerEngine, Channel: runtimecatalog.StableChannel,
			Version: "28.3.2", ComposeVersion: "2.39.1",
			Components: []runtimecatalog.RuntimeComponentInput{
				{Name: runtimecatalog.ComponentEngine, Version: "28.3.2"},
				{Name: runtimecatalog.ComponentCLI, Version: "28.3.2"},
				{Name: runtimecatalog.ComponentContainerd, Version: "1.7.27"},
				{Name: runtimecatalog.ComponentBuildx, Version: "0.25.0"},
				{Name: runtimecatalog.ComponentCompose, Version: "2.39.1"},
				{Name: runtimecatalog.ComponentRootlessExtras, Version: "28.3.2"},
			},
		},
		Artifact: runtimecatalog.ArtifactPolicyInput{
			DownloadBytes: downloadBytes, ExpandedBytes: downloadBytes + 200_000_000,
			ReserveBytes: downloadBytes + 400_000_000, SHA256: packageSetDigest,
			Sources: []runtimecatalog.OfficialSourceInput{
				{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/"},
				{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/"},
			},
			ProxyMode:     runtimecatalog.ProxyModeSystem,
			OfflinePolicy: runtimecatalog.OfflinePolicyUserSelectedOfficial,
			Publisher: runtimecatalog.PublisherPolicyInput{
				Verification: runtimecatalog.NativeVerificationPackageSignature,
				Identity:     "docker-apt-repository", SigningKeyIdentity: "docker-release-key-2026",
				PackageIdentity: "docker-engine-package-set",
			},
		},
		Install: runtimecatalog.InstallerPolicyInput{
			Executable: runtimecatalog.InstallerExecutableRootlessSetup,
			Arguments: []runtimecatalog.ArgumentTemplateInput{
				{Kind: runtimecatalog.ArgumentKindLiteral, Value: "install"},
				{Kind: runtimecatalog.ArgumentKindArtifactPath}, {Kind: runtimecatalog.ArgumentKindPlanDigest},
			},
			ServiceIdentity: "docker.service", RollbackStrategy: runtimecatalog.RollbackStrategyPackageManager,
			OwnershipChanges: []string{"repository:docker-stable", "service:docker.service"},
		},
		LinuxExecution: runtimecatalog.LinuxExecutionPolicyInput{
			PackageManager: runtimecatalog.LinuxPackageManagerAPT, PackageManagerVersion: "2.7.14build2",
			Codename: "noble", MinimumKernel: "6.8.0", MinimumAvailableMemory: 12 << 30,
			Repository: runtimecatalog.LinuxRepositoryInput{
				ID: "docker-stable", URL: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/"},
				Suite: "noble", Component: "stable", SigningKeyFingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
				SigningKeyDigest:       verification[0].SHA256,
				ConfigurationDigest:    runtimecatalog.DigestBytes([]byte("configuration")),
				MetadataAuthentication: runtimecatalog.LinuxRepositoryMetadataAuthenticationInline,
				MetadataDigest:         runtimecatalog.LinuxRepositoryMetadataDigest(verification),
				VerificationArtifacts:  verification,
			},
			VerificationRepositories: []runtimecatalog.LinuxRepositoryInput{{
				ID:    "ubuntu-noble-updates",
				URL:   runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/"},
				Suite: "noble-updates", Component: "main",
				SigningKeyFingerprint:  "F6ECB3762474EDA9D21B7022871920D1991BC93C",
				SigningKeyDigest:       distributionVerification[0].SHA256,
				ConfigurationDigest:    runtimecatalog.DigestBytes([]byte("ubuntu archive source configuration")),
				MetadataAuthentication: runtimecatalog.LinuxRepositoryMetadataAuthenticationInline,
				MetadataDigest:         runtimecatalog.LinuxRepositoryMetadataDigest(distributionVerification),
				VerificationArtifacts:  distributionVerification,
			}},
			Packages: packages, PackageSetDigest: packageSetDigest, SubordinateIDCount: 65536,
			RollbackHeadroomBytes: 200_000_000, AcquisitionSafetyBytes: 200_000_000,
			SELinuxEnforcingSupported: true, ServiceID: "docker.service",
			ServiceUnitDigest:  runtimecatalog.DigestBytes([]byte("unit")),
			RootlessToolPath:   "/usr/bin/dockerd-rootless-setuptool.sh",
			RootlessToolDigest: runtimecatalog.DigestBytes([]byte("rootless tool")),
			ProbeImage:         "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + runtimecatalog.DigestBytes([]byte("probe")).Hex(),
			ProbeImageDigest:   runtimecatalog.DigestBytes([]byte("probe")), ProbeContractVersion: "1",
			CapabilityPolicyDigest: runtimecatalog.LinuxCapabilityPolicyDigest(capabilities),
		},
		Prerequisites: []runtimecatalog.PrerequisiteInput{
			{Operation: runtimecatalog.PrerequisiteConfigureOfficialRepository, RepositoryID: "docker-stable"},
			{Operation: runtimecatalog.PrerequisiteConfigureSubordinateIDs, SubordinateIDCount: 65536},
			{Operation: runtimecatalog.PrerequisiteEnableUserService, ServiceID: "docker.service"},
			{Operation: runtimecatalog.PrerequisiteInstallVerifiedPackage, PackageIDs: packageIDs},
		},
		CapabilityProbes: capabilities,
		Terms: runtimecatalog.TermsPolicyInput{
			ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL:          runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "www.docker.com", PathPrefix: "/legal/docker-subscription-service-agreement"},
			Digest:       runtimecatalog.DigestBytes([]byte("terms")),
			Presentation: runtimecatalog.TermsPresentationAgentMemory,
		},
	}
	manifest, err := runtimecatalog.NewManifest(input)
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	return manifest
}

func linuxCatalogRepositoryArtifacts() []runtimecatalog.LinuxRepositoryArtifactInput {
	return []runtimecatalog.LinuxRepositoryArtifactInput{
		{
			Role: runtimecatalog.LinuxRepositoryArtifactSigningKey, DownloadBytes: 4_000,
			SHA256: runtimecatalog.DigestBytes([]byte("key")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/gpg"},
		},
		{
			Role: runtimecatalog.LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 50_000,
			SHA256: runtimecatalog.DigestBytes([]byte("InRelease")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/dists/noble/InRelease"},
		},
		{
			Role: runtimecatalog.LinuxRepositoryArtifactPackageIndex, DownloadBytes: 200_000,
			SHA256: runtimecatalog.DigestBytes([]byte("Packages")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "download.docker.com", PathPrefix: "/linux/ubuntu/dists/noble/stable/binary-amd64/Packages.gz"},
		},
	}
}

func linuxCatalogDistributionRepositoryArtifacts() []runtimecatalog.LinuxRepositoryArtifactInput {
	return []runtimecatalog.LinuxRepositoryArtifactInput{
		{
			Role: runtimecatalog.LinuxRepositoryArtifactSigningKey, DownloadBytes: 20_000,
			SHA256: runtimecatalog.DigestBytes([]byte("ubuntu archive key")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/project/ubuntu-archive-keyring.gpg"},
		},
		{
			Role: runtimecatalog.LinuxRepositoryArtifactSignedMetadata, DownloadBytes: 250_000,
			SHA256: runtimecatalog.DigestBytes([]byte("ubuntu noble-updates InRelease")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/dists/noble-updates/InRelease"},
		},
		{
			Role: runtimecatalog.LinuxRepositoryArtifactPackageIndex, DownloadBytes: 2_000_000,
			SHA256: runtimecatalog.DigestBytes([]byte("ubuntu noble-updates Packages")),
			Source: runtimecatalog.OfficialSourceInput{Scheme: "https", Host: "archive.ubuntu.com", PathPrefix: "/ubuntu/dists/noble-updates/main/binary-amd64/Packages.xz"},
		},
	}
}

func linuxCatalogPackages() []runtimecatalog.LinuxPackageInput {
	base := "/linux/ubuntu/dists/noble/pool/stable/amd64/"
	values := []struct {
		name, version string
		purpose       runtimecatalog.LinuxPackagePurpose
		size          uint64
	}{
		{"containerd.io", "1.7.27-1", runtimecatalog.LinuxPackagePurposeRuntime, 90_000_000},
		{"docker-buildx-plugin", "0.25.0-1~ubuntu.24.04~noble", runtimecatalog.LinuxPackagePurposeRuntime, 40_000_000},
		{"docker-ce", "5:28.3.2-1~ubuntu.24.04~noble", runtimecatalog.LinuxPackagePurposeRuntime, 25_000_000},
		{"docker-ce-cli", "5:28.3.2-1~ubuntu.24.04~noble", runtimecatalog.LinuxPackagePurposeRuntime, 16_000_000},
		{"docker-ce-rootless-extras", "5:28.3.2-1~ubuntu.24.04~noble", runtimecatalog.LinuxPackagePurposeRuntime, 6_000_000},
		{"docker-compose-plugin", "2.39.1-1~ubuntu.24.04~noble", runtimecatalog.LinuxPackagePurposeRuntime, 14_000_000},
		{"uidmap", "1:4.13+dfsg1-4ubuntu3.2", runtimecatalog.LinuxPackagePurposePrerequisite, 200_000},
	}
	result := make([]runtimecatalog.LinuxPackageInput, 0, len(values))
	for _, value := range values {
		host := "download.docker.com"
		repositoryID := "docker-stable"
		path := base + value.name + ".deb"
		if value.purpose == runtimecatalog.LinuxPackagePurposePrerequisite {
			host = "archive.ubuntu.com"
			repositoryID = "ubuntu-noble-updates"
			path = "/ubuntu/pool/main/s/shadow/uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb"
		}
		input := runtimecatalog.LinuxPackageInput{
			Name: value.name, Version: value.version, Purpose: value.purpose,
			RepositoryID: repositoryID, DownloadBytes: value.size,
			SHA256: runtimecatalog.DigestBytes([]byte(value.name + " artifact")),
			Source: runtimecatalog.OfficialSourceInput{
				Scheme: "https", Host: host, PathPrefix: path,
			},
		}
		input.NativeReceiptDigest = runtimecatalog.LinuxNativePackageReceiptDigest(runtimecatalog.LinuxPackageManagerAPT, input)
		result = append(result, input)
	}
	return result
}
