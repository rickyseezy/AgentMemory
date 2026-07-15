package runtimeprovision

import (
	"slices"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxAuthorityRequiresCompleteExactSignedPackagePolicy(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	valid := testAuthorityInput(plan)

	tests := []struct {
		name   string
		mutate func(*LinuxAuthorityInput)
	}{
		{name: "valid", mutate: func(*LinuxAuthorityInput) {}},
		{name: "root principal", mutate: func(input *LinuxAuthorityInput) { input.InvokingUID = 0 }},
		{name: "remote repository", mutate: func(input *LinuxAuthorityInput) { input.Repository.URL = "https://mirror.invalid/linux/ubuntu" }},
		{name: "mutable version", mutate: func(input *LinuxAuthorityInput) { input.Packages[0].Version = "latest" }},
		{name: "wildcard version", mutate: func(input *LinuxAuthorityInput) { input.Packages[0].Version = "29.*" }},
		{name: "missing package", mutate: func(input *LinuxAuthorityInput) { input.Packages = input.Packages[:6] }},
		{name: "wrong prerequisite", mutate: func(input *LinuxAuthorityInput) { input.Packages[6].Name = "shadow-utils" }},
		{name: "unsorted packages", mutate: func(input *LinuxAuthorityInput) {
			input.Packages[0], input.Packages[1] = input.Packages[1], input.Packages[0]
		}},
		{name: "unsafe home", mutate: func(input *LinuxAuthorityInput) { input.HomeDirectory = "/tmp/user" }},
		{name: "remote endpoint", mutate: func(input *LinuxAuthorityInput) { input.Endpoint = "tcp://127.0.0.1:2375" }},
		{name: "small subordinate range", mutate: func(input *LinuxAuthorityInput) { input.SubordinateIDCount = 65535 }},
		{name: "missing native receipt", mutate: func(input *LinuxAuthorityInput) { input.Packages[2].NativeReceiptDigest = runtimeinstall.Hash{} }},
		{name: "missing package repository", mutate: func(input *LinuxAuthorityInput) { input.Packages[2].RepositoryID = "" }},
		{name: "unbound catalog", mutate: func(input *LinuxAuthorityInput) { input.CatalogDigest = runtimeinstall.Hash{} }},
		{name: "unbound terms", mutate: func(input *LinuxAuthorityInput) { input.TermsDigest = runtimeinstall.Hash{} }},
		{name: "unknown architecture", mutate: func(input *LinuxAuthorityInput) { input.Architecture = runtimeinstall.ArchitectureUnknown }},
		{name: "manager distribution mismatch", mutate: func(input *LinuxAuthorityInput) { input.PackageManager = PackageManagerDNF }},
		{name: "repository suite mismatch", mutate: func(input *LinuxAuthorityInput) { input.Repository.Suite = "jammy" }},
		{name: "docker path", mutate: func(input *LinuxAuthorityInput) { input.DockerCLIPath = "/tmp/docker" }},
		{name: "docker digest", mutate: func(input *LinuxAuthorityInput) { input.DockerCLISHA256 = runtimeinstall.Hash{} }},
		{name: "compose path", mutate: func(input *LinuxAuthorityInput) { input.ComposePluginPath = "/tmp/compose" }},
		{name: "compose digest", mutate: func(input *LinuxAuthorityInput) { input.ComposePluginSHA256 = runtimeinstall.Hash{} }},
		{name: "privilege path", mutate: func(input *LinuxAuthorityInput) { input.PrivilegeToolPath = "/tmp/pkexec" }},
		{name: "privilege digest", mutate: func(input *LinuxAuthorityInput) { input.PrivilegeToolSHA256 = runtimeinstall.Hash{} }},
		{name: "privilege package", mutate: func(input *LinuxAuthorityInput) { input.PrivilegeToolPackage = "polkit" }},
		{name: "privilege package version", mutate: func(input *LinuxAuthorityInput) { input.PrivilegeToolPackageVersion = "latest" }},
		{name: "privilege receipt", mutate: func(input *LinuxAuthorityInput) { input.PrivilegeToolPackageReceiptDigest = runtimeinstall.Hash{} }},
		{name: "helper omitted", mutate: func(input *LinuxAuthorityInput) { input.HelperTools = input.HelperTools[:3] }},
		{name: "helper order", mutate: func(input *LinuxAuthorityInput) {
			input.HelperTools[0], input.HelperTools[1] = input.HelperTools[1], input.HelperTools[0]
		}},
		{name: "helper path", mutate: func(input *LinuxAuthorityInput) { input.HelperTools[0].Path = "/tmp/apt-get" }},
		{name: "helper receipt", mutate: func(input *LinuxAuthorityInput) { input.HelperTools[0].PackageReceiptDigest = runtimeinstall.Hash{} }},
		{name: "apt rpmkeys", mutate: func(input *LinuxAuthorityInput) {
			input.RPMKeysPath = "/usr/bin/rpmkeys"
			input.RPMKeysSHA256 = runtimeinstall.Sum([]byte("rpmkeys"))
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := cloneAuthorityInput(valid)
			test.mutate(&candidate)
			authority, err := NewLinuxAuthority(candidate)
			if test.name == "valid" {
				if err != nil || !authority.ValidFor(plan) || authority.ComposeVersion() != candidate.ComposeVersion {
					t.Fatalf("NewLinuxAuthority(valid) = valid:%v error:%v", authority.Valid(), err)
				}
				return
			}
			if err == nil || authority.Valid() {
				t.Fatalf("NewLinuxAuthority(%s) unexpectedly succeeded", test.name)
			}
		})
	}
}

func TestLinuxAuthorityCopiesPackagesAndBindsEveryPrivilegePostcondition(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	input := testAuthorityInput(plan)
	authority, err := NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Packages[0].Name = "mutated"
	input.HelperTools[0].Path = "/tmp/mutated"
	packages := authority.Packages()
	packages[0] = Package{}
	helperTools := authority.HelperTools()
	helperTools[0] = HelperTool{}
	if authority.Packages()[0].Name() != "containerd.io" ||
		authority.HelperTools()[0].Path() != "/usr/bin/apt-get" || !authority.Valid() {
		t.Fatal("authority package state was mutable through an input or projection")
	}

	states := make(map[runtimeinstall.Hash]struct{})
	for _, operation := range []PrivilegeOperation{
		PrivilegeConfigureRepository,
		PrivilegeInstallPackages,
		PrivilegeConfigureSubordinateIDs,
		PrivilegeEnableUserService,
		PrivilegeVerifyManagedState,
	} {
		state, stateError := ExpectedPrivilegeState(authority, operation)
		if stateError != nil || state.IsZero() {
			t.Fatalf("ExpectedPrivilegeState(%s) error = %v", operation, stateError)
		}
		if _, duplicate := states[state]; duplicate {
			t.Fatalf("operation %s was not domain separated", operation)
		}
		states[state] = struct{}{}
	}
	packageState, _ := ExpectedPackageStateDigest(authority)
	repositoryState, _ := ExpectedRepositoryStateDigest(authority)
	if packageState.IsZero() || repositoryState.IsZero() || packageState == repositoryState {
		t.Fatal("package and repository evidence were not independently bound")
	}
}

func TestLinuxAuthorityProjectsEverySignedFieldWithoutMutation(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	input := testAuthorityInput(plan)
	authority, err := NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	repository := authority.Repository()
	if authority.PlanDigest() != input.PlanDigest || authority.CatalogDigest() != input.CatalogDigest ||
		authority.TermsDigest() != input.TermsDigest ||
		authority.ArtifactDigest() != input.ArtifactDigest || authority.Architecture() != input.Architecture ||
		authority.Distribution() != input.Distribution || authority.VersionID() != input.VersionID ||
		authority.Codename() != input.Codename || authority.MinimumKernel() != input.MinimumKernel ||
		authority.MinimumCPUs() != input.MinimumCPUs || authority.MinimumTotalMemory() != input.MinimumTotalMemory ||
		authority.MinimumAvailableMemory() != input.MinimumAvailableMemory || authority.MinimumFreeDisk() != input.MinimumFreeDisk ||
		authority.PackageManager() != input.PackageManager || authority.PackageManagerVersion() != input.PackageManagerVersion ||
		authority.RuntimeVersion() != input.RuntimeVersion || authority.ComposeVersion() != input.ComposeVersion ||
		authority.UnrelatedWorkloads() != input.UnrelatedWorkloads || authority.InvokingUID() != input.InvokingUID ||
		authority.InvokingGID() != input.InvokingGID || authority.AccountName() != input.AccountName ||
		authority.HomeDirectory() != input.HomeDirectory || authority.RuntimeDirectory() != input.RuntimeDirectory ||
		authority.Endpoint() != input.Endpoint || authority.SELinuxEnforcingSupported() != input.SELinuxEnforcing ||
		authority.ServiceID() != input.ServiceID || authority.RootlessToolPath() != input.RootlessToolPath ||
		authority.RootlessToolDigest() != input.RootlessToolDigest ||
		authority.DockerCLIPath() != input.DockerCLIPath || authority.DockerCLISHA256() != input.DockerCLISHA256 ||
		authority.ComposePluginPath() != input.ComposePluginPath || authority.ComposePluginSHA256() != input.ComposePluginSHA256 ||
		authority.RPMKeysPath() != input.RPMKeysPath || authority.RPMKeysSHA256() != input.RPMKeysSHA256 ||
		authority.RPMKeysPackageVersion() != input.RPMKeysPackageVersion ||
		authority.RPMKeysPackageReceiptDigest() != input.RPMKeysPackageReceiptDigest ||
		authority.PrivilegeToolPath() != input.PrivilegeToolPath ||
		authority.PrivilegeToolSHA256() != input.PrivilegeToolSHA256 ||
		authority.PrivilegeToolPackage() != input.PrivilegeToolPackage ||
		authority.PrivilegeToolPackageVersion() != input.PrivilegeToolPackageVersion ||
		authority.PrivilegeToolPackageReceiptDigest() != input.PrivilegeToolPackageReceiptDigest ||
		len(authority.HelperTools()) != 4 || authority.HelperTools()[0].Role() != HelperToolAPTGet ||
		authority.ProbeImage() != input.ProbeImage || authority.ProbeImageDigest() != input.ProbeImageDigest ||
		authority.ProbeContractVersion() != input.ProbeContractVersion ||
		authority.CapabilityPolicyDigest() != input.CapabilityPolicyDigest {
		t.Fatal("one or more signed authority fields were not projected exactly")
	}
	if repository.URL() != input.Repository.URL || repository.Suite() != input.Repository.Suite ||
		repository.Component() != input.Repository.Component || repository.MetadataDigest() != input.Repository.MetadataDigest {
		t.Fatal("repository authority projection drifted")
	}
	if authority.Packages()[6].RepositoryID() != "ubuntu-noble-updates" {
		t.Fatal("package repository binding drifted")
	}
	if AuthorityDigestBytes([]byte("binding")).IsZero() {
		t.Fatal("authority binding digest was zero")
	}

	dnf := cloneAuthorityInput(input)
	dnf.Distribution, dnf.VersionID, dnf.Codename = "fedora", "42", "42"
	dnf.PackageManager, dnf.PackageManagerVersion = PackageManagerDNF, "4.21.1"
	dnf.Repository.URL, dnf.Repository.Suite = "https://download.docker.com/linux/fedora", "42"
	dnf.Packages[6].Name, dnf.Packages[6].Version = "shadow-utils", "4.15.1-12.fc42"
	dnf.Packages[6].NativeReceiptDigest = runtimeinstall.Sum([]byte("shadow-utils-receipt"))
	dnf.RPMKeysPath, dnf.RPMKeysSHA256 = "/usr/bin/rpmkeys", runtimeinstall.Sum([]byte("rpmkeys"))
	dnf.RPMKeysPackageVersion = "4.20.1-1.fc42"
	dnf.RPMKeysPackageReceiptDigest = runtimeinstall.Sum([]byte("rpm package receipt"))
	dnf.PrivilegeToolPackage = "polkit"
	dnf.PrivilegeToolPackageVersion = "126-3.fc42.2"
	dnf.PrivilegeToolPackageReceiptDigest = runtimeinstall.Sum([]byte("polkit package receipt"))
	dnf.HelperTools = testDNFHelperTools()
	if dnfAuthority, dnfError := NewLinuxAuthority(dnf); dnfError != nil || dnfAuthority.PackageManager() != PackageManagerDNF {
		t.Fatalf("valid DNF authority rejected: %v", dnfError)
	}
}

func TestLinuxAuthorityRejectsMalformedIdentityPathRepositoryAndProbeImageForms(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	valid := testAuthorityInput(plan)
	mutations := []func(*LinuxAuthorityInput){
		func(input *LinuxAuthorityInput) { input.AccountName = "agent memory" },
		func(input *LinuxAuthorityInput) { input.PrincipalID = "linux uid 1000" },
		func(input *LinuxAuthorityInput) { input.Repository.SigningKeyFingerprint = "lowercase" },
		func(input *LinuxAuthorityInput) { input.HomeDirectory = "relative/home" },
		func(input *LinuxAuthorityInput) { input.HomeDirectory = "/home/../root" },
		func(input *LinuxAuthorityInput) { input.ProbeImage = "docker.io/probe:latest" },
		func(input *LinuxAuthorityInput) {
			input.ProbeImage = "DOCKER.IO/probe@sha256:" + input.ProbeImageDigest.String()
		},
		func(input *LinuxAuthorityInput) {
			input.ProbeImage = "docker.io//probe@sha256:" + input.ProbeImageDigest.String()
		},
		func(input *LinuxAuthorityInput) { input.PackageManagerVersion = "latest" },
		func(input *LinuxAuthorityInput) { input.Repository.Component = "testing" },
		func(input *LinuxAuthorityInput) { input.TermsID = "" },
		func(input *LinuxAuthorityInput) { input.TermsURL = "https://example.invalid/terms" },
		func(input *LinuxAuthorityInput) { input.TermsPresentation = "native_vendor_ui" },
	}
	for index, mutate := range mutations {
		candidate := cloneAuthorityInput(valid)
		mutate(&candidate)
		if authority, err := NewLinuxAuthority(candidate); err == nil || authority.Valid() {
			t.Fatalf("malformed authority mutation %d succeeded", index)
		}
	}
}

func testPlan(t *testing.T) runtimeinstall.Plan {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest := runtimeinstall.Sum([]byte("catalog"))
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1",
		"stable", 7, catalogDigest, runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testAuthorityInput(plan runtimeinstall.Plan) LinuxAuthorityInput {
	probeDigest := runtimeinstall.Sum([]byte("probe-image"))
	packages := []PackageInput{
		{Name: "containerd.io", Version: "2.2.4-1", Purpose: PackagePurposeRuntime},
		{Name: "docker-buildx-plugin", Version: "0.31.1-1~ubuntu.24.04~noble", Purpose: PackagePurposeRuntime},
		{Name: "docker-ce", Version: "5:29.6.1-1~ubuntu.24.04~noble", Purpose: PackagePurposeRuntime},
		{Name: "docker-ce-cli", Version: "5:29.6.1-1~ubuntu.24.04~noble", Purpose: PackagePurposeRuntime},
		{Name: "docker-ce-rootless-extras", Version: "5:29.6.1-1~ubuntu.24.04~noble", Purpose: PackagePurposeRuntime},
		{Name: "docker-compose-plugin", Version: "5.1.4-1~ubuntu.24.04~noble", Purpose: PackagePurposeRuntime},
		{Name: "uidmap", Version: "1:4.13+dfsg1-4ubuntu3.2", Purpose: PackagePurposePrerequisite},
	}
	for index := range packages {
		packages[index].RepositoryID = "docker-stable"
		if packages[index].Purpose == PackagePurposePrerequisite {
			packages[index].RepositoryID = "ubuntu-noble-updates"
		}
		packages[index].NativeReceiptDigest = runtimeinstall.Sum([]byte(packages[index].Name + packages[index].Version))
	}
	return LinuxAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), TermsDigest: plan.TermsDigest(),
		TermsID: runtimeinstall.DockerEngineTermsID, TermsVersion: "apache-2.0",
		TermsURL:          "https://docs.docker.com/engine/",
		TermsPresentation: "agentmemory",
		ArtifactDigest:    runtimeinstall.Sum([]byte("artifact")),
		SigningKeyID:      "agentmemory-runtime-root-2026", Architecture: runtimeinstall.ArchitectureAMD64,
		Distribution: "ubuntu", VersionID: "24.04", Codename: "noble", MinimumKernel: "6.8.0",
		MinimumCPUs: 4, MinimumTotalMemory: 16 << 30, MinimumAvailableMemory: 12 << 30,
		MinimumFreeDisk: 30 << 30, PackageManager: PackageManagerAPT, PackageManagerVersion: "2.8.3",
		Repository: RepositoryInput{
			ID: "docker-stable", URL: "https://download.docker.com/linux/ubuntu", Suite: "noble", Component: "stable",
			SigningKeyFingerprint: "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
			SigningKeyDigest:      runtimeinstall.Sum([]byte("key")), ConfigurationDigest: runtimeinstall.Sum([]byte("repo")),
			MetadataDigest: runtimeinstall.Sum([]byte("metadata")),
		},
		Packages: packages, RuntimeVersion: "29.6.1", ComposeVersion: "5.1.4", InvokingUID: 1000,
		InvokingGID: 1000, AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
		SubordinateIDCount: 65536, SELinuxEnforcing: true, ServiceID: "docker.service",
		ServiceUnitDigest: runtimeinstall.Sum([]byte("unit")), RootlessToolPath: "/usr/bin/dockerd-rootless-setuptool.sh",
		DockerCLIPath: "/usr/bin/docker", DockerCLISHA256: runtimeinstall.Sum([]byte("docker-cli")),
		ComposePluginPath:                 "/usr/libexec/docker/cli-plugins/docker-compose",
		ComposePluginSHA256:               runtimeinstall.Sum([]byte("compose-plugin")),
		PrivilegeToolPath:                 "/usr/bin/pkexec",
		PrivilegeToolSHA256:               runtimeinstall.Sum([]byte("pkexec")),
		PrivilegeToolPackage:              "pkexec",
		PrivilegeToolPackageVersion:       "124-2ubuntu1.24.04.3",
		PrivilegeToolPackageReceiptDigest: runtimeinstall.Sum([]byte("pkexec package receipt")),
		HelperTools:                       testAPTHelperTools(),
		RootlessToolDigest:                runtimeinstall.Sum([]byte("rootless-tool")),
		ProbeImage:                        "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probeDigest.String(),
		ProbeImageDigest:                  probeDigest,
		ProbeContractVersion:              "1",
		CapabilityPolicyDigest:            runtimeinstall.Sum([]byte("capability-policy")),
	}
}

func cloneAuthorityInput(input LinuxAuthorityInput) LinuxAuthorityInput {
	clone := input
	clone.Packages = slices.Clone(input.Packages)
	clone.HelperTools = slices.Clone(input.HelperTools)
	return clone
}

func testAPTHelperTools() []HelperToolInput {
	return []HelperToolInput{
		{Role: HelperToolAPTGet, Path: "/usr/bin/apt-get", SHA256: runtimeinstall.Sum([]byte("apt-get")), Package: "apt", PackageVersion: "2.8.3", PackageReceiptDigest: runtimeinstall.Sum([]byte("apt receipt"))},
		{Role: HelperToolDPKGQuery, Path: "/usr/bin/dpkg-query", SHA256: runtimeinstall.Sum([]byte("dpkg-query")), Package: "dpkg", PackageVersion: "1.22.6ubuntu6.5", PackageReceiptDigest: runtimeinstall.Sum([]byte("dpkg receipt"))},
		{Role: HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		{Role: HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
	}
}

func testDNFHelperTools() []HelperToolInput {
	return []HelperToolInput{
		{Role: HelperToolDNF5, Path: "/usr/bin/dnf5", SHA256: runtimeinstall.Sum([]byte("dnf5")), Package: "dnf5", PackageVersion: "5.2.15.0-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("dnf5 receipt"))},
		{Role: HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		{Role: HelperToolRPMQuery, Path: "/usr/bin/rpm", SHA256: runtimeinstall.Sum([]byte("rpm")), Package: "rpm", PackageVersion: "4.20.1-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("rpm receipt"))},
		{Role: HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
	}
}
