package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006LinuxExecutableAuthoritiesBindExactSignedPackageReceipts(t *testing.T) {
	t.Parallel()
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	release := releaseinventory.Digest(runtimeinstall.Sum([]byte("release manifest")))
	tests := []struct {
		role      argvprocess.ExecutableRole
		path      string
		digest    runtimeinstall.Hash
		publisher string
		receipt   runtimeinstall.Hash
	}{
		{
			role: argvprocess.ExecutableRoleDockerCLI, path: authority.DockerCLIPath(),
			digest: authority.DockerCLISHA256(), publisher: "package:docker-ce-cli",
			receipt: launcherLinuxPackage(t, authority, "docker-ce-cli").NativeReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleComposePlugin, path: authority.ComposePluginPath(),
			digest: authority.ComposePluginSHA256(), publisher: "package:docker-compose-plugin",
			receipt: launcherLinuxPackage(t, authority, "docker-compose-plugin").NativeReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleRootlessSetup, path: authority.RootlessToolPath(),
			digest: authority.RootlessToolDigest(), publisher: "package:docker-ce-rootless-extras",
			receipt: launcherLinuxPackage(t, authority, "docker-ce-rootless-extras").NativeReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRolePrivilegeBroker, path: authority.PrivilegeToolPath(),
			digest: authority.PrivilegeToolSHA256(), publisher: "package:pkexec",
			receipt: authority.PrivilegeToolPackageReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleAPTTransaction, path: "/usr/bin/apt-get",
			digest: authority.HelperTools()[0].SHA256(), publisher: "package:apt",
			receipt: authority.HelperTools()[0].PackageReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleDPKGQuery, path: "/usr/bin/dpkg-query",
			digest: authority.HelperTools()[1].SHA256(), publisher: "package:dpkg",
			receipt: authority.HelperTools()[1].PackageReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleLoginCTL, path: "/usr/bin/loginctl",
			digest: authority.HelperTools()[2].SHA256(), publisher: "package:systemd",
			receipt: authority.HelperTools()[2].PackageReceiptDigest(),
		},
		{
			role: argvprocess.ExecutableRoleSystemCTL, path: "/usr/bin/systemctl",
			digest: authority.HelperTools()[3].SHA256(), publisher: "package:systemd",
			receipt: authority.HelperTools()[3].PackageReceiptDigest(),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.role), func(t *testing.T) {
			t.Parallel()
			executable, err := newNativeLinuxExecutableAuthority(authority, release, test.role)
			if err != nil || !executable.Valid() || executable.CanonicalPath() != test.path ||
				executable.SHA256() != test.digest || executable.OwnerIdentity() != "uid:0" ||
				executable.PublisherIdentity() != test.publisher ||
				executable.PublisherPolicyID() != "linux:package-receipt:v1" ||
				executable.PublisherTrustDigest() != test.receipt ||
				executable.ReleaseManifestDigest() != release ||
				executable.RuntimePlanDigest() != authority.PlanDigest() ||
				executable.Platform() != "linux" || executable.Architecture() != "amd64" {
				t.Fatalf("authority=%+v error=%v", executable, err)
			}
		})
	}
	if executable, err := newNativeLinuxExecutableAuthority(
		authority, release, argvprocess.ExecutableRoleRPMKeys,
	); err == nil || executable.Valid() {
		t.Fatalf("APT rpmkeys authority=%+v error=%v", executable, err)
	}
}

func TestPF006LinuxRPMKeysAuthorityUsesIndependentDistributionReceipt(t *testing.T) {
	t.Parallel()
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerDNF)
	release := releaseinventory.Digest(runtimeinstall.Sum([]byte("release manifest")))
	executable, err := newNativeLinuxExecutableAuthority(authority, release, argvprocess.ExecutableRoleRPMKeys)
	if err != nil || !executable.Valid() || executable.CanonicalID() != "rpmkeys" ||
		executable.CanonicalPath() != authority.RPMKeysPath() || executable.SHA256() != authority.RPMKeysSHA256() ||
		executable.PublisherIdentity() != "package:rpm" ||
		executable.PublisherTrustDigest() != authority.RPMKeysPackageReceiptDigest() {
		t.Fatalf("rpmkeys authority=%+v error=%v", executable, err)
	}
	privilege, err := newNativeLinuxExecutableAuthority(
		authority, release, argvprocess.ExecutableRolePrivilegeBroker,
	)
	if err != nil || privilege.PublisherIdentity() != "package:polkit" ||
		privilege.PublisherTrustDigest() != authority.PrivilegeToolPackageReceiptDigest() {
		t.Fatalf("privilege authority=%+v error=%v", privilege, err)
	}
	for _, role := range []argvprocess.ExecutableRole{
		argvprocess.ExecutableRoleDNFTransaction,
		argvprocess.ExecutableRoleLoginCTL,
		argvprocess.ExecutableRoleRPMQuery,
		argvprocess.ExecutableRoleSystemCTL,
	} {
		helper, helperError := newNativeLinuxExecutableAuthority(authority, release, role)
		if helperError != nil || !helper.Valid() {
			t.Fatalf("DNF helper authority role=%s valid=%v error=%v", role, helper.Valid(), helperError)
		}
	}
}

func TestPF006LinuxPackageReceiptVerifierRejectsAuthorityOrEvidenceSubstitution(t *testing.T) {
	t.Parallel()
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	release := releaseinventory.Digest(runtimeinstall.Sum([]byte("release manifest")))
	verifier, err := newNativeLinuxPackageReceiptVerifier(authority, release)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := newNativeLinuxExecutableAuthority(authority, release, argvprocess.ExecutableRoleDockerCLI)
	if err != nil {
		t.Fatal(err)
	}
	evidence := process.ExecutableEvidence{
		CanonicalID: executable.CanonicalID(), Digest: executable.SHA256(),
		OwnerIdentity: executable.OwnerIdentity(), ReleaseManifestDigest: executable.ReleaseManifestDigest(),
		RuntimePlanDigest: executable.RuntimePlanDigest(), Role: executable.Role(),
	}
	if err := verifier.VerifyLinuxPackageReceipt(t.Context(), executable, evidence); err != nil {
		t.Fatalf("exact package receipt error=%v", err)
	}

	tests := []struct {
		name string
		edit func(*argvprocess.ExecutableAuthority, *process.ExecutableEvidence)
	}{
		{name: "canonical identity", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.CanonicalID = "foreign"
		}},
		{name: "digest", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.Digest = runtimeinstall.Sum([]byte("foreign"))
		}},
		{name: "owner", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.OwnerIdentity = "uid:1000"
		}},
		{name: "release", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.ReleaseManifestDigest = runtimeinstall.Sum([]byte("foreign"))
		}},
		{name: "plan", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.RuntimePlanDigest = runtimeinstall.Sum([]byte("foreign"))
		}},
		{name: "role", edit: func(_ *argvprocess.ExecutableAuthority, value *process.ExecutableEvidence) {
			value.Role = argvprocess.ExecutableRoleComposePlugin
		}},
		{name: "authority", edit: func(value *argvprocess.ExecutableAuthority, _ *process.ExecutableEvidence) {
			*value, _ = newNativeLinuxExecutableAuthority(
				authority, release, argvprocess.ExecutableRoleComposePlugin,
			)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidateAuthority, candidateEvidence := executable, evidence
			test.edit(&candidateAuthority, &candidateEvidence)
			if err := verifier.VerifyLinuxPackageReceipt(
				t.Context(), candidateAuthority, candidateEvidence,
			); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
				t.Fatalf("substitution error=%v", err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifier.VerifyLinuxPackageReceipt(cancelled, executable, evidence); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification error=%v", err)
	}
	if candidate, err := newNativeLinuxPackageReceiptVerifier(runtimeport.LinuxAuthority{}, release); err == nil || candidate != nil {
		t.Fatalf("incomplete verifier=%+v error=%v", candidate, err)
	}
}

func launcherLinuxAuthority(t testing.TB, manager runtimeport.PackageManager) runtimeport.LinuxAuthority {
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
	prerequisite, distribution, codename, versionID, managerVersion := "uidmap", "ubuntu", "noble", "24.04", "2.8.3"
	repositoryURL := "https://download.docker.com/linux/ubuntu"
	if manager == runtimeport.PackageManagerDNF {
		prerequisite, distribution, codename, versionID, managerVersion = "shadow-utils", "fedora", "fedora-42", "42", "5.2.12"
		repositoryURL = "https://download.docker.com/linux/fedora"
	}
	packages := []runtimeport.PackageInput{
		{Name: "containerd.io", Version: "2.2.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-buildx-plugin", Version: "0.31.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-cli", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-rootless-extras", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-compose-plugin", Version: "5.1.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: prerequisite, Version: "1:4.13-1", Purpose: runtimeport.PackagePurposePrerequisite},
	}
	for index := range packages {
		packages[index].RepositoryID = "docker-stable"
		if packages[index].Purpose == runtimeport.PackagePurposePrerequisite {
			packages[index].RepositoryID = distribution + "-base"
		}
		packages[index].NativeReceiptDigest = runtimeinstall.Sum([]byte(packages[index].Name + packages[index].Version))
	}
	probeDigest := runtimeinstall.Sum([]byte("probe image"))
	input := runtimeport.LinuxAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), TermsDigest: plan.TermsDigest(),
		TermsID: runtimeinstall.DockerEngineTermsID, TermsVersion: "apache-2.0",
		TermsURL: "https://docs.docker.com/engine/", TermsPresentation: "agentmemory",
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")), SigningKeyID: "runtime-root-2026",
		Architecture: runtimeinstall.ArchitectureAMD64, Distribution: distribution, VersionID: versionID,
		Codename: codename, MinimumKernel: "6.8.0", MinimumCPUs: 4, MinimumTotalMemory: 16 << 30,
		MinimumAvailableMemory: 12 << 30, MinimumFreeDisk: 30 << 30,
		PackageManager: manager, PackageManagerVersion: managerVersion,
		Repository: runtimeport.RepositoryInput{
			ID: "docker-stable", URL: repositoryURL, Suite: codename, Component: "stable",
			SigningKeyFingerprint: "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
			SigningKeyDigest:      runtimeinstall.Sum([]byte("key")), ConfigurationDigest: runtimeinstall.Sum([]byte("repository")),
			MetadataDigest: runtimeinstall.Sum([]byte("metadata")),
		},
		Packages: packages, RuntimeVersion: "29.6.1", ComposeVersion: "5.1.4",
		InvokingUID: 1000, InvokingGID: 1000, AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
		SubordinateIDCount: 65536, SELinuxEnforcing: true, ServiceID: "docker.service",
		ServiceUnitDigest: runtimeinstall.Sum([]byte("service unit")),
		DockerCLIPath:     "/usr/bin/docker", DockerCLISHA256: runtimeinstall.Sum([]byte("docker CLI")),
		ComposePluginPath:   "/usr/libexec/docker/cli-plugins/docker-compose",
		ComposePluginSHA256: runtimeinstall.Sum([]byte("compose plugin")),
		PrivilegeToolPath:   "/usr/bin/pkexec", PrivilegeToolSHA256: runtimeinstall.Sum([]byte("pkexec")),
		PrivilegeToolPackage: "pkexec", PrivilegeToolPackageVersion: "124-2ubuntu1.24.04.3",
		PrivilegeToolPackageReceiptDigest: runtimeinstall.Sum([]byte("pkexec package receipt")),
		HelperTools:                       launcherHelperTools(manager),
		RootlessToolPath:                  "/usr/bin/dockerd-rootless-setuptool.sh",
		RootlessToolDigest:                runtimeinstall.Sum([]byte("rootless setup")),
		ProbeImage:                        "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probeDigest.String(),
		ProbeImageDigest:                  probeDigest, ProbeContractVersion: "1",
		CapabilityPolicyDigest: runtimeinstall.Sum([]byte("capability policy")),
	}
	if manager == runtimeport.PackageManagerDNF {
		input.RPMKeysPath = "/usr/bin/rpmkeys"
		input.RPMKeysSHA256 = runtimeinstall.Sum([]byte("rpmkeys"))
		input.RPMKeysPackageVersion = "4.20.1-1.fc42"
		input.RPMKeysPackageReceiptDigest = runtimeinstall.Sum([]byte("rpm package receipt"))
		input.PrivilegeToolPackage = "polkit"
		input.PrivilegeToolPackageVersion = "126-3.fc42.2"
		input.PrivilegeToolPackageReceiptDigest = runtimeinstall.Sum([]byte("polkit package receipt"))
	}
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func launcherHelperTools(manager runtimeport.PackageManager) []runtimeport.HelperToolInput {
	if manager == runtimeport.PackageManagerDNF {
		return []runtimeport.HelperToolInput{
			{Role: runtimeport.HelperToolDNF5, Path: "/usr/bin/dnf5", SHA256: runtimeinstall.Sum([]byte("dnf5")), Package: "dnf5", PackageVersion: "5.2.15.0-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("dnf5 receipt"))},
			{Role: runtimeport.HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
			{Role: runtimeport.HelperToolRPMQuery, Path: "/usr/bin/rpm", SHA256: runtimeinstall.Sum([]byte("rpm")), Package: "rpm", PackageVersion: "4.20.1-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("rpm receipt"))},
			{Role: runtimeport.HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		}
	}
	return []runtimeport.HelperToolInput{
		{Role: runtimeport.HelperToolAPTGet, Path: "/usr/bin/apt-get", SHA256: runtimeinstall.Sum([]byte("apt-get")), Package: "apt", PackageVersion: "2.8.3", PackageReceiptDigest: runtimeinstall.Sum([]byte("apt receipt"))},
		{Role: runtimeport.HelperToolDPKGQuery, Path: "/usr/bin/dpkg-query", SHA256: runtimeinstall.Sum([]byte("dpkg-query")), Package: "dpkg", PackageVersion: "1.22.6ubuntu6.5", PackageReceiptDigest: runtimeinstall.Sum([]byte("dpkg receipt"))},
		{Role: runtimeport.HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		{Role: runtimeport.HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
	}
}

func launcherLinuxPackage(t testing.TB, authority runtimeport.LinuxAuthority, name string) runtimeport.Package {
	t.Helper()
	for _, pkg := range authority.Packages() {
		if pkg.Name() == name {
			return pkg
		}
	}
	t.Fatalf("package %s was not found", name)
	return runtimeport.Package{}
}
