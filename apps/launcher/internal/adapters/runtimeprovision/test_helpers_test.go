package runtimeprovision

import (
	"strconv"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func adapterAuthority(t *testing.T) (runtimeinstall.Plan, runtimeport.LinuxAuthority) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.Sum([]byte("terms")), 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	return plan, adapterLinuxAuthority(t, plan, 0)
}

func adapterLinuxAuthority(
	t *testing.T,
	plan runtimeinstall.Plan,
	workloads uint32,
) runtimeport.LinuxAuthority {
	return adapterLinuxAuthorityForIdentity(t, plan, workloads, 1000, 1000, "/home/agentmemory", "/run/user/1000")
}

func adapterLinuxAuthorityForIdentity(
	t *testing.T,
	plan runtimeinstall.Plan,
	workloads uint32,
	uid uint32,
	gid uint32,
	home string,
	runtimeDirectory string,
) runtimeport.LinuxAuthority {
	t.Helper()
	probeDigest := runtimeinstall.Sum([]byte("probe-image"))
	packages := []runtimeport.PackageInput{
		{Name: "containerd.io", Version: "2.2.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-buildx-plugin", Version: "0.31.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-cli", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-rootless-extras", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-compose-plugin", Version: "5.1.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "uidmap", Version: "1:4.13+dfsg1-4", Purpose: runtimeport.PackagePurposePrerequisite},
	}
	for index := range packages {
		packages[index].RepositoryID = "docker-stable"
		if packages[index].Purpose == runtimeport.PackagePurposePrerequisite {
			packages[index].RepositoryID = "ubuntu-noble-updates"
		}
		packages[index].NativeReceiptDigest = runtimeinstall.Sum([]byte(packages[index].Name + packages[index].Version))
	}
	authority, err := runtimeport.NewLinuxAuthority(runtimeport.LinuxAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), TermsDigest: plan.TermsDigest(),
		TermsID: "docker-subscription-service-agreement", TermsVersion: "2025.07.02",
		TermsURL:          "https://www.docker.com/legal/docker-subscription-service-agreement/",
		TermsPresentation: "agentmemory",
		ArtifactDigest:    runtimeinstall.Sum([]byte("artifact")),
		SigningKeyID:      "agentmemory-runtime-root-2026", Architecture: runtimeinstall.ArchitectureAMD64,
		Distribution: "ubuntu", VersionID: "24.04", Codename: "noble", MinimumKernel: "6.8.0",
		MinimumCPUs: 4, MinimumTotalMemory: 16 << 30, MinimumAvailableMemory: 12 << 30,
		MinimumFreeDisk: 30 << 30, PackageManager: runtimeport.PackageManagerAPT, PackageManagerVersion: "2.8.3",
		Repository: runtimeport.RepositoryInput{
			ID: "docker-stable", URL: "https://download.docker.com/linux/ubuntu", Suite: "noble", Component: "stable",
			SigningKeyFingerprint: "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
			SigningKeyDigest:      runtimeinstall.Sum([]byte("key")), ConfigurationDigest: runtimeinstall.Sum([]byte("repo")),
			MetadataDigest: runtimeinstall.Sum([]byte("metadata")),
		},
		Packages: packages, RuntimeVersion: "29.6.1", ComposeVersion: "5.1.4", UnrelatedWorkloads: workloads,
		InvokingUID: uid, InvokingGID: gid, AccountName: "agentmemory",
		PrincipalID:   "linux:uid:" + strconv.FormatUint(uint64(uid), 10),
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: home,
		RuntimeDirectory: runtimeDirectory, Endpoint: "unix://" + runtimeDirectory + "/docker.sock",
		SubordinateIDCount: 65536, SELinuxEnforcing: true, ServiceID: "docker.service",
		ServiceUnitDigest: runtimeinstall.Sum([]byte("unit")), RootlessToolPath: "/usr/bin/dockerd-rootless-setuptool.sh",
		RootlessToolDigest:     runtimeinstall.Sum([]byte("tool")),
		ProbeImage:             "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probeDigest.String(),
		ProbeImageDigest:       probeDigest,
		ProbeContractVersion:   "1",
		CapabilityPolicyDigest: runtimeinstall.Sum([]byte("capability")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func adapterBaseHostCatalog(t *testing.T) (runtimeinstall.HostCapabilities, runtimeinstall.CertifiedRuntime) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.Sum([]byte("terms")), 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	return host, catalog
}
