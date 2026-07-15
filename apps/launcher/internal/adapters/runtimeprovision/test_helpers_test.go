package runtimeprovision

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type discardOwnership struct{}

type memoryRuntimeOwnershipRepository struct {
	mu     sync.Mutex
	exists bool
	record runtimeinstall.RuntimeOwnershipRecord
}

func (r *memoryRuntimeOwnershipRepository) LoadRuntimeOwnership(
	_ context.Context,
	operationID string,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.exists || r.record.OperationID() != operationID {
		return runtimeinstall.RuntimeOwnershipRecord{}, runtimeinstallapp.ErrOwnershipNotFound
	}
	return runtimeinstall.RestoreRuntimeOwnershipRecord(r.record.Snapshot())
}

func (r *memoryRuntimeOwnershipRepository) SaveRuntimeOwnership(
	_ context.Context,
	record runtimeinstall.RuntimeOwnershipRecord,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	restored, err := runtimeinstall.RestoreRuntimeOwnershipRecord(record.Snapshot())
	if err != nil {
		return errors.Join(runtimeinstallapp.ErrOwnershipIntegrity, err)
	}
	if r.exists {
		switch {
		case restored.Revision() == r.record.Revision() && restored.Digest() == r.record.Digest():
			return nil
		case !restored.CanFollow(r.record):
			return runtimeinstallapp.ErrOwnershipConflict
		}
	}
	r.record = restored
	r.exists = true
	return nil
}

func (discardOwnership) ResolveRuntimeOwnershipAuthority(
	_ context.Context,
	canonical []byte,
) (runtimeinstall.RuntimeOwnershipAuthority, error) {
	plan, err := runtimeinstall.DecodePlanV1(canonical)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipAuthority{}, err
	}
	endpoint := "unix:///run/user/1000/docker.sock"
	publisher := "docker-release-key-2026"
	if plan.Platform() == runtimeinstall.PlatformDarwin {
		endpoint = "unix:///Users/agentmemory/.docker/run/docker.sock"
		publisher = "developer-id-application-docker-inc-9bnsxjn65r"
	} else if plan.Platform() == runtimeinstall.PlatformWindows {
		endpoint = "npipe:////./pipe/docker_engine"
		publisher = "microsoft-authenticode-docker-inc"
	}
	return runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: endpoint, Context: explicitLocalEndpointContext, Publisher: publisher,
		PublisherDigest: runtimeinstall.Sum([]byte("publisher")), ArtifactDigest: runtimeinstall.Sum([]byte("artifact")),
		Components: []string{"compose@5.1.4", "engine@29.6.1"},
		Settings:   []string{"endpoint:" + endpoint},
	})
}

func (discardOwnership) LoadRuntimeOwnership(
	context.Context,
	string,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	return runtimeinstall.RuntimeOwnershipRecord{}, runtimeinstallapp.ErrOwnershipNotFound
}

func (discardOwnership) SaveRuntimeOwnership(
	context.Context,
	runtimeinstall.RuntimeOwnershipRecord,
) error {
	return nil
}

func (discardOwnership) CompensateRuntime(
	_ context.Context,
	request runtimeinstallapp.RuntimeCompensationRequest,
) (runtimeinstallapp.RuntimeCompensationReceipt, error) {
	runtimeDigest := runtimeinstall.Sum([]byte("preserved-test-runtime"))
	return runtimeinstallapp.NewRuntimeCompensationReceipt(
		request,
		runtimeinstallapp.RuntimeCompensationReceiptInput{
			RuntimeBeforeDigest: runtimeDigest, RuntimeAfterDigest: runtimeDigest,
			ArtifactCleanupDigest: runtimeinstall.Sum([]byte("test-cleanup")), RuntimePreserved: true,
		},
	)
}

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
		runtimeinstall.Sum([]byte("catalog")), linuxTerms(runtimeinstall.Sum([]byte("terms"))), 1, 2,
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
		TermsID: runtimeinstall.DockerEngineTermsID, TermsVersion: "apache-2.0",
		TermsURL:          "https://docs.docker.com/engine/",
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
		DockerCLIPath: "/usr/bin/docker", DockerCLISHA256: runtimeinstall.Sum([]byte("docker-cli")),
		ComposePluginPath:                 "/usr/libexec/docker/cli-plugins/docker-compose",
		ComposePluginSHA256:               runtimeinstall.Sum([]byte("compose-plugin")),
		PrivilegeToolPath:                 "/usr/bin/pkexec",
		PrivilegeToolSHA256:               runtimeinstall.Sum([]byte("pkexec")),
		PrivilegeToolPackage:              "pkexec",
		PrivilegeToolPackageVersion:       "124-2ubuntu1.24.04.3",
		PrivilegeToolPackageReceiptDigest: runtimeinstall.Sum([]byte("pkexec package receipt")),
		HelperTools: []runtimeport.HelperToolInput{
			{Role: runtimeport.HelperToolAPTGet, Path: "/usr/bin/apt-get", SHA256: runtimeinstall.Sum([]byte("apt-get")), Package: "apt", PackageVersion: "2.8.3", PackageReceiptDigest: runtimeinstall.Sum([]byte("apt receipt"))},
			{Role: runtimeport.HelperToolDPKGQuery, Path: "/usr/bin/dpkg-query", SHA256: runtimeinstall.Sum([]byte("dpkg-query")), Package: "dpkg", PackageVersion: "1.22.6ubuntu6.5", PackageReceiptDigest: runtimeinstall.Sum([]byte("dpkg receipt"))},
			{Role: runtimeport.HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
			{Role: runtimeport.HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "255.4-1ubuntu8.10", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		},
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
		runtimeinstall.Sum([]byte("catalog")), linuxTerms(runtimeinstall.Sum([]byte("terms"))), 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	return host, catalog
}

func linuxTerms(digest runtimeinstall.Hash) runtimeinstall.RuntimeTermsInput {
	return runtimeinstall.RuntimeTermsInput{
		ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
		Digest: digest, Presentation: runtimeinstall.TermsPresentationAgentMemory,
	}
}

func desktopTerms(digest runtimeinstall.Hash) runtimeinstall.RuntimeTermsInput {
	return runtimeinstall.RuntimeTermsInput{
		ID: runtimeinstall.DockerDesktopTermsID, Version: "2025.07.02",
		URL: "https://www.docker.com/legal/docker-subscription-service-agreement/", Digest: digest,
		Presentation: runtimeinstall.TermsPresentationAgentMemory,
	}
}
