package runtimeconsent

import (
	"context"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const brokerOperationID = "019f6000-1111-7111-8111-111111111111"

func TestConsentBrokerIssuesAndVerifiesLinuxAndDesktopReceipts(t *testing.T) {
	t.Parallel()
	broker, hub, binding, clock := brokerFixture(t)
	linuxAuthority := brokerLinuxAuthority(t)
	linuxRequest, err := runtimeport.NewLinuxConsentRequest(
		brokerOperationID, 1, linuxAuthority, runtimeport.Nonce{1},
		clock.now.Add(-time.Second), clock.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	go submitBrokerDecision(hub, binding, setupprogressapp.DecisionAccept)
	linuxReceipt, err := broker.AwaitLinuxConsent(context.Background(), linuxRequest)
	if err != nil || broker.VerifyLinuxConsent(context.Background(), linuxRequest, linuxReceipt) != nil ||
		broker.VerifyStoredLinuxConsent(context.Background(), linuxAuthority, linuxReceipt) != nil {
		t.Fatalf("Linux receipt error=%v", err)
	}

	desktopAuthority := brokerDesktopAuthority(t)
	desktopRequest, err := runtimeport.NewDesktopConsentRequest(
		brokerOperationID, 1, desktopAuthority, runtimeport.Nonce{2},
		clock.now.Add(-time.Second), clock.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	go submitBrokerDecision(hub, binding, setupprogressapp.DecisionAccept)
	desktopReceipt, err := broker.AwaitDesktopConsent(context.Background(), desktopRequest)
	if err != nil || broker.VerifyDesktopConsent(context.Background(), desktopRequest, desktopReceipt) != nil ||
		broker.VerifyStoredDesktopConsent(context.Background(), desktopAuthority, desktopReceipt) != nil {
		t.Fatalf("Desktop receipt error=%v", err)
	}
}

func TestConsentBrokerMapsDeclineCancellationAndIntegrityFailures(t *testing.T) {
	t.Parallel()
	broker, hub, binding, clock := brokerFixture(t)
	authority := brokerDesktopAuthority(t)
	request, _ := runtimeport.NewDesktopConsentRequest(
		brokerOperationID, 1, authority, runtimeport.Nonce{3},
		clock.now.Add(-time.Second), clock.now.Add(time.Minute),
	)
	go submitBrokerDecision(hub, binding, setupprogressapp.DecisionDecline)
	if _, err := broker.AwaitDesktopConsent(context.Background(), request); !errors.Is(err, runtimeport.ErrDesktopConsentDeclined) {
		t.Fatalf("decline error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := broker.AwaitLinuxConsent(cancelled, runtimeport.LinuxConsentRequest{}); !errors.Is(err, runtimeport.ErrLinuxConsentIntegrity) {
		t.Fatalf("zero Linux request error=%v", err)
	}
	if err := broker.VerifyDesktopConsent(cancelled, request, runtimeport.DesktopConsentReceipt{}); !errors.Is(err, runtimeport.ErrDesktopConsentIntegrity) {
		t.Fatalf("cancelled verification error=%v", err)
	}
	clock.now = time.Time{}
	if err := broker.VerifyStoredDesktopConsent(context.Background(), authority, runtimeport.DesktopConsentReceipt{}); !errors.Is(err, runtimeport.ErrDesktopConsentIntegrity) {
		t.Fatalf("zero clock error=%v", err)
	}
	if _, err := NewBroker(nil, nil, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("incomplete broker error=%v", err)
	}
}

type brokerClock struct{ now time.Time }

func (c *brokerClock) Now() time.Time { return c.now }

func brokerFixture(t testing.TB) (*Broker, *Hub, setupprogressapp.Binding, *brokerClock) {
	t.Helper()
	operationID, err := install.NewOperationID(brokerOperationID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := install.BindPlan([]byte("broker-parent"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := setupprogressapp.NewBinding(operationID, parent)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Bind(binding); err != nil {
		t.Fatal(err)
	}
	owners, keys := signerCapabilities(t)
	signer, err := NewProtectedSigner(owners, keys)
	if err != nil {
		t.Fatal(err)
	}
	clock := &brokerClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	broker, err := NewBroker(hub, signer, clock)
	if err != nil {
		t.Fatal(err)
	}
	return broker, hub, binding, clock
}

func submitBrokerDecision(
	hub *Hub,
	binding setupprogressapp.Binding,
	decision setupprogressapp.Decision,
) {
	_ = hub.SubmitRuntimeConsent(
		context.Background(), binding, decision, "019f6000-2222-7222-8222-222222222222",
	)
}

func brokerPlan(t testing.TB, platform runtimeinstall.Platform, architecture runtimeinstall.Architecture) runtimeinstall.Plan {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		platform, architecture, "26.0", true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		platform, architecture, "docker_desktop", "4.70.0", "stable", 7,
		runtimeinstall.Sum([]byte("catalog-"+platform.String())), brokerRuntimeTerms(platform, runtimeinstall.Sum([]byte("terms"))),
		500<<20, 2<<30,
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

func brokerRuntimeTerms(platform runtimeinstall.Platform, digest runtimeinstall.Hash) runtimeinstall.RuntimeTermsInput {
	if platform == runtimeinstall.PlatformLinux {
		return runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: digest, Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}
	}
	return runtimeinstall.RuntimeTermsInput{
		ID: runtimeinstall.DockerDesktopTermsID, Version: "2025.07.02",
		URL: "https://www.docker.com/legal/docker-subscription-service-agreement/", Digest: digest,
		Presentation: runtimeinstall.TermsPresentationAgentMemory,
	}
}

func brokerLinuxAuthority(t testing.TB) runtimeport.LinuxAuthority {
	t.Helper()
	plan := brokerPlan(t, runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64)
	packages := []runtimeport.PackageInput{
		{Name: "containerd.io", Version: "2.2.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-buildx-plugin", Version: "0.31.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-cli", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-ce-rootless-extras", Version: "5:29.6.1-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "docker-compose-plugin", Version: "5.1.4-1", Purpose: runtimeport.PackagePurposeRuntime},
		{Name: "uidmap", Version: "1:4.13-1", Purpose: runtimeport.PackagePurposePrerequisite},
	}
	for index := range packages {
		packages[index].RepositoryID = "docker-stable"
		if packages[index].Purpose == runtimeport.PackagePurposePrerequisite {
			packages[index].RepositoryID = "ubuntu-noble-updates"
		}
		packages[index].NativeReceiptDigest = runtimeinstall.Sum([]byte(packages[index].Name))
	}
	probe := runtimeinstall.Sum([]byte("probe"))
	authority, err := runtimeport.NewLinuxAuthority(runtimeport.LinuxAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), TermsDigest: plan.TermsDigest(),
		TermsID: runtimeinstall.DockerEngineTermsID, TermsVersion: "apache-2.0",
		TermsURL: "https://docs.docker.com/engine/", TermsPresentation: "agentmemory",
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")), SigningKeyID: "agentmemory-runtime-root-2026",
		Architecture: runtimeinstall.ArchitectureAMD64, Distribution: "ubuntu", VersionID: "24.04", Codename: "noble",
		MinimumKernel: "6.8.0", MinimumCPUs: 4, MinimumTotalMemory: 16 << 30,
		MinimumAvailableMemory: 12 << 30, MinimumFreeDisk: 30 << 30,
		PackageManager: runtimeport.PackageManagerAPT, PackageManagerVersion: "2.8.3",
		Repository: runtimeport.RepositoryInput{ID: "docker-stable", URL: "https://download.docker.com/linux/ubuntu",
			Suite: "noble", Component: "stable", SigningKeyFingerprint: "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
			SigningKeyDigest: runtimeinstall.Sum([]byte("key")), ConfigurationDigest: runtimeinstall.Sum([]byte("repo")),
			MetadataDigest: runtimeinstall.Sum([]byte("metadata"))},
		Packages: packages, RuntimeVersion: "29.6.1", ComposeVersion: "5.1.4", InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		HomeDirectory: "/home/agentmemory", RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
		SubordinateIDCount: 65536, SELinuxEnforcing: true, ServiceID: "docker.service",
		ServiceUnitDigest: runtimeinstall.Sum([]byte("unit")), RootlessToolPath: "/usr/bin/dockerd-rootless-setuptool.sh",
		RootlessToolDigest: runtimeinstall.Sum([]byte("rootless")),
		ProbeImage:         "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probe.String(), ProbeImageDigest: probe,
		ProbeContractVersion: "1", CapabilityPolicyDigest: runtimeinstall.Sum([]byte("policy")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func brokerDesktopAuthority(t testing.TB) runtimeport.DesktopAuthority {
	t.Helper()
	plan := brokerPlan(t, runtimeinstall.PlatformWindows, runtimeinstall.ArchitectureAMD64)
	probe := runtimeinstall.Sum([]byte("probe"))
	authority, err := runtimeport.NewDesktopAuthority(runtimeport.DesktopAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), Platform: runtimeinstall.PlatformWindows,
		Architecture: runtimeinstall.ArchitectureAMD64, PrincipalID: "sid:S-1-5-21-1000-1001-1002-1003", UserName: "Agent User",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: `C:\Users\Agent User`, OSProduct: "windows-11",
		MinimumOSVersion: "10.0.0", MaximumOSVersion: "10.0.0", MinimumBuild: 22631, MaximumBuild: 26199,
		MinimumCPUs: 4, MinimumTotalMemory: 16 << 30, MinimumAvailableMemory: 12 << 30, MinimumFreeDisk: 30 << 30,
		RuntimeVersion: "4.70.0", EngineVersion: "29.6.1", ComposeVersion: "5.1.4", Endpoint: "npipe:////./pipe/docker_engine",
		ArtifactPath:   `C:\Users\Agent User\AppData\Local\AgentMemory\runtime\Docker Desktop Installer.exe`,
		ArtifactSHA256: runtimeinstall.Sum([]byte("artifact")), ArtifactBytes: 500 << 20,
		ArtifactSourceURL: "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe",
		Publisher: runtimeport.DesktopPublisherInput{Kind: runtimeport.DesktopPublisherAuthenticode,
			Identity: "microsoft-authenticode-docker-inc", SigningKeyIdentity: "docker-authenticode-2026",
			PackageIdentity: "com.docker.docker", CertificateSHA256: runtimeinstall.Sum([]byte("certificate"))},
		Terms: runtimeport.DesktopTermsInput{ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL: "https://www.docker.com/legal/docker-subscription-service-agreement/", Digest: plan.TermsDigest()},
		InstallerArguments: []string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"},
		ApplicationPath:    `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop`, ApplicationExecutable: `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe`,
		DockerCLIPath:     `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe`,
		ComposePluginPath: `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\cli-plugins\docker-compose.exe`,
		ProbeImage:        "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + probe.String(), ProbeImageDigest: probe,
		ProbeContractVersion: "1", CapabilityPolicyDigest: runtimeinstall.Sum([]byte("policy")),
		RebootExitCodes: []uint32{1641, 3010}, WindowsFeatures: []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"},
		MinimumWSLVersion: "2.1.5", VendorUIMandatory: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
