package runtimeprovision

import (
	"slices"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDesktopAuthorityAcceptsOnlyClosedCertifiedMacAndWindowsPlans(t *testing.T) {
	t.Parallel()
	macPlan := desktopTestPlan(t, runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64)
	mac := desktopAuthorityInput(macPlan, runtimeinstall.PlatformDarwin)
	windowsPlan := desktopTestPlan(t, runtimeinstall.PlatformWindows, runtimeinstall.ArchitectureAMD64)
	windows := desktopAuthorityInput(windowsPlan, runtimeinstall.PlatformWindows)

	for _, test := range []struct {
		name  string
		plan  runtimeinstall.Plan
		input DesktopAuthorityInput
	}{
		{name: "macOS ARM64", plan: macPlan, input: mac},
		{name: "Windows AMD64", plan: windowsPlan, input: windows},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority, err := NewDesktopAuthority(test.input)
			if err != nil || !authority.ValidFor(test.plan) || authority.Digest().IsZero() ||
				authority.Publisher().CertificateSHA256().IsZero() || authority.Terms().Digest().IsZero() ||
				authority.DockerCLISHA256().IsZero() || authority.ComposePluginSHA256().IsZero() ||
				authority.ExecutableOwnerIdentity() == "" || authority.ExecutablePublisherIdentity() == "" ||
				authority.ExecutablePublisherPolicyID() == "" {
				t.Fatalf("valid desktop authority = %#v, %v", authority, err)
			}
			arguments := authority.InstallerArguments()
			arguments[0] = "attacker"
			if authority.InstallerArguments()[0] == "attacker" {
				t.Fatal("installer argument projection was mutable")
			}
			features := authority.WindowsFeatures()
			if len(features) != 0 {
				features[0] = "attacker"
				if authority.WindowsFeatures()[0] == "attacker" {
					t.Fatal("Windows prerequisite projection was mutable")
				}
			}
		})
	}
}

func TestDesktopAuthorityRejectsEveryAmbientOrBroadenedExecutionField(t *testing.T) {
	t.Parallel()
	plan := desktopTestPlan(t, runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64)
	valid := desktopAuthorityInput(plan, runtimeinstall.PlatformDarwin)
	tests := []struct {
		name   string
		mutate func(*DesktopAuthorityInput)
	}{
		{name: "zero plan", mutate: func(v *DesktopAuthorityInput) { v.PlanDigest = runtimeinstall.Hash{} }},
		{name: "unsupported platform", mutate: func(v *DesktopAuthorityInput) { v.Platform = runtimeinstall.PlatformLinux }},
		{name: "root principal", mutate: func(v *DesktopAuthorityInput) { v.PrincipalID = "uid:0" }},
		{name: "unsafe user", mutate: func(v *DesktopAuthorityInput) { v.UserName = "user;id" }},
		{name: "temporary home", mutate: func(v *DesktopAuthorityInput) { v.HomeDirectory = "/tmp/user" }},
		{name: "remote endpoint", mutate: func(v *DesktopAuthorityInput) { v.Endpoint = "tcp://127.0.0.1:2375" }},
		{name: "latest version", mutate: func(v *DesktopAuthorityInput) { v.RuntimeVersion = "latest" }},
		{name: "arbitrary artifact", mutate: func(v *DesktopAuthorityInput) { v.ArtifactPath = "/tmp/Docker.dmg" }},
		{name: "arbitrary source", mutate: func(v *DesktopAuthorityInput) { v.ArtifactSourceURL = "https://mirror.invalid/Docker.dmg" }},
		{name: "source query", mutate: func(v *DesktopAuthorityInput) { v.ArtifactSourceURL += "?token=secret" }},
		{name: "source user info", mutate: func(v *DesktopAuthorityInput) {
			v.ArtifactSourceURL = "https://desktop.docker.com@mirror.invalid/mac/main/arm64/Docker.dmg"
		}},
		{name: "source port", mutate: func(v *DesktopAuthorityInput) {
			v.ArtifactSourceURL = "https://desktop.docker.com:443/mac/main/arm64/Docker.dmg"
		}},
		{name: "source encoded traversal", mutate: func(v *DesktopAuthorityInput) {
			v.ArtifactSourceURL = "https://desktop.docker.com/mac/main/arm64/%2e%2e%2fDocker.dmg"
		}},
		{name: "wrong publisher", mutate: func(v *DesktopAuthorityInput) { v.Publisher.Identity = "attacker" }},
		{name: "missing certificate", mutate: func(v *DesktopAuthorityInput) { v.Publisher.CertificateSHA256 = runtimeinstall.Hash{} }},
		{name: "untrusted terms URL", mutate: func(v *DesktopAuthorityInput) { v.Terms.URL = "https://example.invalid/legal" }},
		{name: "different terms", mutate: func(v *DesktopAuthorityInput) { v.Terms.URL = "https://www.docker.com/legal/privacy/" }},
		{name: "missing accept license", mutate: func(v *DesktopAuthorityInput) { v.InstallerArguments = v.InstallerArguments[1:] }},
		{name: "extra installer switch", mutate: func(v *DesktopAuthorityInput) { v.InstallerArguments = append(v.InstallerArguments, "--allowed-org=x") }},
		{name: "wrong destination", mutate: func(v *DesktopAuthorityInput) { v.ApplicationPath = "/Users/user/Docker.app" }},
		{name: "ambient Docker CLI", mutate: func(v *DesktopAuthorityInput) { v.DockerCLIPath = "docker" }},
		{name: "missing Docker CLI digest", mutate: func(v *DesktopAuthorityInput) { v.DockerCLISHA256 = runtimeinstall.Hash{} }},
		{name: "missing Compose digest", mutate: func(v *DesktopAuthorityInput) { v.ComposePluginSHA256 = runtimeinstall.Hash{} }},
		{name: "aliased executable digests", mutate: func(v *DesktopAuthorityInput) { v.ComposePluginSHA256 = v.DockerCLISHA256 }},
		{name: "mutable probe tag", mutate: func(v *DesktopAuthorityInput) { v.ProbeImage = "docker.io/rickyseezy/agentmemory-runtime-probe:latest" }},
		{name: "wrong probe digest", mutate: func(v *DesktopAuthorityInput) { v.ProbeImageDigest = runtimeinstall.Sum([]byte("other")) }},
		{name: "unknown probe contract", mutate: func(v *DesktopAuthorityInput) { v.ProbeContractVersion = "2" }},
		{name: "Windows feature on Mac", mutate: func(v *DesktopAuthorityInput) { v.WindowsFeatures = []string{"VirtualMachinePlatform"} }},
		{name: "Windows reboot on Mac", mutate: func(v *DesktopAuthorityInput) { v.RebootExitCodes = []uint32{3010} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := cloneDesktopInput(valid)
			test.mutate(&candidate)
			if authority, err := NewDesktopAuthority(candidate); err == nil || authority.Valid() {
				t.Fatalf("broadened authority %q was accepted", test.name)
			}
		})
	}
}

func TestWindowsDesktopAuthorityRejectsMissingPerUserARMAndDockerUsersPolicies(t *testing.T) {
	t.Parallel()
	plan := desktopTestPlan(t, runtimeinstall.PlatformWindows, runtimeinstall.ArchitectureAMD64)
	valid := desktopAuthorityInput(plan, runtimeinstall.PlatformWindows)
	for _, test := range []struct {
		name   string
		mutate func(*DesktopAuthorityInput)
	}{
		{name: "ARM preview", mutate: func(v *DesktopAuthorityInput) { v.Architecture = runtimeinstall.ArchitectureARM64 }},
		{name: "missing per-user mode", mutate: func(v *DesktopAuthorityInput) {
			v.InstallerArguments = append(v.InstallerArguments[:1], v.InstallerArguments[2:]...)
		}},
		{name: "always-run service", mutate: func(v *DesktopAuthorityInput) {
			v.InstallerArguments = append(v.InstallerArguments, "--always-run-service")
		}},
		{name: "Windows containers", mutate: func(v *DesktopAuthorityInput) { v.InstallerArguments = v.InstallerArguments[:4] }},
		{name: "docker-users", mutate: func(v *DesktopAuthorityInput) { v.WindowsFeatures = append(v.WindowsFeatures, "docker-users") }},
		{name: "wrong WSL floor", mutate: func(v *DesktopAuthorityInput) { v.MinimumWSLVersion = "2.0.0" }},
		{name: "feature order", mutate: func(v *DesktopAuthorityInput) {
			v.WindowsFeatures[0], v.WindowsFeatures[1] = v.WindowsFeatures[1], v.WindowsFeatures[0]
		}},
		{name: "wrong reboot codes", mutate: func(v *DesktopAuthorityInput) { v.RebootExitCodes = []uint32{3010, 1641} }},
		{name: "alternate install root", mutate: func(v *DesktopAuthorityInput) { v.ApplicationPath = `D:\Docker` }},
		{name: "ADS artifact", mutate: func(v *DesktopAuthorityInput) { v.ArtifactPath += ":evil" }},
	} {
		candidate := cloneDesktopInput(valid)
		test.mutate(&candidate)
		if authority, err := NewDesktopAuthority(candidate); err == nil || authority.Valid() {
			t.Fatalf("Windows policy %q was accepted", test.name)
		}
	}
}

func desktopTestPlan(
	t testing.TB,
	platform runtimeinstall.Platform,
	architecture runtimeinstall.Architecture,
) runtimeinstall.Plan {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		platform, architecture, "26.0", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		platform, architecture, "docker_desktop", "4.70.0", "stable", 7,
		runtimeinstall.Sum([]byte("desktop-catalog-"+platform.String())),
		runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerDesktopTermsID, Version: "2025.07.02",
			URL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
			Digest: runtimeinstall.Sum([]byte("docker-terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 500<<20, 2<<30,
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

func desktopAuthorityInput(plan runtimeinstall.Plan, platform runtimeinstall.Platform) DesktopAuthorityInput {
	input := DesktopAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), Platform: platform,
		Architecture: runtimeinstall.ArchitectureARM64, PrincipalID: "uid:501", UserName: "agentmemory",
		MachineDigest: runtimeinstall.Sum([]byte("desktop-machine")), HomeDirectory: "/Users/agentmemory",
		OSProduct: "macos", MinimumOSVersion: "26.0", MaximumOSVersion: "26.9.9",
		MinimumBuild: 25_000, MaximumBuild: 25_999, MinimumCPUs: 4,
		MinimumTotalMemory: 16 << 30, MinimumAvailableMemory: 12 << 30, MinimumFreeDisk: 30 << 30,
		RuntimeVersion: "4.70.0", EngineVersion: "29.6.1", ComposeVersion: "5.1.4",
		Endpoint:       "unix:///Users/agentmemory/.docker/run/docker.sock",
		ArtifactPath:   "/Users/agentmemory/Library/Caches/AgentMemory/runtime/Docker.dmg",
		ArtifactSHA256: runtimeinstall.Sum([]byte("docker-desktop-artifact")), ArtifactBytes: 500 << 20,
		ArtifactSourceURL: "https://desktop.docker.com/mac/main/arm64/Docker.dmg",
		Publisher: DesktopPublisherInput{
			Kind: DesktopPublisherAppleNotarized, Identity: "developer-id-application-docker-inc-9bnsxjn65r",
			SigningKeyIdentity: "apple-developer-id-9bnsxjn65r", PackageIdentity: "com.docker.docker",
			CertificateSHA256: runtimeinstall.Sum([]byte("docker-apple-certificate")),
		},
		Terms: DesktopTermsInput{
			ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
			Digest: runtimeinstall.Sum([]byte("docker-terms")),
		},
		InstallerArguments:     []string{"--accept-license", "--user=agentmemory"},
		ApplicationPath:        "/Applications/Docker.app",
		ApplicationExecutable:  "/Applications/Docker.app/Contents/MacOS/Docker Desktop",
		DockerCLIPath:          "/Applications/Docker.app/Contents/Resources/bin/docker",
		ComposePluginPath:      "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
		DockerCLISHA256:        runtimeinstall.Sum([]byte("desktop docker cli")),
		ComposePluginSHA256:    runtimeinstall.Sum([]byte("desktop compose plugin")),
		ProbeImage:             "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + runtimeinstall.Sum([]byte("desktop-probe-image")).String(),
		ProbeImageDigest:       runtimeinstall.Sum([]byte("desktop-probe-image")),
		ProbeContractVersion:   "1",
		CapabilityPolicyDigest: runtimeinstall.Sum([]byte("desktop-capability-policy")), VendorUIMandatory: false,
	}
	if platform == runtimeinstall.PlatformWindows {
		input.Architecture = runtimeinstall.ArchitectureAMD64
		input.PrincipalID = "sid:S-1-5-21-1000-1001-1002-1003"
		input.UserName = "Agent User"
		input.HomeDirectory = `C:\Users\Agent User`
		input.OSProduct = "windows-11"
		input.MinimumOSVersion = "10.0.0"
		input.MaximumOSVersion = "10.0.0"
		input.MinimumBuild = 22_631
		input.MaximumBuild = 26_199
		input.Endpoint = "npipe:////./pipe/docker_engine"
		input.ArtifactPath = `C:\Users\Agent User\AppData\Local\AgentMemory\runtime\Docker Desktop Installer.exe`
		input.ArtifactSourceURL = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
		input.Publisher = DesktopPublisherInput{
			Kind: DesktopPublisherAuthenticode, Identity: "microsoft-authenticode-docker-inc",
			SigningKeyIdentity: "docker-authenticode-2026", PackageIdentity: "com.docker.docker",
			CertificateSHA256: runtimeinstall.Sum([]byte("docker-windows-certificate")),
		}
		input.InstallerArguments = []string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"}
		input.ApplicationPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop`
		input.ApplicationExecutable = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe`
		input.DockerCLIPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe`
		input.ComposePluginPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\cli-plugins\docker-compose.exe`
		input.RebootExitCodes = []uint32{1641, 3010}
		input.WindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}
		input.MinimumWSLVersion = "2.1.5"
	}
	return input
}

func cloneDesktopInput(input DesktopAuthorityInput) DesktopAuthorityInput {
	clone := input
	clone.InstallerArguments = slices.Clone(input.InstallerArguments)
	clone.RebootExitCodes = slices.Clone(input.RebootExitCodes)
	clone.WindowsFeatures = slices.Clone(input.WindowsFeatures)
	return clone
}
