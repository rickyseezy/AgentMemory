package launcher

import (
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006DesktopExecutableAuthoritiesBindExactSignedPlanAndPublisherTrust(t *testing.T) {
	t.Parallel()
	desktop := launcherDesktopAuthority(t, runtimeinstall.PlatformDarwin)
	request, _, _ := nativeRuntimeExecutionFixture(t)
	release := request.SignedRelease.Manifest().Digest()
	docker, err := newNativeDesktopExecutableAuthority(
		desktop, release, "docker-desktop-cli", desktop.DockerCLIPath(), desktop.DockerCLISHA256(),
		argvprocess.ExecutableRoleDockerCLI,
	)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := newNativeDesktopExecutableAuthority(
		desktop, release, "docker-desktop-compose", desktop.ComposePluginPath(), desktop.ComposePluginSHA256(),
		argvprocess.ExecutableRoleComposePlugin,
	)
	if err != nil || !docker.Valid() || !compose.Valid() || !docker.SameSignedPlan(compose) ||
		docker.PublisherTrustDigest() != desktop.Publisher().CertificateSHA256() ||
		compose.PublisherTrustDigest() != desktop.Publisher().CertificateSHA256() ||
		docker.ReleaseManifestDigest() != release || docker.RuntimePlanDigest() != desktop.PlanDigest() {
		t.Fatalf("docker=%+v compose=%+v error=%v", docker, compose, err)
	}
}

func TestPF006NativeDesktopRunnerPairRejectsIncompleteAuthority(t *testing.T) {
	t.Parallel()
	request, _, _ := nativeRuntimeExecutionFixture(t)
	release := request.SignedRelease.Manifest().Digest()
	if pair, err := newNativeDesktopRunnerPair(runtimeport.DesktopAuthority{}, release); err == nil || pair.docker != nil || pair.compose != nil {
		t.Fatalf("incomplete runner pair=%+v error=%v", pair, err)
	}
	if authority, err := newNativeDesktopExecutableAuthority(
		runtimeport.DesktopAuthority{}, release, "docker-desktop-cli", "/invalid",
		[32]byte{}, argvprocess.ExecutableRoleDockerCLI,
	); err == nil || authority.Valid() {
		t.Fatalf("incomplete executable authority=%+v error=%v", authority, err)
	}
	platform := runtimeinstall.PlatformDarwin
	if runtime.GOOS == "windows" {
		platform = runtimeinstall.PlatformWindows
	}
	pair, err := newNativeDesktopRunnerPair(launcherDesktopAuthority(t, platform), release)
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if err == nil || pair.docker != nil || pair.compose != nil {
			t.Fatalf("foreign desktop runner pair=%+v error=%v", pair, err)
		}
		return
	}
	if err != nil || pair.docker == nil || pair.compose == nil ||
		!pair.docker.ExecutableAuthority().SameSignedPlan(pair.compose.ExecutableAuthority()) {
		t.Fatalf("complete runner pair=%+v error=%v", pair, err)
	}
}
