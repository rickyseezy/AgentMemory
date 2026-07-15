package launcher

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/agentconfigapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001NativeAgentConfigurationBindsExactPlanTarget(t *testing.T) {
	t.Parallel()
	configurationPath := "/tmp/agentmemory/config.json"
	if runtime.GOOS == "windows" {
		configurationPath = `C:\Users\Agent User\AppData\Roaming\AgentMemory\config.json`
	}
	location, err := agentconfigport.NewConfigLocation(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	target := nativeAgentTarget(t, agentconfigdomain.AgentHostClaude)
	plan, err := install.BindPlan([]byte("canonical agent plan"))
	if err != nil {
		t.Fatal(err)
	}
	release := &nativeReleaseAuthority{stack: nativeReleaseStack{application: &appreleaseverify.Application{}}}
	merger, err := newNativeAgentConfigurationMergerFromAuthority(
		release,
		releaseinventory.SignedManifest{},
		plan,
		location,
		target,
		t.TempDir(),
	)
	if err != nil || merger == nil {
		t.Fatalf("merger=%T error=%v", merger, err)
	}
	request := agentconfigapp.MergeRequest{Location: location, Target: target}
	if _, err := merger.Merge(t.Context(), request); err == nil {
		t.Fatal("unverified release reached host mutation")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := merger.Merge(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled merge error=%v", err)
	}
	foreign := request
	foreign.Target = nativeAgentTarget(t, agentconfigdomain.AgentHostGemini)
	if _, err := merger.Merge(t.Context(), foreign); !errors.Is(err, agentconfigport.ErrIntegrity) {
		t.Fatalf("foreign target error=%v", err)
	}
	if !sameNativeAgentTarget(target, target) || sameNativeAgentTarget(target, foreign.Target) {
		t.Fatal("target equality accepted substitution")
	}
	if candidate, buildError := newNativeAgentConfigurationMergerFromAuthority(
		nil,
		releaseinventory.SignedManifest{},
		install.PlanDigest{},
		agentconfigport.ConfigLocation{},
		agentconfigdomain.Target{},
		"",
	); candidate != nil || buildError == nil {
		t.Fatalf("incomplete merger=%T error=%v", candidate, buildError)
	}
	if candidate, buildError := newNativeAgentConfigurationMerger(release, []byte("invalid"), t.TempDir()); candidate != nil || buildError == nil {
		t.Fatalf("invalid canonical merger=%T error=%v", candidate, buildError)
	}
	if (nativeVerifiedLauncherInventory{}).Authorizes(nativeAgentLauncherResource(t, target)) {
		t.Fatal("empty verified inventory authorized a launcher")
	}
}

func TestPF001NativeLauncherResourceAndRunnerRequireExactVerifiedDescriptor(t *testing.T) {
	t.Parallel()
	target := nativeAgentTarget(t, agentconfigdomain.AgentHostCodex)
	resource := nativeAgentLauncherResource(t, target)
	inventory := nativeLauncherInventoryStub{authorizedID: resource.ID()}
	selected, err := nativeLauncherResource(inventory, []releaseinventory.Resource{resource}, target)
	if err != nil || selected.ID() != resource.ID() {
		t.Fatalf("selected=%q error=%v", selected.ID(), err)
	}
	if _, err := nativeLauncherResource(nativeLauncherInventoryStub{}, []releaseinventory.Resource{resource}, target); err == nil {
		t.Fatal("unauthorized launcher descriptor accepted")
	}
	foreign := nativeAgentTarget(t, agentconfigdomain.AgentHostGemini)
	if _, err := nativeLauncherResource(inventory, []releaseinventory.Resource{resource}, foreign); err == nil {
		t.Fatal("foreign launcher digest accepted")
	}
	manifestDigest := releaseinventory.DigestBytes([]byte("release manifest"))
	planDigest, err := install.BindPlan([]byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	release := &nativeReleaseAuthority{
		runtimeHelperPublisherCertificates: map[string]releaseinventory.Digest{
			resource.ID(): releaseinventory.DigestBytes([]byte("windows signer certificate")),
		},
	}
	runner, err := newNativeLauncherRunner(release, resource, manifestDigest, planDigest, target)
	if err != nil || runner == nil || runner.ExecutableAuthority().CanonicalPath() != target.Command() ||
		runner.ExecutableAuthority().Role() == "" {
		t.Fatalf("runner=%T error=%v", runner, err)
	}
	if store, err := newNativeAgentConfigurationStore(t.TempDir()); err != nil || store == nil {
		t.Fatalf("store=%T error=%v", store, err)
	}
	owner, policy, trust, err := nativeLauncherExecutionPolicy(release, resource.ID(), manifestDigest)
	if err != nil || owner == "" || policy == "" || trust == [32]byte{} {
		t.Fatalf("policy=%q/%q/%x error=%v", owner, policy, trust, err)
	}
	if runner, err := newNativeLauncherRunner(
		release, releaseinventory.Resource{}, manifestDigest, planDigest, target,
	); runner != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("zero resource runner=%T error=%v", runner, err)
	}
	if runner, err := newNativeLauncherRunner(
		release, resource, manifestDigest, install.PlanDigest{}, target,
	); runner != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("zero plan runner=%T error=%v", runner, err)
	}
}

func nativeAgentTarget(t testing.TB, host agentconfigdomain.AgentHost) agentconfigdomain.Target {
	t.Helper()
	digest := agentconfigdomain.DigestBytes([]byte("signed launcher " + string(host)))
	command := "/opt/agentmemory/bin/agentmemory"
	if runtime.GOOS == "windows" {
		command = `C:\Program Files\AgentMemory\bin\agentmemory.exe`
	}
	target, err := agentconfigdomain.NewTargetForAgent(
		host,
		"019f5f20-1234-7abc-8123-0123456789ab",
		"019f5f22-5678-7def-9123-abcdef012346",
		command,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func nativeAgentLauncherResource(t testing.TB, target agentconfigdomain.Target) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	publisher := "agentmemory.publisher"
	if runtime.GOOS == "darwin" {
		publisher = "teamid:AB12CD34EF"
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID:   "launcher-" + runtime.GOOS + "-" + runtime.GOARCH,
		Kind: releaseinventory.ResourceKindLauncher, Purpose: releaseinventory.ResourcePurposeNativeLauncher,
		MediaType: releaseinventory.MediaTypeNativeExecutable, Platform: platform,
		Digest: releaseinventory.Digest(target.LauncherDigest()), Size: 1024,
		SourceRef: "bundle://launcher", SourceAllowlist: []string{"bundle://launcher"},
		CycloneDXSBOMResourceID: "launcher-cyclonedx", SPDXSBOMResourceID: "launcher-spdx",
		ProvenanceResourceID: "launcher-provenance", LicenseResourceID: "launcher-license",
		VulnerabilityResourceID: "launcher-vulnerability",
		NativePublisherIdentity: publisher, NativePublisherPolicyID: "agentmemory-native-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

type nativeLauncherInventoryStub struct{ authorizedID string }

func (s nativeLauncherInventoryStub) Authorizes(resource releaseinventory.Resource) bool {
	return s.authorizedID != "" && resource.ID() == s.authorizedID
}
