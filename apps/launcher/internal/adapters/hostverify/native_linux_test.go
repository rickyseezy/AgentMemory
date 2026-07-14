//go:build linux

package hostverify

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

func TestPF001LinuxNativePlatformAndResourceEvidence(t *testing.T) {
	platform, ok := linuxPlatform()
	if !ok || platform.OperatingSystem != hostverification.OperatingSystemLinux || platform.Product == "" || platform.Build == "" {
		t.Fatalf("Linux platform evidence = %+v/%t", platform, ok)
	}
	product, version, ok := readOSRelease()
	if !ok || !safeProduct(product) || !safeVersion(version) {
		t.Fatalf("Linux os-release evidence = %q/%q/%t", product, version, ok)
	}
	for _, test := range []struct {
		value string
		want  string
		ok    bool
	}{
		{value: `"24.04"`, want: "24.04", ok: true},
		{value: "'bookworm'", want: "bookworm", ok: true},
		{value: "unsafe value"},
		{value: `bad\value`},
	} {
		got, valid := strictOSReleaseValue(test.value)
		if got != test.want || valid != test.ok {
			t.Fatalf("strictOSReleaseValue(%q) = %q/%t", test.value, got, valid)
		}
	}
	if linuxUnameString([]byte{'6', '.', '1', 0, 'x'}) != "6.1" || linuxUnameString([]byte("latest")) != "" {
		t.Fatal("Linux uname normalization drifted")
	}
	cpus, memory, ok := linuxResources()
	if !ok || cpus == 0 || memory == 0 {
		t.Fatalf("Linux resources = %d/%d/%t", cpus, memory, ok)
	}
	if linuxVirtualization(cancelledContext()) {
		t.Fatal("cancelled KVM proof succeeded")
	}
	if encryption, valid := linuxEncryption(nil); valid || encryption != "" {
		t.Fatalf("nil Linux encryption evidence = %q/%t", encryption, valid)
	}
	if formatDevice(259, 17) != "259:17" || uint32Decimal(0) != "0" || uint32Decimal(4_294_967_295) != "4294967295" {
		t.Fatal("Linux device formatter drifted")
	}
	if architecture, valid := nativeArchitecture(runtime.GOARCH); !valid || architecture == "" {
		t.Fatalf("native architecture = %q/%t", architecture, valid)
	}
	if _, valid := nativeArchitecture("mips"); valid || safeProduct("Ubuntu") || safeProduct("-linux") ||
		safeVersion("latest") || safeVersion("unsafe value") {
		t.Fatal("native Linux token policy accepted an unsafe value")
	}
}

func TestPF001LinuxControlledTargetAndEncryptedLeafProofs(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		t.Fatalf("owner home unavailable: %v", err)
	}
	target, err := os.MkdirTemp(home, ".agentmemory-hostverify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(target) })
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: owner-only storage target fixture.
		t.Fatal(err)
	}
	evidence, ok := openControlledTarget(context.Background(), target)
	if !ok || evidence.file == nil || evidence.freeBytes == 0 || evidence.identity == "" {
		t.Fatalf("controlled target = %+v/%t", evidence, ok)
	}
	if !targetIdentityUnchanged(context.Background(), target, evidence) {
		t.Fatal("stable controlled target changed identity")
	}
	_ = evidence.file.Close()
	if _, ok := openControlledTarget(cancelledContext(), target); ok {
		t.Fatal("cancelled target proof succeeded")
	}
	if _, ok := openControlledTarget(context.Background(), "relative"); ok {
		t.Fatal("relative target proof succeeded")
	}
	if err := os.Chmod(target, 0o722); err != nil { //nolint:gosec // G302: deliberate unsafe target fixture.
		t.Fatal(err)
	}
	if _, ok := openControlledTarget(context.Background(), target); ok {
		t.Fatal("group-writable target proof succeeded")
	}

	leaf := t.TempDir()
	ok, leaves := encryptedDeviceLeaves(leaf, false, 0, make(map[string]bool))
	if ok || leaves != 1 {
		t.Fatalf("plain device leaf = %t/%d", ok, leaves)
	}
	if err := os.Mkdir(filepath.Join(leaf, "dm"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "dm", "uuid"), []byte("CRYPT-agentmemory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, leaves = encryptedDeviceLeaves(leaf, false, 0, make(map[string]bool))
	if !ok || leaves != 1 {
		t.Fatalf("encrypted device leaf = %t/%d", ok, leaves)
	}
	if ok, _ := encryptedDeviceLeaves(leaf, false, 17, make(map[string]bool)); ok {
		t.Fatal("over-deep device graph was accepted")
	}
	if ok, _ := encryptedDeviceLeaves(leaf, false, 0, map[string]bool{leaf: true}); ok {
		t.Fatal("cyclic device graph was accepted")
	}
}

func TestPF001LinuxCollectorRejectsCrossPlatformPlanBeforeHostMutation(t *testing.T) {
	plan, _ := adapterFixture(t)
	_, reason := (nativeCollector{}).collect(context.Background(), plan, plan.StorageTarget())
	if reason != hostverification.FailureUnsupportedPlatform {
		t.Fatalf("cross-platform Linux collection reason = %s", reason)
	}
	if !strings.Contains(plan.StorageTarget(), "AgentMemory") {
		t.Fatal("fixture storage binding drifted")
	}
	platform, ok := linuxPlatform()
	if !ok {
		t.Fatal("Linux platform unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.MkdirTemp(home, ".agentmemory-collector-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(target) })
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: owner-only collector fixture.
		t.Fatal(err)
	}
	linuxPlan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "linux-policy", SigningKeyID: "linux-root", Platform: platform,
		MinimumCPUCores: 1, MinimumMemoryBytes: 1, MinimumFreeDiskBytes: 1,
		StorageTarget: target,
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, reason = (nativeCollector{}).collect(context.Background(), linuxPlan, target)
	if reason == hostverification.FailureUnsupportedPlatform || reason == hostverification.FailurePlatformProofUnavailable ||
		reason == hostverification.FailureTargetNotOwnerControlled ||
		reason == hostverification.FailureResourceProofUnavailable {
		t.Fatalf("Linux collector did not advance through native host proofs: %s", reason)
	}
}
