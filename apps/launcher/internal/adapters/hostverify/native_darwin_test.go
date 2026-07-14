//go:build darwin

package hostverify

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/unix"
)

func TestPF001DarwinPlatformUsesExactNativeTuple(t *testing.T) {
	t.Parallel()
	platform, ok := darwinPlatform()
	architecture, architectureOK := nativeArchitecture(runtime.GOARCH)
	if !ok || !architectureOK || platform.OperatingSystem != hostverification.OperatingSystemMacOS ||
		platform.Product != "macos" || platform.Architecture != architecture ||
		!safeVersion(platform.Version) || !safeVersion(platform.Build) {
		t.Fatalf("darwinPlatform() = %+v, %v", platform, ok)
	}
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"15.5", true}, {"24F74", true}, {"latest", false}, {"15.*", false}, {"", false},
	} {
		if got := safeVersion(test.value); got != test.want {
			t.Errorf("safeVersion(%q) = %v", test.value, got)
		}
	}
	if _, ok := nativeArchitecture("386"); ok {
		t.Fatal("unsupported architecture was accepted")
	}
	if amd64, ok := nativeArchitecture("amd64"); !ok || amd64 != hostverification.ArchitectureAMD64 {
		t.Fatal("amd64 was not mapped")
	}
	if arm64, ok := nativeArchitecture("arm64"); !ok || arm64 != hostverification.ArchitectureARM64 {
		t.Fatal("arm64 was not mapped")
	}
	for _, test := range []struct {
		value string
		want  bool
	}{{"macos", true}, {"mac_os", true}, {"MacOS", false}, {"-macos", false}, {"", false}} {
		if got := safeProduct(test.value); got != test.want {
			t.Errorf("safeProduct(%q) = %v", test.value, got)
		}
	}
}

func TestPF001DarwinControlledTargetUsesDescriptorIdentityAndFreeSpace(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.MkdirTemp(home, ".agentmemory-host-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(target) }()
	evidence, ok := openControlledTarget(context.Background(), target)
	if !ok || evidence.file == nil || evidence.freeBytes == 0 || evidence.identity == "" {
		t.Fatalf("openControlledTarget() = %+v, %v", evidence, ok)
	}
	if !targetIdentityUnchanged(context.Background(), target, evidence) {
		t.Fatal("unchanged target identity was rejected")
	}
	if err := evidence.file.Close(); err != nil {
		t.Fatal(err)
	}
	replaced := target + ".old"
	if err := os.Rename(target, replaced); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(replaced) }()
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if targetIdentityUnchanged(context.Background(), target, evidence) {
		t.Fatal("substituted target identity was accepted")
	}
	if err := unix.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, ok := openControlledTarget(context.Background(), target); ok {
		t.Fatal("group/world-writable target was accepted")
	}
	if _, ok := openControlledTarget(cancelledContext(), target); ok {
		t.Fatal("cancelled target proof succeeded")
	}
	if _, ok := openControlledTarget(context.Background(), "relative"); ok {
		t.Fatal("relative target was accepted")
	}
	symlink := filepath.Join(home, ".agentmemory-host-proof-link")
	_ = os.Remove(symlink)
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(symlink) }()
	if _, ok := openControlledTarget(context.Background(), symlink); ok {
		t.Fatal("symlink target was accepted")
	}
}

func TestPF001DarwinNativeCollectorFailsClosedAtEveryObservableBoundary(t *testing.T) {
	platform, ok := darwinPlatform()
	if !ok {
		t.Fatal("current Darwin platform could not be observed")
	}
	linuxPlan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy", SigningKeyID: "host-root",
		Platform:        hostverification.PlatformTuple{OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu", Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0"},
		MinimumCPUCores: 1, MinimumMemoryBytes: 1, MinimumFreeDiskBytes: 1,
		StorageTarget: "/home/user", RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := (nativeCollector{}).collect(context.Background(), linuxPlan); reason != hostverification.FailureUnsupportedPlatform {
		t.Fatalf("cross-platform reason = %q", reason)
	}

	missingPlan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy", SigningKeyID: "host-root",
		Platform: platform, MinimumCPUCores: 1, MinimumMemoryBytes: 1, MinimumFreeDiskBytes: 1,
		StorageTarget: filepath.Join(os.TempDir(), "agentmemory-host-target-does-not-exist"),
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := (nativeCollector{}).collect(context.Background(), missingPlan); reason != hostverification.FailureTargetNotOwnerControlled {
		t.Fatalf("missing target reason = %q", reason)
	}
	if darwinEncryptionAttested("") {
		t.Fatal("empty encryption target was attested")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the native Disk Arbitration proof regardless of whether this
	// particular development host is policy-compliant.
	_ = darwinEncryptionAttested(home)
	target, err := os.MkdirTemp(home, ".agentmemory-host-collector-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(target) }()
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := checkedTestPort(t, listener)
	_ = listener.Close()
	localPlan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy", SigningKeyID: "host-root",
		Platform: platform, MinimumCPUCores: 1, MinimumMemoryBytes: 1, MinimumFreeDiskBytes: 1,
		StorageTarget: target,
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: port}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, reason := (nativeCollector{}).collect(context.Background(), localPlan)
	switch reason {
	case hostverification.FailureNone, hostverification.FailureResourceProofUnavailable,
		hostverification.FailureVirtualizationUnavailable, hostverification.FailureEncryptionUnavailable,
		hostverification.FailureLoopbackPortUnavailable:
	case hostverification.FailureUnsupportedPlatform, hostverification.FailureInsufficientCPU,
		hostverification.FailureInsufficientMemory, hostverification.FailureInsufficientDisk,
		hostverification.FailureTargetNotOwnerControlled, hostverification.FailurePlatformProofUnavailable:
		t.Fatalf("native collector returned non-closed reason %q", reason)
	}
}
