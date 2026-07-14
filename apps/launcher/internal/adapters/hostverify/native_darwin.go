//go:build darwin

package hostverify

import (
	"context"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/unix"
)

type nativeCollector struct{}

func (nativeCollector) collect(
	ctx context.Context,
	plan hostverification.Plan,
	storageTarget string,
) (hostverification.ObservationInput, hostverification.FailureReason) {
	if plan.Platform().OperatingSystem != hostverification.OperatingSystemMacOS {
		return hostverification.ObservationInput{}, hostverification.FailureUnsupportedPlatform
	}
	platform, ok := darwinPlatform()
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailurePlatformProofUnavailable
	}
	target, ok := openControlledTarget(ctx, storageTarget)
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailureTargetNotOwnerControlled
	}
	defer func() { _ = target.file.Close() }()
	cpu, cpuError := unix.SysctlUint32("hw.physicalcpu")
	memory, memoryError := unix.SysctlUint64("hw.memsize")
	if cpuError != nil || memoryError != nil || cpu == 0 || memory == 0 {
		return hostverification.ObservationInput{}, hostverification.FailureResourceProofUnavailable
	}
	hypervisor, hypervisorError := unix.SysctlUint32("kern.hv_support")
	if hypervisorError != nil || hypervisor != 1 {
		return hostverification.ObservationInput{}, hostverification.FailureVirtualizationUnavailable
	}
	if !darwinEncryptionAttested(storageTarget) || !targetIdentityUnchanged(ctx, storageTarget, target) {
		return hostverification.ObservationInput{}, hostverification.FailureEncryptionUnavailable
	}
	if !attestLoopback(ctx, plan.RequiredPorts()) {
		return hostverification.ObservationInput{}, hostverification.FailureLoopbackPortUnavailable
	}
	return hostverification.ObservationInput{
		Platform: platform, CPUCores: cpu, MemoryBytes: memory, FreeDiskBytes: target.freeBytes,
		StorageTarget: storageTarget, Virtualization: hostverification.VirtualizationHypervisorFramework,
		Encryption: hostverification.EncryptionFileVault, AvailablePorts: plan.RequiredPorts(),
	}, hostverification.FailureNone
}

func darwinPlatform() (hostverification.PlatformTuple, bool) {
	version, versionError := unix.Sysctl("kern.osproductversion")
	build, buildError := unix.Sysctl("kern.osversion")
	architecture, architectureOK := nativeArchitecture(runtime.GOARCH)
	if versionError != nil || buildError != nil || !architectureOK || !safeVersion(version) || !safeVersion(build) {
		return hostverification.PlatformTuple{}, false
	}
	return hostverification.PlatformTuple{
		OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos",
		Architecture: architecture, Version: version, Build: build,
	}, true
}
