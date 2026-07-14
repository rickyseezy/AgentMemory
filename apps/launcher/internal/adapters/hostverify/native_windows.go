//go:build windows

package hostverify

import (
	"context"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/windows"
)

const allProcessorGroups = uint16(0xffff)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	getProductInfo           = kernel32.NewProc("GetProductInfo")
	globalMemoryStatusExProc = kernel32.NewProc("GlobalMemoryStatusEx")
)

type windowsMemoryStatus struct {
	Length            uint32
	MemoryLoad        uint32
	TotalPhysical     uint64
	AvailablePhysical uint64
	TotalPageFile     uint64
	AvailablePageFile uint64
	TotalVirtual      uint64
	AvailableVirtual  uint64
	AvailableExtended uint64
}

type nativeCollector struct{ bitLocker *bitLockerWorker }

func (c *nativeCollector) collect(
	ctx context.Context,
	plan hostverification.Plan,
) (hostverification.ObservationInput, hostverification.FailureReason) {
	if plan.Platform().OperatingSystem != hostverification.OperatingSystemWindows {
		return hostverification.ObservationInput{}, hostverification.FailureUnsupportedPlatform
	}
	platform, ok := windowsPlatform()
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailurePlatformProofUnavailable
	}
	target, _, err := windowssecurity.OpenVerified(ctx, plan.StorageTarget(), true, false, true)
	if err != nil {
		return hostverification.ObservationInput{}, hostverification.FailureTargetNotOwnerControlled
	}
	defer func() { _ = target.Close() }()
	memory, ok := windowsPhysicalMemory()
	cpu := windows.GetActiveProcessorCount(allProcessorGroups)
	if !ok || cpu == 0 {
		return hostverification.ObservationInput{}, hostverification.FailureResourceProofUnavailable
	}
	path, err := windows.UTF16PtrFromString(plan.StorageTarget())
	if err != nil {
		return hostverification.ObservationInput{}, hostverification.FailureResourceProofUnavailable
	}
	var availableToCaller, total, totalFree uint64
	if windows.GetDiskFreeSpaceEx(path, &availableToCaller, &total, &totalFree) != nil || availableToCaller == 0 {
		return hostverification.ObservationInput{}, hostverification.FailureResourceProofUnavailable
	}
	if !windows.IsProcessorFeaturePresent(windows.PF_VIRT_FIRMWARE_ENABLED) {
		return hostverification.ObservationInput{}, hostverification.FailureVirtualizationUnavailable
	}
	if c == nil || c.bitLocker == nil || !c.bitLocker.attest(ctx, plan.StorageTarget()) {
		return hostverification.ObservationInput{}, hostverification.FailureEncryptionUnavailable
	}
	if !attestLoopback(ctx, plan.RequiredPorts()) {
		return hostverification.ObservationInput{}, hostverification.FailureLoopbackPortUnavailable
	}
	return hostverification.ObservationInput{
		Platform: platform, CPUCores: cpu, MemoryBytes: memory, FreeDiskBytes: availableToCaller,
		StorageTarget: plan.StorageTarget(), Virtualization: hostverification.VirtualizationWindowsFirmware,
		Encryption: hostverification.EncryptionBitLocker, AvailablePorts: plan.RequiredPorts(),
	}, hostverification.FailureNone
}

func newNativeCollector() collector {
	return &nativeCollector{bitLocker: newBitLockerWorker(newWindowsBitLockerBackend())}
}

func (c *nativeCollector) close(ctx context.Context) error {
	if c == nil || c.bitLocker == nil {
		return errBitLockerEvidence
	}
	return c.bitLocker.close(ctx)
}

func windowsPlatform() (hostverification.PlatformTuple, bool) {
	version := windows.RtlGetVersion()
	if version == nil || version.MajorVersion == 0 || version.BuildNumber == 0 {
		return hostverification.PlatformTuple{}, false
	}
	var product uint32
	result, _, _ := getProductInfo.Call(
		uintptr(version.MajorVersion), uintptr(version.MinorVersion),
		uintptr(version.ServicePackMajor), uintptr(version.ServicePackMinor),
		uintptr(unsafe.Pointer(&product)), // #nosec G103 -- exact GetProductInfo output pointer.
	)
	architecture, ok := nativeArchitecture(runtime.GOARCH)
	if result == 0 || product == 0 || !ok {
		return hostverification.PlatformTuple{}, false
	}
	return hostverification.PlatformTuple{
		OperatingSystem: hostverification.OperatingSystemWindows,
		Product:         "product_" + strconv.FormatUint(uint64(product), 10), Architecture: architecture,
		Version: strconv.FormatUint(uint64(version.MajorVersion), 10) + "." +
			strconv.FormatUint(uint64(version.MinorVersion), 10) + ".0",
		Build: strconv.FormatUint(uint64(version.BuildNumber), 10),
	}, true
}

func windowsPhysicalMemory() (uint64, bool) {
	status := windowsMemoryStatus{Length: uint32(unsafe.Sizeof(windowsMemoryStatus{}))}
	result, _, _ := globalMemoryStatusExProc.Call(uintptr(unsafe.Pointer(&status))) // #nosec G103 -- exact GlobalMemoryStatusEx ABI structure.
	return status.TotalPhysical, result != 0 && status.TotalPhysical != 0
}
