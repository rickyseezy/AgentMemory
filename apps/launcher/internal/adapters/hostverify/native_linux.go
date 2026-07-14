//go:build linux

package hostverify

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/unix"
)

const (
	maximumOSReleaseBytes = 64 << 10
	kvmGetAPIVersion      = 0xAE00
	kvmAPIVersion         = 12
)

type nativeCollector struct{}

func (nativeCollector) collect(
	ctx context.Context,
	plan hostverification.Plan,
	storageTarget string,
) (hostverification.ObservationInput, hostverification.FailureReason) {
	if plan.Platform().OperatingSystem != hostverification.OperatingSystemLinux {
		return hostverification.ObservationInput{}, hostverification.FailureUnsupportedPlatform
	}
	platform, ok := linuxPlatform()
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailurePlatformProofUnavailable
	}
	target, ok := openControlledTarget(ctx, storageTarget)
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailureTargetNotOwnerControlled
	}
	defer func() { _ = target.file.Close() }()
	cpu, memory, ok := linuxResources()
	if !ok {
		return hostverification.ObservationInput{}, hostverification.FailureResourceProofUnavailable
	}
	if !linuxVirtualization(ctx) {
		return hostverification.ObservationInput{}, hostverification.FailureVirtualizationUnavailable
	}
	encryption, ok := linuxEncryption(target.file)
	if !ok || !targetIdentityUnchanged(ctx, storageTarget, target) {
		return hostverification.ObservationInput{}, hostverification.FailureEncryptionUnavailable
	}
	if !attestLoopback(ctx, plan.RequiredPorts()) {
		return hostverification.ObservationInput{}, hostverification.FailureLoopbackPortUnavailable
	}
	return hostverification.ObservationInput{
		Platform: platform, CPUCores: cpu, MemoryBytes: memory, FreeDiskBytes: target.freeBytes,
		StorageTarget: storageTarget, Virtualization: hostverification.VirtualizationKVM,
		Encryption: encryption, AvailablePorts: plan.RequiredPorts(),
	}, hostverification.FailureNone
}

func linuxPlatform() (hostverification.PlatformTuple, bool) {
	product, version, ok := readOSRelease()
	if !ok {
		return hostverification.PlatformTuple{}, false
	}
	var name unix.Utsname
	if unix.Uname(&name) != nil {
		return hostverification.PlatformTuple{}, false
	}
	build := linuxUnameString(name.Release[:])
	architecture, ok := nativeArchitecture(runtime.GOARCH)
	if !ok || build == "" {
		return hostverification.PlatformTuple{}, false
	}
	return hostverification.PlatformTuple{
		OperatingSystem: hostverification.OperatingSystemLinux, Product: product,
		Architecture: architecture, Version: version, Build: build,
	}, true
}

func readOSRelease() (string, string, bool) {
	path := "/etc/os-release"
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readError := os.Readlink(path)
		if readError != nil || target != "/usr/lib/os-release" && target != "../usr/lib/os-release" {
			return "", "", false
		}
		path = "/usr/lib/os-release"
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", "", false
	}
	file := os.NewFile(uintptr(descriptor), "linux-os-release")
	if file == nil {
		_ = unix.Close(descriptor)
		return "", "", false
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > maximumOSReleaseBytes {
		return "", "", false
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumOSReleaseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumOSReleaseBytes {
		return "", "", false
	}
	values := make(map[string]string, 2)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return "", "", false
		}
		parsed, valid := strictOSReleaseValue(value)
		if !valid {
			return "", "", false
		}
		values[key] = parsed
	}
	product, productOK := values["ID"]
	version, versionOK := values["VERSION_ID"]
	return product, version, productOK && versionOK && safeProduct(product) && safeVersion(version)
}

func strictOSReleaseValue(value string) (string, bool) {
	if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
		value = value[1 : len(value)-1]
	}
	if value == "" || strings.ContainsAny(value, "\\\"' \t\r\n") {
		return "", false
	}
	return value, true
}

func linuxUnameString(value []byte) string {
	bytes := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		bytes = append(bytes, character)
	}
	result := string(bytes)
	if !safeVersion(result) {
		return ""
	}
	return result
}

func linuxResources() (uint32, uint64, bool) {
	var affinity unix.CPUSet
	if unix.SchedGetaffinity(0, &affinity) != nil || affinity.Count() <= 0 {
		return 0, 0, false
	}
	var information unix.Sysinfo_t
	if unix.Sysinfo(&information) != nil || information.Totalram == 0 || information.Unit == 0 {
		return 0, 0, false
	}
	memory := information.Totalram
	unit := uint64(information.Unit)
	if memory > ^uint64(0)/unit {
		return 0, 0, false
	}
	count := affinity.Count()
	if count > int(^uint32(0)) {
		return 0, 0, false
	}
	return uint32(count), memory * unit, true // #nosec G115 -- count is bounded to uint32 above.
}

func linuxVirtualization(ctx context.Context) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	descriptor, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(descriptor) }()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return false
	}
	version, err := unix.IoctlGetInt(descriptor, kvmGetAPIVersion)
	return err == nil && version == kvmAPIVersion
}

func linuxEncryption(file *os.File) (hostverification.EncryptionKind, bool) {
	if file == nil {
		return "", false
	}
	var policy [64]byte
	// #nosec G103 -- FS_IOC_GET_ENCRYPTION_POLICY requires a fixed native output buffer.
	_, _, ioctlError := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(unix.FS_IOC_GET_ENCRYPTION_POLICY), uintptr(unsafe.Pointer(&policy[0])))
	if ioctlError == 0 && (policy[0] == 0 || policy[0] == 2) {
		return hostverification.EncryptionFScrypt, true
	}
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		return "", false
	}
	deviceLink := filepath.Join("/sys/dev/block", formatDevice(unix.Major(stat.Dev), unix.Minor(stat.Dev)))
	resolved, err := filepath.EvalSymlinks(deviceLink)
	if err != nil || !strings.HasPrefix(resolved, "/sys/devices/") {
		return "", false
	}
	ok, leaves := encryptedDeviceLeaves(resolved, false, 0, make(map[string]bool))
	if !ok || leaves == 0 {
		return "", false
	}
	return hostverification.EncryptionDMcrypt, true
}

func formatDevice(major, minor uint32) string {
	return strings.Join([]string{uint32Decimal(major), uint32Decimal(minor)}, ":")
}

func uint32Decimal(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buffer [10]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

func encryptedDeviceLeaves(path string, encrypted bool, depth int, visited map[string]bool) (bool, int) {
	if depth > 16 || len(visited) > 64 || visited[path] {
		return false, 0
	}
	visited[path] = true
	defer delete(visited, path)
	uuid, err := os.ReadFile(filepath.Join(path, "dm", "uuid")) // #nosec G304 -- path is a bounded, resolved /sys/devices node.
	if err == nil && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(uuid))), "CRYPT-") {
		encrypted = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, 0
	}
	entries, err := os.ReadDir(filepath.Join(path, "slaves"))
	if errors.Is(err, os.ErrNotExist) || err == nil && len(entries) == 0 {
		if !encrypted {
			return false, 1
		}
		return true, 1
	}
	if err != nil {
		return false, 0
	}
	slices.SortFunc(entries, func(left, right os.DirEntry) int { return strings.Compare(left.Name(), right.Name()) })
	leaves := 0
	for _, entry := range entries {
		child, resolveError := filepath.EvalSymlinks(filepath.Join(path, "slaves", entry.Name()))
		if resolveError != nil || !strings.HasPrefix(child, "/sys/devices/") {
			return false, 0
		}
		childOK, childLeaves := encryptedDeviceLeaves(child, encrypted, depth+1, visited)
		if !childOK {
			return false, 0
		}
		leaves += childLeaves
	}
	return leaves > 0, leaves
}
