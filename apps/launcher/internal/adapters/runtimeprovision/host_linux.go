//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"strings"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const (
	linuxExtMagic              = int64(0xef53)
	linuxXFSMagic              = int64(0x58465342)
	linuxBtrfsMagic            = int64(0x9123683e)
	linuxZFSMagic              = int64(0x2fc12fc1)
	linuxF2FSMagic             = int64(0xf2f52010)
	linuxTmpfsMagic            = int64(0x01021994)
	maximumSupplementaryGroups = 65536
)

// NativeHostProbe uses fixed Linux files and syscalls only.
type NativeHostProbe struct{}

// NewNativeHostProbe constructs the production Linux host probe.
func NewNativeHostProbe() *NativeHostProbe { return &NativeHostProbe{} }

// ProbeLinuxHost independently proves the signed host/principal tuple.
func (*NativeHostProbe) ProbeLinuxHost(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (HostEvidence, error) {
	if ctx == nil {
		return HostEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return HostEvidence{}, err
	}
	if !authority.Valid() || runtime.GOOS != "linux" || os.Geteuid() != int(authority.InvokingUID()) ||
		os.Getegid() != int(authority.InvokingGID()) {
		return HostEvidence{}, ErrUnsupportedHost
	}
	distribution, versionID, err := linuxOSRelease()
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	kernel, architecture, err := linuxKernelArchitecture()
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	machineDigest, err := linuxMachineDigest()
	if err != nil || machineDigest != authority.MachineDigest() {
		return HostEvidence{}, ErrUnsupportedHost
	}
	if err := validateOwnerDirectory(authority.HomeDirectory(), authority.InvokingUID(), false); err != nil {
		return HostEvidence{}, ErrUnsupportedHost
	}
	cpus, totalMemory, availableMemory, err := linuxResources()
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	freeDisk, localFilesystem, err := linuxHomeFilesystem(authority.HomeDirectory())
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	userNamespaces, err := linuxUserNamespaces()
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	userSystemd := linuxUserSystemd(authority.RuntimeDirectory(), authority.InvokingUID())
	dockerGroupAbsent, err := linuxDockerGroupAbsent(authority.AccountName(), authority.InvokingGID())
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	selinux, err := linuxSELinuxEnforcing()
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	subUIDs, err := linuxSubordinateCount("/etc/subuid", authority.AccountName())
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	subGIDs, err := linuxSubordinateCount("/etc/subgid", authority.AccountName())
	if err != nil {
		return HostEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	if err := ctx.Err(); err != nil {
		return HostEvidence{}, err
	}
	return NewHostEvidence(HostEvidenceInput{
		Distribution: distribution, VersionID: versionID, Kernel: kernel, Architecture: architecture,
		UID: authority.InvokingUID(), GID: authority.InvokingGID(), CPUs: cpus,
		TotalMemory: totalMemory, AvailableMemory: availableMemory, FreeDisk: freeDisk,
		UserNamespaces: userNamespaces, UserSystemd: userSystemd, LocalFilesystem: localFilesystem,
		DockerGroupAbsent: dockerGroupAbsent, SELinuxEnforcing: selinux,
		SubordinateUIDs: subUIDs, SubordinateGIDs: subGIDs,
		MachineDigest: machineDigest,
	})
}

func linuxDockerGroupAbsent(account string, primaryGID uint32) (bool, error) {
	raw, err := readRootOwnedRegular("/etc/group", maximumIDMapBytes)
	if err != nil {
		return false, err
	}
	groups, err := unix.Getgroups()
	if err != nil || len(groups) > maximumSupplementaryGroups {
		return false, ErrProbeFailed
	}
	active := make(map[uint32]struct{}, len(groups)+1)
	active[primaryGID] = struct{}{}
	for _, group := range groups {
		if group < 0 || uint64(group) > math.MaxUint32 {
			return false, ErrProbeFailed
		}
		active[uint32(group)] = struct{}{} // #nosec G115 -- range is explicitly proven above.
	}
	return dockerGroupAbsent(raw, account, active)
}

func linuxOSRelease() (string, string, error) {
	path := "/etc/os-release"
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readError := os.Readlink(path)
		if readError != nil || target != "/usr/lib/os-release" && target != "../usr/lib/os-release" {
			return "", "", ErrProbeFailed
		}
		path = "/usr/lib/os-release"
	}
	raw, err := readRootOwnedRegular(path, maximumOSReleaseBytes)
	if err != nil {
		return "", "", err
	}
	return parseOSRelease(raw)
}

func linuxKernelArchitecture() (string, runtimeinstall.Architecture, error) {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "", runtimeinstall.ArchitectureUnknown, err
	}
	bytes := make([]byte, 0, len(name.Release))
	for _, character := range name.Release {
		if character == 0 {
			break
		}
		bytes = append(bytes, character)
	}
	kernel := string(bytes)
	if !validKernel(kernel) {
		return "", runtimeinstall.ArchitectureUnknown, ErrProbeFailed
	}
	var architecture runtimeinstall.Architecture
	switch runtime.GOARCH {
	case "amd64":
		architecture = runtimeinstall.ArchitectureAMD64
	case "arm64":
		architecture = runtimeinstall.ArchitectureARM64
	default:
		return "", runtimeinstall.ArchitectureUnknown, ErrUnsupportedHost
	}
	return kernel, architecture, nil
}

func linuxMachineDigest() (runtimeinstall.Hash, error) {
	raw, err := readRootOwnedRegular("/etc/machine-id", 128)
	if err != nil {
		return runtimeinstall.Hash{}, err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if len(value) != 32 {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return runtimeinstall.Hash{}, ErrProbeFailed
			}
		}
	}
	return runtimeinstall.Sum([]byte(value)), nil
}

func readRootOwnedRegular(path string, maximum int64) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "runtime-provision-read")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProbeFailed
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 ||
		stat.Mode&0o022 != 0 || stat.Size < 0 || stat.Size > maximum {
		return nil, ErrProbeFailed
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, ErrProbeFailed
	}
	return raw, nil
}

func validateOwnerDirectory(path string, uid uint32, runtimeDirectory bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProbeFailed
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode().Perm()&0o022 != 0 {
		return ErrProbeFailed
	}
	if runtimeDirectory && info.Mode().Perm() != 0o700 {
		return ErrProbeFailed
	}
	return nil
}

func linuxResources() (uint16, uint64, uint64, error) {
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		return 0, 0, 0, ErrProbeFailed
	}
	cpuCount := affinity.Count()
	if cpuCount <= 0 || cpuCount > math.MaxUint16 {
		return 0, 0, 0, ErrProbeFailed
	}
	var information unix.Sysinfo_t
	if err := unix.Sysinfo(&information); err != nil || information.Totalram == 0 || information.Unit == 0 {
		return 0, 0, 0, ErrProbeFailed
	}
	total := information.Totalram
	unit := uint64(information.Unit)
	if total > math.MaxUint64/unit {
		return 0, 0, 0, ErrProbeFailed
	}
	meminfo, err := readRootOwnedRegular("/proc/meminfo", maximumOSReleaseBytes)
	if err != nil {
		return 0, 0, 0, err
	}
	available, err := parseMemAvailable(meminfo)
	if err != nil || available > total*unit {
		return 0, 0, 0, ErrProbeFailed
	}
	return uint16(cpuCount), total * unit, available, nil // #nosec G115 -- cpuCount is proven positive and <= MaxUint16 above.
}

func linuxHomeFilesystem(path string) (uint64, bool, error) {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil || filesystem.Bsize <= 0 {
		return 0, false, ErrProbeFailed
	}
	blockSize := uint64(filesystem.Bsize)
	if filesystem.Bavail > math.MaxUint64/blockSize {
		return 0, false, ErrProbeFailed
	}
	local := false
	switch filesystem.Type {
	case linuxExtMagic, linuxXFSMagic, linuxBtrfsMagic, linuxZFSMagic, linuxF2FSMagic:
		local = true
	default:
	}
	return filesystem.Bavail * blockSize, local, nil
}

func linuxUserNamespaces() (bool, error) {
	maximum, err := readRootOwnedRegular("/proc/sys/user/max_user_namespaces", 128)
	if err != nil {
		return false, err
	}
	if _, err := parsePositiveUint(maximum); err != nil {
		return false, err
	}
	clone, err := readRootOwnedRegular("/proc/sys/kernel/unprivileged_userns_clone", 128)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	value := strings.TrimSuffix(string(clone), "\n")
	return value == "1", nil
}

func linuxUserSystemd(runtimeDirectory string, uid uint32) bool {
	if validateOwnerDirectory(runtimeDirectory, uid, true) != nil {
		return false
	}
	var filesystem unix.Statfs_t
	if unix.Statfs(runtimeDirectory, &filesystem) != nil || filesystem.Type != linuxTmpfsMagic {
		return false
	}
	info, err := os.Lstat(runtimeDirectory + "/bus")
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}

func linuxSELinuxEnforcing() (bool, error) {
	raw, err := readRootOwnedRegular("/sys/fs/selinux/enforce", 8)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if value != "0" && value != "1" {
		return false, ErrProbeFailed
	}
	return value == "1", nil
}

func linuxSubordinateCount(path, principal string) (uint32, error) {
	raw, err := readRootOwnedRegular(path, maximumIDMapBytes)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	ranges, err := parseSubordinateRanges(raw)
	if err != nil {
		return 0, err
	}
	return subordinateCount(ranges, principal)
}

var _ HostProbe = (*NativeHostProbe)(nil)
