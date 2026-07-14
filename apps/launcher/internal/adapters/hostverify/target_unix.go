//go:build darwin || linux

package hostverify

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type unixTargetEvidence struct {
	file      *os.File
	freeBytes uint64
	identity  string
}

func openControlledTarget(ctx context.Context, target string) (unixTargetEvidence, bool) {
	if err := ctx.Err(); err != nil || !strings.HasPrefix(target, "/") {
		return unixTargetEvidence{}, false
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return unixTargetEvidence{}, false
	}
	current := root
	closeCurrent := true
	defer func() {
		if closeCurrent {
			_ = unix.Close(current)
		}
	}()

	components := strings.Split(strings.TrimPrefix(target, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		components = nil
	}
	effectiveUID := os.Geteuid()
	if effectiveUID < 0 || uint64(effectiveUID) > math.MaxUint32 {
		return unixTargetEvidence{}, false
	}
	ownerUID := uint32(effectiveUID)
	for _, component := range components {
		if err := ctx.Err(); err != nil || component == "" || component == "." || component == ".." {
			return unixTargetEvidence{}, false
		}
		next, openError := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openError != nil {
			return unixTargetEvidence{}, false
		}
		var descriptor, linked unix.Stat_t
		descriptorError := unix.Fstat(next, &descriptor)
		linkedError := unix.Fstatat(current, component, &linked, unix.AT_SYMLINK_NOFOLLOW)
		if descriptorError != nil || linkedError != nil || descriptor.Dev != linked.Dev || descriptor.Ino != linked.Ino ||
			descriptor.Mode&unix.S_IFMT != unix.S_IFDIR || linked.Mode&unix.S_IFMT != unix.S_IFDIR ||
			descriptor.Mode&0o022 != 0 || (descriptor.Uid != 0 && descriptor.Uid != ownerUID) {
			_ = unix.Close(next)
			return unixTargetEvidence{}, false
		}
		_ = unix.Close(current)
		current = next
	}

	var descriptor unix.Stat_t
	if unix.Fstat(current, &descriptor) != nil || descriptor.Mode&unix.S_IFMT != unix.S_IFDIR ||
		descriptor.Uid != ownerUID || descriptor.Mode&0o022 != 0 {
		return unixTargetEvidence{}, false
	}
	var filesystem unix.Statfs_t
	if unix.Fstatfs(current, &filesystem) != nil {
		return unixTargetEvidence{}, false
	}
	blockSize := uint64(filesystem.Bsize)
	available := filesystem.Bavail
	if blockSize == 0 || available == 0 || available > math.MaxUint64/blockSize {
		return unixTargetEvidence{}, false
	}
	file := os.NewFile(uintptr(current), "host-verification-target")
	if file == nil {
		return unixTargetEvidence{}, false
	}
	closeCurrent = false
	return unixTargetEvidence{
		file: file, freeBytes: available * blockSize,
		identity: fmt.Sprintf("%v:%v", descriptor.Dev, descriptor.Ino),
	}, true
}

func targetIdentityUnchanged(ctx context.Context, target string, expected unixTargetEvidence) bool {
	observed, ok := openControlledTarget(ctx, target)
	if !ok {
		return false
	}
	defer func() { _ = observed.file.Close() }()
	return observed.identity == expected.identity
}
