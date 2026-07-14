//go:build darwin || linux

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func ensurePrivateMaterializationDirectory(ctx context.Context, privateBoundary, target string) error {
	if ctx == nil || !validMaterializationDirectoryBoundary(privateBoundary, target) {
		return artifactapp.ErrStoreIntegrity
	}
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return artifactapp.ErrStoreOperation
	}
	current := os.NewFile(uintptr(rootFD), "/")
	if current == nil {
		_ = unix.Close(rootFD)
		return artifactapp.ErrStoreOperation
	}
	defer func() { _ = current.Close() }()
	currentPath := ""
	for _, component := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		if err := ctx.Err(); err != nil {
			return errors.Join(artifactapp.ErrStoreOperation, err)
		}
		if !safeLeaf(component) {
			return artifactapp.ErrStoreIntegrity
		}
		nextPath := filepath.Join("/", currentPath, component)
		private := nextPath == privateBoundary || strings.HasPrefix(nextPath, privateBoundary+string(filepath.Separator))
		nextFD, openError := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if errors.Is(openError, unix.ENOENT) && private {
			if mkdirError := unix.Mkdirat(int(current.Fd()), component, 0o700); mkdirError != nil &&
				!errors.Is(mkdirError, unix.EEXIST) {
				return artifactapp.ErrStoreOperation
			}
			nextFD, openError = unix.Openat(
				int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
			)
		}
		if openError != nil {
			return artifactapp.ErrStoreIntegrity
		}
		var stat unix.Stat_t
		if unix.Fstat(nextFD, &stat) != nil || !safeControlledDirectoryStat(&stat, private) {
			_ = unix.Close(nextFD)
			return artifactapp.ErrStoreIntegrity
		}
		next := os.NewFile(uintptr(nextFD), nextPath)
		if next == nil {
			_ = unix.Close(nextFD)
			return artifactapp.ErrStoreOperation
		}
		_ = current.Close()
		current = next
		currentPath = strings.TrimPrefix(nextPath, "/")
	}
	return durableSync(current)
}

func validMaterializationDirectoryBoundary(privateBoundary, target string) bool {
	if privateBoundary == "" || target == "" || !filepath.IsAbs(privateBoundary) || !filepath.IsAbs(target) ||
		filepath.Clean(privateBoundary) != privateBoundary || filepath.Clean(target) != target {
		return false
	}
	relative, err := filepath.Rel(privateBoundary, target)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) && !pathEscapesBoundary(relative)
}
