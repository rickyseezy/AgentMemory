//go:build darwin || linux || windows

package artifactfs

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func attestHostReleasePool(locator string) (artifactacquisition.StoragePool, error) {
	ancestor, err := openNearestSecureAncestor(locator)
	if err != nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	defer func() { _ = ancestor.Close() }()
	local, filesystemID, err := localFilesystemDescriptor(ancestor)
	if err != nil || !local || filesystemID == "" {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	digest := sha256.Sum256([]byte("agentmemory-host-release-pool-v1\x00" + filesystemID + "\x00" + locator))
	return artifactacquisition.NewStoragePool("r-"+releaseinventory.Digest(digest).Hex(), artifactapp.CapacityHostRelease)
}

func openNearestSecureAncestor(target string) (*os.File, error) {
	if target == "" || len(target) > 4096 || !filepath.IsAbs(target) || filepath.Clean(target) != target ||
		strings.ContainsRune(target, 0) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	for candidate := target; ; candidate = filepath.Dir(candidate) {
		info, err := os.Lstat(candidate)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, artifactapp.ErrStoreIntegrity
			}
			directory, openErr := openSecureDirectory(candidate)
			if openErr != nil {
				return nil, openErr
			}
			return directory, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return nil, artifactapp.ErrStoreIntegrity
		}
	}
}
