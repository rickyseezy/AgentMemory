// Package artifactfs implements owner-controlled local artifact reservation,
// partial storage, atomic CAS publication, and verified offline-bundle reads.
package artifactfs

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
)

// Store is rooted at one proven local, owner-only, non-symlink directory.
type Store struct {
	filesystemID    string
	identityFile    *os.File
	identityDir     *os.File
	identityValue   [32]byte
	rootDirectory   *os.File
	partialRoot     *os.File
	reservationRoot *os.File
	casRoot         *os.File
	available       func(*os.File) (uint64, error)
	// reservationSafe is established from the retained root descriptor, never
	// from a caller-supplied path. CoW/snapshot filesystems are deliberately
	// rejected because allocating extents does not reserve later CoW writes.
	reservationSafe bool
	lifecycle       sync.RWMutex
	closed          bool
	// afterPublish is a deterministic test seam for exercising replacement
	// between publication and mandatory final-path re-verification.
	afterPublish func()
}

// NewStore constructs the platform implementation or fails closed when local
// filesystem and durability semantics cannot be proven.
func NewStore(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsRune(root, 0) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	return newStore(root)
}

// BundleFetcher reads exact ranges from a previously verified offline bundle.
type BundleFetcher struct {
	rootDirectory *os.File
	lifecycle     sync.RWMutex
	closed        bool
}

// NewBundleFetcher accepts only a proven local owner-controlled bundle root.
func NewBundleFetcher(root string) (*BundleFetcher, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, artifactapp.ErrFetchIntegrity
	}
	rootDirectory, err := openSecureDirectory(root)
	if err != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	local, _, err := localFilesystemDescriptor(rootDirectory)
	if err != nil || !local {
		_ = rootDirectory.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return &BundleFetcher{rootDirectory: rootDirectory}, nil
}

func safeToken(value string, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, prefix) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sanitizeStoreError(err error, integrity bool) error {
	if errors.Is(err, artifactapp.ErrArtifactNotFound) || errors.Is(err, artifactapp.ErrStoreIntegrity) ||
		errors.Is(err, artifactapp.ErrStoreOperation) {
		return err
	}
	if integrity {
		return artifactapp.ErrStoreIntegrity
	}
	return artifactapp.ErrStoreOperation
}

func infoSize(info os.FileInfo, err error) int64 {
	if err != nil || info == nil {
		return -1
	}
	return info.Size()
}

func nonNegativeInt64(value int64) (uint64, bool) {
	if value < 0 {
		return 0, false
	}
	return uint64(value), true // #nosec G115 -- non-negativity is proven above.
}

func uint64ToInt64(value uint64) (int64, bool) {
	if value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true // #nosec G115 -- upper bound is proven above.
}

func uint64ToInt(value uint64) (int, bool) {
	if value > math.MaxInt {
		return 0, false
	}
	return int(value), true // #nosec G115 -- architecture-specific bound is proven above.
}
