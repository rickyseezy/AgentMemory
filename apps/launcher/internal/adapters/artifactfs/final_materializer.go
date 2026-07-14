//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// MaterializeFinal copies one verified CAS object into an owner-private native
// installer path and publishes it atomically without replacing any existing
// name. Exact existing bytes are idempotent; every other collision fails closed.
func (s *Store) MaterializeFinal(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	privateBoundary string,
	targetPath string,
) error {
	if s == nil || ctx == nil || artifact.Size() == 0 || artifact.Digest().IsZero() ||
		!validPrivateMaterializationTarget(privateBoundary, targetPath) || !s.beginOperation() {
		return artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	if err := ctx.Err(); err != nil {
		return errors.Join(artifactapp.ErrStoreOperation, err)
	}
	targetDirectoryPath := filepath.Dir(targetPath)
	if err := ensurePrivateMaterializationDirectory(ctx, privateBoundary, targetDirectoryPath); err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	targetDirectory, err := openSecureDirectory(targetDirectoryPath)
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer func() { _ = targetDirectory.Close() }()
	targetLeaf := filepath.Base(targetPath)
	if err := verifyMaterializedFinal(ctx, targetDirectory, targetLeaf, artifact); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return artifactapp.ErrStoreIntegrity
	}
	reader, err := s.OpenFinal(ctx, artifact)
	if err != nil {
		return err
	}
	readerOpen := true
	defer func() {
		if readerOpen {
			_ = reader.Close()
		}
	}()
	temporaryLeaf, err := materializationTemporaryLeaf()
	if err != nil {
		return artifactapp.ErrStoreOperation
	}
	temporary, created, err := openSecureLeafAt(targetDirectory, temporaryLeaf, true)
	if err != nil || !created {
		if temporary != nil {
			temporary.close()
		}
		return artifactapp.ErrStoreOperation
	}
	published := false
	defer func() {
		if !published {
			_ = removeOpenSecureFile(temporary)
		}
		temporary.close()
	}()
	written, copyError := io.Copy(temporary.file, reader)
	if copyError != nil || written < 0 || uint64(written) != artifact.Size() ||
		temporary.verifyExactSize(artifact.Size()) != nil || durableSync(temporary.file) != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := reader.Close(); err != nil {
		readerOpen = false
		return artifactapp.ErrStoreIntegrity
	}
	readerOpen = false
	if err := renameSecureNoReplace(temporary, targetDirectory, targetLeaf); err != nil {
		if errors.Is(err, os.ErrExist) {
			if removeError := removeOpenSecureFile(temporary); removeError != nil {
				return artifactapp.ErrStoreOperation
			}
			published = true
			return verifyMaterializedFinal(ctx, targetDirectory, targetLeaf, artifact)
		}
		return artifactapp.ErrStoreOperation
	}
	published = true
	if durableSync(targetDirectory) != nil {
		return artifactapp.ErrStoreOperation
	}
	return verifyMaterializedFinal(ctx, targetDirectory, targetLeaf, artifact)
}

func validPrivateMaterializationTarget(privateBoundary, targetPath string) bool {
	if privateBoundary == "" || targetPath == "" || !filepath.IsAbs(privateBoundary) || !filepath.IsAbs(targetPath) ||
		filepath.Clean(privateBoundary) != privateBoundary || filepath.Clean(targetPath) != targetPath ||
		!safeLeaf(filepath.Base(targetPath)) {
		return false
	}
	relative, err := filepath.Rel(privateBoundary, filepath.Dir(targetPath))
	return err == nil && relative != ".." && !filepath.IsAbs(relative) &&
		(relative == "." || !pathEscapesBoundary(relative))
}

func pathEscapesBoundary(relative string) bool {
	return relative == ".." || len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)
}

func materializationTemporaryLeaf() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return ".agentmemory-materialize-" + hex.EncodeToString(token[:]) + ".tmp", nil
}

func verifyMaterializedFinal(
	ctx context.Context,
	directory *os.File,
	leaf string,
	artifact artifactacquisition.Artifact,
) error {
	opened, err := openSecureReadLeafAt(directory, leaf)
	if err != nil {
		return err
	}
	defer opened.close()
	return verifyFile(ctx, opened, artifact)
}

var _ artifactapp.VerifiedFinalMaterializer = (*Store)(nil)
