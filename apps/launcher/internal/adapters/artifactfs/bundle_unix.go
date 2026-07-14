//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// Fetch reads one exact offline-bundle range without following symlinks.
func (f *BundleFetcher) Fetch(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	source string,
	chunk artifactacquisition.Chunk,
) ([]byte, error) {
	if !f.beginOperation() {
		return nil, artifactapp.ErrFetchIntegrity
	}
	defer f.endOperation()
	if ctx == nil || !artifact.SourceAuthorized(source) || !strings.HasPrefix(source, "bundle://") {
		return nil, artifactapp.ErrFetchIntegrity
	}
	relative := strings.TrimPrefix(source, "bundle://")
	if relative == "" || strings.HasPrefix(relative, "/") || strings.HasSuffix(relative, "/") || strings.Contains(relative, "//") {
		return nil, artifactapp.ErrFetchIntegrity
	}
	file, err := openSecureRelativeBundleFile(f.rootDirectory, relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil, artifactapp.ErrFetchUnavailable
	}
	if err != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	defer file.close()
	info, err := file.file.Stat()
	fileSize, sizeValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !sizeValid || fileSize != artifact.Size() || file.verifyExactSize(artifact.Size()) != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	chunkSize, sizeValid := uint64ToInt(chunk.Size())
	chunkOffset, offsetValid := uint64ToInt64(chunk.Offset())
	if !sizeValid || !offsetValid {
		return nil, artifactapp.ErrFetchIntegrity
	}
	value := make([]byte, chunkSize)
	count, err := file.file.ReadAt(value, chunkOffset)
	if err != nil && !errors.Is(err, io.EOF) || count != chunkSize || !chunk.VerifyBytes(value) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(artifactapp.ErrFetchUnavailable, err)
	}
	if err := file.verifyExactSize(artifact.Size()); err != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	return value, nil
}

func openSecureRelativeBundleFile(root *os.File, relative string) (*secureFile, error) {
	components := strings.Split(relative, "/")
	if len(components) == 0 || len(components) > 64 {
		return nil, artifactapp.ErrFetchIntegrity
	}
	current, err := duplicateSecureDirectory(root)
	if err != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	for _, component := range components[:len(components)-1] {
		if !safeLeaf(component) {
			_ = current.Close()
			return nil, artifactapp.ErrFetchIntegrity
		}
		next, openError := openSecureChildDirectoryAt(current, component, false)
		_ = current.Close()
		if openError != nil {
			return nil, openError
		}
		current = next
	}
	file, err := openSecureReadLeafAt(current, components[len(components)-1])
	_ = current.Close()
	return file, err
}

var _ artifactapp.Fetcher = (*BundleFetcher)(nil)
