//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
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

// OpenResource exposes the same retained-descriptor bundle authority to the
// release verifier. The signed resource must select one exact bundle source;
// mutable URLs and fallback allowlist entries are never resolved here.
func (f *BundleFetcher) OpenResource(
	ctx context.Context,
	resource releaseinventory.Resource,
) (io.ReadCloser, error) {
	source := resource.SourceRef()
	authorized := false
	for _, candidate := range resource.SourceAllowlist() {
		if candidate == source {
			authorized = true
			break
		}
	}
	if !authorized || resource.Size() == 0 {
		return nil, artifactapp.ErrFetchIntegrity
	}
	return f.openExactResource(ctx, source, resource.Size())
}

func (f *BundleFetcher) openExactResource(
	ctx context.Context,
	source string,
	expectedSize uint64,
) (io.ReadCloser, error) {
	if !f.beginOperation() {
		return nil, artifactapp.ErrFetchIntegrity
	}
	failed := true
	defer func() {
		if failed {
			f.endOperation()
		}
	}()
	if ctx == nil || ctx.Err() != nil || expectedSize == 0 || !strings.HasPrefix(source, "bundle://") {
		return nil, artifactapp.ErrFetchIntegrity
	}
	relative := strings.TrimPrefix(source, "bundle://")
	if relative == "" || strings.HasPrefix(relative, "/") || strings.HasSuffix(relative, "/") ||
		strings.Contains(relative, "//") {
		return nil, artifactapp.ErrFetchIntegrity
	}
	file, err := openSecureRelativeBundleFile(f.rootDirectory, relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil, artifactapp.ErrFetchUnavailable
	}
	if err != nil || file.verifyExactSize(expectedSize) != nil || file.verifyPathIdentity() != nil {
		if file != nil {
			file.close()
		}
		return nil, artifactapp.ErrFetchIntegrity
	}
	failed = false
	return &bundleResourceReader{owner: f, file: file, expectedSize: expectedSize}, nil
}

type bundleResourceReader struct {
	owner        *BundleFetcher
	file         *secureFile
	expectedSize uint64
	once         sync.Once
	closeError   error
}

func (r *bundleResourceReader) Read(destination []byte) (int, error) {
	if r == nil || r.file == nil || r.file.file == nil {
		return 0, artifactapp.ErrFetchIntegrity
	}
	return r.file.file.Read(destination)
}

func (r *bundleResourceReader) Close() error {
	if r == nil {
		return artifactapp.ErrFetchIntegrity
	}
	r.once.Do(func() {
		if r.file == nil || r.owner == nil || r.file.verifyExactSize(r.expectedSize) != nil ||
			r.file.verifyPathIdentity() != nil {
			r.closeError = artifactapp.ErrFetchIntegrity
		}
		if r.file != nil {
			r.file.close()
		}
		if r.owner != nil {
			r.owner.endOperation()
		}
		r.file = nil
		r.owner = nil
	})
	return r.closeError
}

var _ artifactapp.Fetcher = (*BundleFetcher)(nil)
