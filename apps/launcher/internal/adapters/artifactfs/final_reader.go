//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"os"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// OpenFinal opens an immutable-by-contract CAS object without exposing its
// ambient path. The store lifecycle read lock remains held until Close.
func (s *Store) OpenFinal(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
) (io.ReadCloser, error) {
	if !s.beginOperation() {
		return nil, artifactapp.ErrStoreIntegrity
	}
	failed := true
	defer func() {
		if failed {
			s.endOperation()
		}
	}()
	if ctx == nil || artifact.Size() == 0 || artifact.Digest().IsZero() || len(artifact.Chunks()) == 0 {
		return nil, artifactapp.ErrStoreIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(artifactapp.ErrStoreOperation, err)
	}
	prefix, _, err := finalParts(artifact.ContentKey())
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	directory, leaf, err := s.finalLocation(artifact.ContentKey(), false)
	if err != nil {
		return nil, err
	}
	file, err := openSecureReadLeafAt(directory, leaf)
	if errors.Is(err, os.ErrNotExist) {
		_ = directory.Close()
		return nil, artifactapp.ErrArtifactNotFound
	}
	if err != nil {
		_ = directory.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	if verifyFile(ctx, file, artifact) != nil || file.verifyPathIdentity() != nil ||
		!secureChildDirectoryIdentity(s.casRoot, prefix, directory) {
		file.close()
		_ = directory.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		file.close()
		_ = directory.Close()
		return nil, artifactapp.ErrStoreOperation
	}
	failed = false
	return &verifiedFinalReader{
		owner: s, directory: directory, prefix: prefix, file: file, artifact: artifact,
		ctx: ctx, hasher: sha256.New(),
	}, nil
}

type verifiedFinalReader struct {
	owner     *Store
	directory *os.File
	prefix    string
	file      *secureFile
	artifact  artifactacquisition.Artifact
	ctx       context.Context
	hasher    hash.Hash
	readBytes uint64
	once      sync.Once
	closeErr  error
	closed    bool
}

func (r *verifiedFinalReader) Read(destination []byte) (int, error) {
	if r == nil || r.closed || r.file == nil || r.file.file == nil || r.hasher == nil || r.ctx == nil {
		return 0, artifactapp.ErrStoreIntegrity
	}
	if err := r.ctx.Err(); err != nil {
		return 0, errors.Join(artifactapp.ErrStoreOperation, err)
	}
	count, err := r.file.file.Read(destination)
	if count < 0 || count > len(destination) || r.readBytes > r.artifact.Size() ||
		uint64(count) > r.artifact.Size()-r.readBytes {
		return 0, artifactapp.ErrStoreIntegrity
	}
	if count > 0 {
		_, _ = r.hasher.Write(destination[:count])
		r.readBytes += uint64(count)
	}
	return count, err
}

func (r *verifiedFinalReader) Close() error {
	if r == nil {
		return artifactapp.ErrStoreIntegrity
	}
	r.once.Do(func() {
		r.closed = true
		if r.owner == nil || r.file == nil || r.file.file == nil || r.directory == nil || r.hasher == nil ||
			r.readBytes != r.artifact.Size() || !readerDigest(r.hasher).Equal(r.artifact.Digest()) ||
			r.file.verifyPathIdentity() != nil || r.file.verifyExactSize(r.artifact.Size()) != nil ||
			!secureChildDirectoryIdentity(r.owner.casRoot, r.prefix, r.directory) {
			r.closeErr = artifactapp.ErrStoreIntegrity
		}
		if r.file != nil {
			r.file.close()
		}
		if r.directory != nil {
			if err := r.directory.Close(); err != nil {
				r.closeErr = errors.Join(r.closeErr, artifactapp.ErrStoreOperation)
			}
		}
		if r.owner != nil {
			r.owner.endOperation()
		}
	})
	return r.closeErr
}

func readerDigest(hasher hash.Hash) releaseinventory.Digest {
	var digest releaseinventory.Digest
	if hasher != nil {
		copy(digest[:], hasher.Sum(nil))
	}
	return digest
}

var _ artifactapp.VerifiedFinalReader = (*Store)(nil)
