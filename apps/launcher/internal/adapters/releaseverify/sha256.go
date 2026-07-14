package releaseverifyadapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	resourceDigestBufferSize     = 32 * 1024
	maximumConsecutiveEmptyReads = 100
)

// ResourceContentSource opens exact locally acquired bytes. Production sources
// must themselves enforce owner/symlink/source policy; this verifier performs
// no network access and never resolves a mutable locator.
type ResourceContentSource interface {
	OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error)
}

// SHA256ResourceDigestVerifier streams exact bytes through SHA-256 and also
// enforces the signed byte length.
type SHA256ResourceDigestVerifier struct {
	source ResourceContentSource
}

var _ application.ResourceDigestVerifier = (*SHA256ResourceDigestVerifier)(nil)

// NewSHA256ResourceDigestVerifier requires an exact local content source.
func NewSHA256ResourceDigestVerifier(
	source ResourceContentSource,
) (*SHA256ResourceDigestVerifier, error) {
	if adapterNil(source) {
		return nil, errors.New("release content source is required")
	}
	return &SHA256ResourceDigestVerifier{source: source}, nil
}

// VerifyResourceDigest streams, bounds, hashes, and closes one resource.
func (v *SHA256ResourceDigestVerifier) VerifyResourceDigest(
	ctx context.Context,
	resource releaseinventory.Resource,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	reader, err := v.source.OpenResource(ctx, resource)
	if err != nil {
		if contextError := adapterContextError(ctx); contextError != nil {
			return contextError
		}
		return errors.Join(application.ErrResourceUnavailable, err)
	}
	if adapterNil(reader) {
		return application.ErrResourceUnavailable
	}

	hasher := sha256.New()
	// Resource construction limits size to the exact-integer range (2^53-1),
	// which is strictly below MaxInt64 on every supported launcher target.
	//nolint:gosec // G115: the signed domain invariant proves this conversion cannot overflow.
	limited := &io.LimitedReader{R: reader, N: int64(resource.Size()) + 1}
	buffer := make([]byte, resourceDigestBufferSize)
	var total uint64
	var readError error
	emptyReads := 0
	for {
		if contextError := adapterContextError(ctx); contextError != nil {
			readError = contextError
			break
		}
		count, nextError := limited.Read(buffer)
		if count > 0 {
			emptyReads = 0
			total += uint64(count)
			if _, writeError := hasher.Write(buffer[:count]); writeError != nil {
				readError = writeError
				break
			}
		}
		if count == 0 && nextError == nil {
			emptyReads++
			if emptyReads >= maximumConsecutiveEmptyReads {
				readError = io.ErrNoProgress
				break
			}
		}
		if nextError != nil {
			if !errors.Is(nextError, io.EOF) {
				readError = nextError
			}
			break
		}
	}
	closeError := reader.Close()
	if readError != nil {
		if errors.Is(readError, context.Canceled) || errors.Is(readError, context.DeadlineExceeded) {
			return readError
		}
		return errors.Join(application.ErrResourceUnavailable, readError, closeError)
	}
	if closeError != nil {
		return errors.Join(application.ErrResourceUnavailable, closeError)
	}
	if total != resource.Size() {
		return fmt.Errorf("%w: byte length differs", application.ErrResourceDigestMismatch)
	}
	calculated := releaseinventory.Digest(hasher.Sum(nil))
	if !calculated.Equal(resource.Digest()) {
		return fmt.Errorf("%w: SHA-256 differs", application.ErrResourceDigestMismatch)
	}
	return nil
}

func adapterNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}
