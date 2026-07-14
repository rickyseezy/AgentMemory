package releaseverifyadapter

import (
	"context"
	"errors"
	"strings"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// CanonicalOCIIndexVerifier verifies OCI Image Index v1 bytes from the same
// immutable local source used for release evidence.
type CanonicalOCIIndexVerifier struct {
	source ResourceContentSource
}

var _ application.OCIIndexVerifier = (*CanonicalOCIIndexVerifier)(nil)

// NewCanonicalOCIIndexVerifier requires an immutable local artifact reader.
func NewCanonicalOCIIndexVerifier(source ResourceContentSource) (*CanonicalOCIIndexVerifier, error) {
	if adapterNil(source) {
		return nil, errors.New("release OCI index content source is required")
	}
	return &CanonicalOCIIndexVerifier{source: source}, nil
}

// VerifyOCIIndex proves that the signed index has exactly one descriptor for
// the selected platform-manifest digest, size, media type, OS, and architecture.
func (v *CanonicalOCIIndexVerifier) VerifyOCIIndex(
	ctx context.Context,
	subject releaseinventory.Resource,
	index releaseinventory.Resource,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if subject.Kind() != releaseinventory.ResourceKindOCIImage || subject.Platform().IsAny() ||
		index.Kind() != releaseinventory.ResourceKindOCIIndex || !index.Platform().IsAny() ||
		subject.OCIIndexResourceID() != index.ID() ||
		!subject.OCIIndexDigest().Equal(index.Digest()) {
		return application.ErrOCIIndexInvalid
	}
	raw, err := readEvidence(ctx, v.source, index)
	if err != nil {
		return evidencePortError(application.ErrOCIIndexInvalid, err)
	}
	var document ociIndexDocument
	if err := decodeCanonicalJSON(raw, &document); err != nil {
		return evidencePortError(application.ErrOCIIndexInvalid, err)
	}
	if !ociIndexBinds(document, subject) {
		return application.ErrOCIIndexInvalid
	}
	return nil
}

type ociIndexDocument struct {
	Manifests     []ociDescriptor `json:"manifests"`
	MediaType     string          `json:"mediaType"`
	SchemaVersion uint32          `json:"schemaVersion"`
}

type ociDescriptor struct {
	Digest    string      `json:"digest"`
	MediaType string      `json:"mediaType"`
	Platform  ociPlatform `json:"platform"`
	Size      uint64      `json:"size"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

func ociIndexBinds(document ociIndexDocument, subject releaseinventory.Resource) bool {
	if document.SchemaVersion != 2 || document.MediaType != releaseinventory.MediaTypeOCIIndex ||
		len(document.Manifests) == 0 || len(document.Manifests) > 256 {
		return false
	}
	seenDigests := make(map[string]struct{}, len(document.Manifests))
	seenPlatforms := make(map[string]struct{}, len(document.Manifests))
	previousDigest := ""
	matches := 0
	for position, descriptor := range document.Manifests {
		digestText := strings.TrimPrefix(descriptor.Digest, "sha256:")
		if descriptor.Digest != "sha256:"+digestText || !validHexDigest(digestText) ||
			descriptor.MediaType != releaseinventory.MediaTypeOCIManifest || descriptor.Size == 0 ||
			descriptor.Size > uint64(maximumSafeJSONInteger) {
			return false
		}
		platform, err := releaseinventory.NewPlatform(descriptor.Platform.OS, descriptor.Platform.Architecture)
		if err != nil {
			return false
		}
		if _, duplicate := seenDigests[descriptor.Digest]; duplicate {
			return false
		}
		platformKey := platform.String()
		if _, duplicate := seenPlatforms[platformKey]; duplicate {
			return false
		}
		if position > 0 && descriptor.Digest <= previousDigest {
			return false
		}
		seenDigests[descriptor.Digest] = struct{}{}
		seenPlatforms[platformKey] = struct{}{}
		previousDigest = descriptor.Digest
		if digestText == subject.Digest().Hex() {
			matches++
			if descriptor.Size != subject.Size() || platform != subject.Platform() {
				return false
			}
		}
	}
	return matches == 1
}
