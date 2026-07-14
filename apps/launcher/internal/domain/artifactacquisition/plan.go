// Package artifactacquisition defines signed-plan-bound space reservation and
// verified content-addressed artifact acquisition.
package artifactacquisition

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const maximumSafeBytes = uint64(1<<53 - 1)

var (
	// ErrInvalidPlan rejects unsigned, inconsistent, overflowing, or mutable input.
	ErrInvalidPlan = errors.New("invalid signed artifact acquisition plan")
	// ErrInvalidTransition rejects an acquisition state change that lacks its
	// required reservation, ownership, chunk, or final-content proof.
	ErrInvalidTransition = errors.New("invalid artifact acquisition transition")
	// ErrIntegrity rejects contradictory authenticated acquisition state.
	ErrIntegrity = errors.New("artifact acquisition integrity violation")
	// ErrUnauthorizedPartial rejects mutation without aggregate-minted ownership.
	ErrUnauthorizedPartial = errors.New("artifact partial mutation is unauthorized")
)

// Chunk is one signed contiguous byte-range digest.
type Chunk struct {
	index  uint32
	offset uint64
	size   uint64
	digest releaseinventory.Digest
}

// Index returns the zero-based signed chunk index.
func (c Chunk) Index() uint32 { return c.index }

// Offset returns the inclusive byte offset.
func (c Chunk) Offset() uint64 { return c.offset }

// Size returns the exact chunk byte length.
func (c Chunk) Size() uint64 { return c.size }

// End returns the inclusive final byte offset.
func (c Chunk) End() uint64 { return c.offset + c.size - 1 }

// Digest returns the expected chunk SHA-256 digest.
func (c Chunk) Digest() releaseinventory.Digest { return c.digest }

// VerifyBytes validates exact length and SHA-256 before any store write.
func (c Chunk) VerifyBytes(value []byte) bool {
	return uint64(len(value)) == c.size && releaseinventory.DigestBytes(value).Equal(c.digest)
}

// ChunkInput is the signed persistence-neutral chunk descriptor.
type ChunkInput struct {
	Offset uint64
	Size   uint64
	Digest releaseinventory.Digest
}

// ArtifactInput describes one signed immutable artifact.
type ArtifactInput struct {
	ID                    string
	Digest                releaseinventory.Digest
	Size                  uint64
	ExpandedBytes         uint64
	ExpandedDigest        releaseinventory.Digest
	TargetKind            releaseinventory.ExpandedTargetKind
	TargetStorageID       string
	TargetAuthorityDigest releaseinventory.Digest
	Sources               []string
	Chunks                []ChunkInput
}

// Artifact is one immutable content-addressed acquisition subject.
type Artifact struct {
	id                    string
	digest                releaseinventory.Digest
	size                  uint64
	expandedBytes         uint64
	expandedDigest        releaseinventory.Digest
	targetKind            releaseinventory.ExpandedTargetKind
	targetStorageID       string
	targetAuthorityDigest releaseinventory.Digest
	sources               []string
	chunks                []Chunk
}

// ID returns the signed logical resource ID.
func (a Artifact) ID() string { return a.id }

// Digest returns the final expected SHA-256.
func (a Artifact) Digest() releaseinventory.Digest { return a.digest }

// Size returns the exact final byte length.
func (a Artifact) Size() uint64 { return a.size }

// ExpandedBytes returns signed extraction/install space.
func (a Artifact) ExpandedBytes() uint64 { return a.expandedBytes }

// ExpandedDigest returns the signed immutable OCI/model/bundle target digest.
func (a Artifact) ExpandedDigest() releaseinventory.Digest { return a.expandedDigest }

// TargetKind returns the release-signed expanded representation kind.
func (a Artifact) TargetKind() releaseinventory.ExpandedTargetKind { return a.targetKind }

// TargetStorageID returns the normalized release-relative target identity.
func (a Artifact) TargetStorageID() string { return a.targetStorageID }

// TargetAuthorityDigest returns the selected publisher-signed target authority digest.
func (a Artifact) TargetAuthorityDigest() releaseinventory.Digest { return a.targetAuthorityDigest }

// Sources returns exact allowlisted HTTPS or offline-bundle references.
func (a Artifact) Sources() []string { return append([]string(nil), a.sources...) }

// Chunks returns immutable-by-copy contiguous chunk descriptors.
func (a Artifact) Chunks() []Chunk { return append([]Chunk(nil), a.chunks...) }

// ContentKey returns the canonical relative CAS key.
func (a Artifact) ContentKey() string {
	hexDigest := a.digest.Hex()
	return "sha256/" + hexDigest[:2] + "/" + hexDigest
}

// SourceAuthorized reports exact, not prefix, allowlist membership.
func (a Artifact) SourceAuthorized(source string) bool {
	index := sort.SearchStrings(a.sources, source)
	return index < len(a.sources) && a.sources[index] == source
}

// TotalsInput repeats signed manifest totals so arithmetic disagreement fails closed.
type TotalsInput struct {
	DownloadBytes         uint64
	ExpandedBytes         uint64
	RollbackHeadroomBytes uint64
	SafetyHeadroomBytes   uint64
	RequiredBytes         uint64
}

// PlanInput is the verified release projection consumed by acquisition.
type PlanInput struct {
	PlanDigest releaseinventory.Digest
	Artifacts  []ArtifactInput
	Totals     TotalsInput
}

// Totals are checked signed capacity requirements.
type Totals struct {
	download uint64
	expanded uint64
	rollback uint64
	safety   uint64
	required uint64
}

// DownloadBytes returns exact compressed/download bytes.
func (t Totals) DownloadBytes() uint64 { return t.download }

// ExpandedBytes returns exact expansion/install bytes.
func (t Totals) ExpandedBytes() uint64 { return t.expanded }

// RollbackHeadroomBytes returns preserved rollback-generation headroom.
func (t Totals) RollbackHeadroomBytes() uint64 { return t.rollback }

// SafetyHeadroomBytes returns the signed post-install free-space floor.
func (t Totals) SafetyHeadroomBytes() uint64 { return t.safety }

// RequiredBytes returns the checked sum of all four components.
func (t Totals) RequiredBytes() uint64 { return t.required }

// Plan is a closed, signed, immutable acquisition plan.
type Plan struct {
	digest    releaseinventory.Digest
	artifacts []Artifact
	totals    Totals
}

// NewPlan validates signed totals, sources, ranges, digests, and overflow.
func NewPlan(input PlanInput) (Plan, error) {
	if input.PlanDigest.IsZero() || len(input.Artifacts) == 0 || len(input.Artifacts) > 4096 {
		return Plan{}, ErrInvalidPlan
	}
	artifacts := make([]Artifact, 0, len(input.Artifacts))
	seenIDs := make(map[string]struct{}, len(input.Artifacts))
	seenDigests := make(map[string]struct{}, len(input.Artifacts))
	var download, expanded uint64
	for _, raw := range input.Artifacts {
		artifact, err := newArtifact(raw)
		if err != nil {
			return Plan{}, err
		}
		if _, duplicate := seenIDs[artifact.id]; duplicate {
			return Plan{}, ErrInvalidPlan
		}
		if _, duplicate := seenDigests[artifact.digest.Hex()]; duplicate {
			return Plan{}, ErrInvalidPlan
		}
		seenIDs[artifact.id] = struct{}{}
		seenDigests[artifact.digest.Hex()] = struct{}{}
		download, err = checkedAdd(download, artifact.size)
		if err != nil {
			return Plan{}, err
		}
		expanded, err = checkedAdd(expanded, artifact.expandedBytes)
		if err != nil {
			return Plan{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	if download != input.Totals.DownloadBytes || expanded != input.Totals.ExpandedBytes ||
		input.Totals.RollbackHeadroomBytes == 0 || input.Totals.SafetyHeadroomBytes == 0 {
		return Plan{}, ErrInvalidPlan
	}
	required, err := checkedAdd(download, expanded)
	if err == nil {
		required, err = checkedAdd(required, input.Totals.RollbackHeadroomBytes)
	}
	if err == nil {
		required, err = checkedAdd(required, input.Totals.SafetyHeadroomBytes)
	}
	if err != nil || required != input.Totals.RequiredBytes {
		return Plan{}, ErrInvalidPlan
	}
	return Plan{
		digest: input.PlanDigest, artifacts: artifacts,
		totals: Totals{download: download, expanded: expanded, rollback: input.Totals.RollbackHeadroomBytes,
			safety: input.Totals.SafetyHeadroomBytes, required: required},
	}, nil
}

// Digest returns the signed plan binding.
func (p Plan) Digest() releaseinventory.Digest { return p.digest }

// Artifacts returns immutable-by-copy descriptors in signed order.
func (p Plan) Artifacts() []Artifact { return append([]Artifact(nil), p.artifacts...) }

// Totals returns the checked capacity contract.
func (p Plan) Totals() Totals { return p.totals }

// Artifact returns an exact logical descriptor.
func (p Plan) Artifact(id string) (Artifact, bool) {
	for _, artifact := range p.artifacts {
		if artifact.id == id {
			return artifact, true
		}
	}
	return Artifact{}, false
}

// ReservationID derives an opaque plan-and-operation-bound reservation key.
func (p Plan) ReservationID(operationID string) (string, error) {
	if !validIdentifier(operationID) {
		return "", ErrInvalidPlan
	}
	digest := sha256.Sum256([]byte("reservation\x00" + p.digest.Hex() + "\x00" + operationID))
	return "r-" + releaseinventory.Digest(digest).Hex(), nil
}

func newArtifact(input ArtifactInput) (Artifact, error) {
	if !validIdentifier(input.ID) || input.Digest.IsZero() || input.Size == 0 ||
		input.Size > maximumSafeBytes || input.ExpandedBytes > maximumSafeBytes ||
		(input.ExpandedBytes > 0) != !input.ExpandedDigest.IsZero() ||
		len(input.Sources) == 0 || len(input.Sources) > 16 || len(input.Chunks) == 0 || len(input.Chunks) > 65536 {
		return Artifact{}, ErrInvalidPlan
	}
	if input.ExpandedBytes > 0 {
		target, targetError := releaseinventory.NewReleaseExpandedTarget(
			input.Digest, input.Size, releaseinventory.ReleaseExpandedTargetInput{
				Kind: input.TargetKind, StorageID: input.TargetStorageID,
				Digest: input.ExpandedDigest, Bytes: input.ExpandedBytes,
			},
		)
		if targetError != nil || !target.AuthorityDigest().Equal(input.TargetAuthorityDigest) {
			return Artifact{}, ErrInvalidPlan
		}
	} else if input.TargetKind != "" || input.TargetStorageID != "" || !input.TargetAuthorityDigest.IsZero() {
		return Artifact{}, ErrInvalidPlan
	}
	sources := append([]string(nil), input.Sources...)
	sort.Strings(sources)
	for index, source := range sources {
		if !validSource(source) || (index > 0 && sources[index-1] == source) {
			return Artifact{}, ErrInvalidPlan
		}
	}
	chunks := make([]Chunk, 0, len(input.Chunks))
	var cursor uint64
	for index, raw := range input.Chunks {
		if raw.Offset != cursor || raw.Size == 0 || raw.Digest.IsZero() {
			return Artifact{}, ErrInvalidPlan
		}
		next, err := checkedAdd(cursor, raw.Size)
		if err != nil || next > input.Size {
			return Artifact{}, ErrInvalidPlan
		}
		chunks = append(chunks, Chunk{index: uint32(index), offset: raw.Offset, size: raw.Size, digest: raw.Digest})
		cursor = next
	}
	if cursor != input.Size {
		return Artifact{}, ErrInvalidPlan
	}
	return Artifact{id: input.ID, digest: input.Digest, size: input.Size, expandedBytes: input.ExpandedBytes,
		expandedDigest: input.ExpandedDigest, targetKind: input.TargetKind, targetStorageID: input.TargetStorageID,
		targetAuthorityDigest: input.TargetAuthorityDigest, sources: sources, chunks: chunks}, nil
}

func validSource(value string) bool {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n\t ?#@%") {
		return false
	}
	if strings.HasPrefix(value, "bundle://") {
		path := strings.TrimPrefix(value, "bundle://")
		return validPath(path)
	}
	if !strings.HasPrefix(value, "https://") {
		return false
	}
	remainder := strings.TrimPrefix(value, "https://")
	slash := strings.IndexByte(remainder, '/')
	if slash <= 0 || slash == len(remainder)-1 {
		return false
	}
	host, path := remainder[:slash], remainder[slash+1:]
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, ":") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	for _, character := range host {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return validPath(path)
}

func validPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func checkedAdd(left uint64, right uint64) (uint64, error) {
	if left > maximumSafeBytes || right > maximumSafeBytes || right > maximumSafeBytes-left {
		return 0, ErrInvalidPlan
	}
	return left + right, nil
}
