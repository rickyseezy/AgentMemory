package releaseinventory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// ErrExpandedTargetInvalid rejects missing, unknown, inferred, or
// contradictory release-signed materialization semantics.
var ErrExpandedTargetInvalid = errors.New("release expanded target authority is invalid")

// ExpandedTargetKind is the closed release-signed representation vocabulary.
type ExpandedTargetKind string

// ExpandedTargetComposeBundle publishes the signed Compose YAML bytes
// byte-for-byte beneath the installation's parent-bound release directory.
const ExpandedTargetComposeBundle ExpandedTargetKind = "compose-bundle"

// ReleaseExpandedTargetInput is the publisher-signed target projection.
type ReleaseExpandedTargetInput struct {
	Kind      ExpandedTargetKind
	StorageID string
	Digest    Digest
	Bytes     uint64
}

// ReleaseExpandedTarget is installation-agnostic publisher authority. The
// manifest signature covers every field; authorityDigest gives downstream
// plans one compact exact selection binding.
type ReleaseExpandedTarget struct {
	kind            ExpandedTargetKind
	storageID       string
	sourceDigest    Digest
	sourceBytes     uint64
	digest          Digest
	bytes           uint64
	authorityDigest Digest
}

// NewReleaseExpandedTarget constructs the only currently supported exact
// representation. Compose YAML is a raw immutable publication, not a tar or
// inferred archive, so its target content digest equals its source CAS digest.
func NewReleaseExpandedTarget(
	sourceDigest Digest,
	sourceBytes uint64,
	input ReleaseExpandedTargetInput,
) (ReleaseExpandedTarget, error) {
	if input.Kind != ExpandedTargetComposeBundle || sourceDigest.IsZero() || sourceBytes == 0 ||
		sourceBytes > maxSafeJSONInteger || input.Digest.IsZero() || !input.Digest.Equal(sourceDigest) ||
		input.Bytes != sourceBytes || input.Bytes > maxSafeJSONInteger ||
		!validExpandedTargetStorageID(input.StorageID) {
		return ReleaseExpandedTarget{}, ErrExpandedTargetInvalid
	}
	authorityDigest := expandedTargetAuthorityDigest(
		input.Kind, input.StorageID, sourceDigest, sourceBytes, input.Digest, input.Bytes,
	)
	value := ReleaseExpandedTarget{
		kind: input.Kind, storageID: input.StorageID, sourceDigest: sourceDigest,
		sourceBytes: sourceBytes, digest: input.Digest, bytes: input.Bytes,
		authorityDigest: authorityDigest,
	}
	if !value.Valid() {
		return ReleaseExpandedTarget{}, ErrExpandedTargetInvalid
	}
	return value, nil
}

// Kind returns the closed representation kind.
func (t ReleaseExpandedTarget) Kind() ExpandedTargetKind { return t.kind }

// StorageID returns the normalized release-relative target path.
func (t ReleaseExpandedTarget) StorageID() string { return t.storageID }

// SourceDigest returns the signed CAS input digest.
func (t ReleaseExpandedTarget) SourceDigest() Digest { return t.sourceDigest }

// SourceBytes returns the exact signed CAS input size.
func (t ReleaseExpandedTarget) SourceBytes() uint64 { return t.sourceBytes }

// Digest returns the exact published target content digest.
func (t ReleaseExpandedTarget) Digest() Digest { return t.digest }

// Bytes returns the signed maximum physical allocation for the target.
func (t ReleaseExpandedTarget) Bytes() uint64 { return t.bytes }

// AuthorityDigest returns the canonical signed target-selection digest.
func (t ReleaseExpandedTarget) AuthorityDigest() Digest { return t.authorityDigest }

// Valid reports whether the complete authority recomputes exactly.
func (t ReleaseExpandedTarget) Valid() bool {
	return t.kind == ExpandedTargetComposeBundle && validExpandedTargetStorageID(t.storageID) &&
		!t.sourceDigest.IsZero() && t.sourceBytes > 0 && t.sourceBytes <= maxSafeJSONInteger &&
		t.digest.Equal(t.sourceDigest) && t.bytes == t.sourceBytes && t.bytes <= maxSafeJSONInteger &&
		t.authorityDigest.Equal(expandedTargetAuthorityDigest(
			t.kind, t.storageID, t.sourceDigest, t.sourceBytes, t.digest, t.bytes,
		))
}

func validExpandedTargetStorageID(value string) bool {
	return len(value) <= 256 && validSourcePath(value) &&
		strings.HasPrefix(value, "compose/") &&
		(strings.HasSuffix(value, ".yaml") || strings.HasSuffix(value, ".yml"))
}

func expandedTargetAuthorityDigest(
	kind ExpandedTargetKind,
	storageID string,
	sourceDigest Digest,
	sourceBytes uint64,
	targetDigest Digest,
	targetBytes uint64,
) Digest {
	fields := []string{
		"agentmemory-release-expanded-target-v1",
		string(kind), storageID, sourceDigest.Hex(), strconv.FormatUint(sourceBytes, 10),
		targetDigest.Hex(), strconv.FormatUint(targetBytes, 10),
	}
	var canonical bytes.Buffer
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		canonical.Write(length[:])
		canonical.WriteString(field)
	}
	return DigestBytes(canonical.Bytes())
}
