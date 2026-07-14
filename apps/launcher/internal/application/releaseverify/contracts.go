package releaseverify

import (
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ReleaseAnchor is the HMAC-protected anti-rollback high-water mark persisted
// by an outbound adapter.
type ReleaseAnchor struct {
	channel        releaseinventory.ReleaseChannel
	sequence       uint64
	manifestDigest releaseinventory.Digest
	releaseID      string
}

// NewReleaseAnchor creates a validated accepted-release high-water mark.
func NewReleaseAnchor(
	channel releaseinventory.ReleaseChannel,
	sequence uint64,
	manifestDigest releaseinventory.Digest,
	releaseID string,
) (ReleaseAnchor, error) {
	if !channel.Valid() || sequence == 0 || manifestDigest.IsZero() || !validReleaseAnchorID(releaseID) {
		return ReleaseAnchor{}, errors.New("release anchor is invalid")
	}
	return ReleaseAnchor{
		channel: channel, sequence: sequence, manifestDigest: manifestDigest, releaseID: releaseID,
	}, nil
}

func (a ReleaseAnchor) valid() bool {
	_, err := NewReleaseAnchor(a.channel, a.sequence, a.manifestDigest, a.releaseID)
	return err == nil
}

func validReleaseAnchorID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

// Channel returns the release-channel anti-rollback namespace.
func (a ReleaseAnchor) Channel() releaseinventory.ReleaseChannel { return a.channel }

// Sequence returns the accepted monotonic sequence.
func (a ReleaseAnchor) Sequence() uint64 { return a.sequence }

// ManifestDigest returns the exact accepted canonical manifest digest.
func (a ReleaseAnchor) ManifestDigest() releaseinventory.Digest { return a.manifestDigest }

// ReleaseID returns the accepted release identity.
func (a ReleaseAnchor) ReleaseID() string { return a.releaseID }

// VerifiedResource is safe inventory evidence. It deliberately excludes host
// paths, credentials, process output, and acquisition headers.
type VerifiedResource struct {
	id        string
	kind      releaseinventory.ResourceKind
	purpose   releaseinventory.ResourcePurpose
	mediaType string
	digest    releaseinventory.Digest
	size      uint64
	platform  releaseinventory.Platform
	sourceRef string
}

// ID returns the verified resource identifier.
func (r VerifiedResource) ID() string { return r.id }

// Kind returns the verified resource kind.
func (r VerifiedResource) Kind() releaseinventory.ResourceKind { return r.kind }

// Purpose returns the independently verified execution purpose. Callers must
// authorize both Kind and Purpose before using a resource.
func (r VerifiedResource) Purpose() releaseinventory.ResourcePurpose { return r.purpose }

// MediaType returns the independently verified execution format.
func (r VerifiedResource) MediaType() string { return r.mediaType }

// Digest returns the verified SHA-256 digest.
func (r VerifiedResource) Digest() releaseinventory.Digest { return r.digest }

// Size returns the verified byte length.
func (r VerifiedResource) Size() uint64 { return r.size }

// Platform returns the verified exact target or platform-independent value.
func (r VerifiedResource) Platform() releaseinventory.Platform { return r.platform }

// SourceRef returns the exact digest-pinned source selected from the signed
// release inventory. It is acquisition metadata and never replaces Digest.
func (r VerifiedResource) SourceRef() string { return r.sourceRef }

// Authorizes reports whether a descriptor from the exact signed manifest is
// the same closed resource that passed every release verification gate. It
// lets downstream adapters recover non-projected manifest metadata without
// turning a hand-built Resource into verified authority.
func (r VerifiedResource) Authorizes(candidate releaseinventory.Resource) bool {
	return r.id != "" && candidate.ID() == r.id && candidate.Kind() == r.kind &&
		candidate.Purpose() == r.purpose && candidate.MediaType() == r.mediaType &&
		candidate.Digest().Equal(r.digest) && candidate.Size() == r.size &&
		candidate.Platform() == r.platform && candidate.SourceRef() == r.sourceRef
}

// VerifiedInventory is emitted only after every selected subject and evidence
// resource passes the closed release policy and the anchor CAS succeeds.
type VerifiedInventory struct {
	releaseID       string
	manifestDigest  releaseinventory.Digest
	sequence        uint64
	platform        releaseinventory.Platform
	verifiedAt      time.Time
	alreadyAccepted bool
	resources       []VerifiedResource
}

func newVerifiedInventory(
	manifest releaseinventory.Manifest,
	platform releaseinventory.Platform,
	verifiedAt time.Time,
	alreadyAccepted bool,
	resources []releaseinventory.Resource,
) VerifiedInventory {
	verified := make([]VerifiedResource, 0, len(resources))
	for _, resource := range resources {
		verified = append(verified, VerifiedResource{
			id:        resource.ID(),
			kind:      resource.Kind(),
			purpose:   resource.Purpose(),
			mediaType: resource.MediaType(),
			digest:    resource.Digest(),
			size:      resource.Size(),
			platform:  resource.Platform(),
			sourceRef: resource.SourceRef(),
		})
	}
	return VerifiedInventory{
		releaseID:       manifest.ReleaseID(),
		manifestDigest:  manifest.Digest(),
		sequence:        manifest.Sequence(),
		platform:        platform,
		verifiedAt:      verifiedAt.UTC(),
		alreadyAccepted: alreadyAccepted,
		resources:       verified,
	}
}

// ReleaseID returns the verified release identity.
func (i VerifiedInventory) ReleaseID() string { return i.releaseID }

// ManifestDigest returns the canonical signed manifest digest.
func (i VerifiedInventory) ManifestDigest() releaseinventory.Digest { return i.manifestDigest }

// Sequence returns the verified anti-rollback sequence.
func (i VerifiedInventory) Sequence() uint64 { return i.sequence }

// Platform returns the exact platform selected from the manifest.
func (i VerifiedInventory) Platform() releaseinventory.Platform { return i.platform }

// VerifiedAt returns the UTC policy-verification time.
func (i VerifiedInventory) VerifiedAt() time.Time { return i.verifiedAt }

// AlreadyAccepted reports an idempotent re-verification of the same anchor.
func (i VerifiedInventory) AlreadyAccepted() bool { return i.alreadyAccepted }

// Resources returns a copy of the closed verified inventory.
func (i VerifiedInventory) Resources() []VerifiedResource {
	return append([]VerifiedResource(nil), i.resources...)
}

// Resource selects one exact member of the closed, fully verified target
// inventory. A caller cannot manufacture VerifiedResource values because all
// authority-bearing fields are private and this inventory is emitted only by
// Application.Verify after every release gate succeeds.
func (i VerifiedInventory) Resource(id string) (VerifiedResource, bool) {
	for _, resource := range i.resources {
		if resource.id == id {
			return resource, true
		}
	}
	return VerifiedResource{}, false
}
