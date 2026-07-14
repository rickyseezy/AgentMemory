package runtimecatalogapp

import (
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// Request binds catalog verification to the digest authorized by the signed AgentMemory release.
type Request struct {
	SignedManifest         runtimecatalog.SignedManifest
	ExpectedManifestDigest runtimecatalog.Digest
	SourceMode             runtimecatalog.SourceMode
	OnlineSource           runtimecatalog.SourceLocation
}

// CatalogAnchor is the HMAC-protected monotonic catalog acceptance state.
type CatalogAnchor struct {
	catalogID      string
	sequence       uint64
	manifestDigest runtimecatalog.Digest
}

// NewCatalogAnchor validates persisted anti-rollback state.
func NewCatalogAnchor(
	catalogID string,
	sequence uint64,
	manifestDigest runtimecatalog.Digest,
) (CatalogAnchor, error) {
	if !validAnchorID(catalogID) || sequence == 0 || manifestDigest.IsZero() {
		return CatalogAnchor{}, errors.New("runtime catalog anchor is invalid")
	}
	return CatalogAnchor{
		catalogID: catalogID, sequence: sequence, manifestDigest: manifestDigest,
	}, nil
}

// CatalogID returns the anchor namespace.
func (a CatalogAnchor) CatalogID() string { return a.catalogID }

// Sequence returns the monotonic accepted sequence.
func (a CatalogAnchor) Sequence() uint64 { return a.sequence }

// ManifestDigest returns the exact accepted canonical digest.
func (a CatalogAnchor) ManifestDigest() runtimecatalog.Digest { return a.manifestDigest }

func (a CatalogAnchor) valid() bool {
	_, err := NewCatalogAnchor(a.catalogID, a.sequence, a.manifestDigest)
	return err == nil
}

func validAnchorID(value string) bool {
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

// VerifiedCatalog is execution input only after signature, platform, source,
// native publisher policy, support window, release binding, and CAS gates pass.
type VerifiedCatalog struct {
	manifest        runtimecatalog.Manifest
	verifiedAt      time.Time
	sourceMode      runtimecatalog.SourceMode
	onlineSource    *runtimecatalog.SourceLocation
	alreadyAccepted bool
}

func newVerifiedCatalog(
	manifest runtimecatalog.Manifest,
	verifiedAt time.Time,
	sourceMode runtimecatalog.SourceMode,
	onlineSource *runtimecatalog.SourceLocation,
	alreadyAccepted bool,
) VerifiedCatalog {
	var sourceCopy *runtimecatalog.SourceLocation
	if onlineSource != nil {
		copied := *onlineSource
		sourceCopy = &copied
	}
	return VerifiedCatalog{
		manifest: manifest, verifiedAt: verifiedAt.UTC(), sourceMode: sourceMode,
		onlineSource: sourceCopy, alreadyAccepted: alreadyAccepted,
	}
}

// CatalogID returns the verified catalog namespace.
func (c VerifiedCatalog) CatalogID() string { return c.manifest.CatalogID() }

// Sequence returns the accepted monotonic sequence.
func (c VerifiedCatalog) Sequence() uint64 { return c.manifest.CatalogSequence() }

// ManifestDigest returns the exact release-bound canonical digest.
func (c VerifiedCatalog) ManifestDigest() runtimecatalog.Digest { return c.manifest.Digest() }

// Manifest returns immutable verified execution policy.
func (c VerifiedCatalog) Manifest() runtimecatalog.Manifest { return c.manifest }

// VerifiedAt returns trusted UTC verification time.
func (c VerifiedCatalog) VerifiedAt() time.Time { return c.verifiedAt }

// SourceMode returns the verified acquisition mode.
func (c VerifiedCatalog) SourceMode() runtimecatalog.SourceMode { return c.sourceMode }

// OnlineSource returns a copy of the verified official online source, if any.
func (c VerifiedCatalog) OnlineSource() *runtimecatalog.SourceLocation {
	if c.onlineSource == nil {
		return nil
	}
	sourceCopy := *c.onlineSource
	return &sourceCopy
}

// AlreadyAccepted reports exact idempotent verification of the current anchor.
func (c VerifiedCatalog) AlreadyAccepted() bool { return c.alreadyAccepted }
