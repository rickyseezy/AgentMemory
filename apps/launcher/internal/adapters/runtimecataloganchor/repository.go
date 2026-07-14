// Package runtimecataloganchor persists the independently signed runtime
// catalog high-water mark in a rollback-protected launcher journal.
package runtimecataloganchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

const (
	catalogAnchorOperationID = "019f5f30-0000-7000-8000-000000000002"
	catalogAnchorSchema      = uint16(1)
	maximumSafeJSONInteger   = uint64(1<<53 - 1)
	maximumCatalogAnchors    = 64
	maximumSnapshotBytes     = 64 * 1024
)

type anchoredJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// Repository provides optimistic, rollback-protected catalog-anchor storage.
type Repository struct {
	journal *bootstrapadapter.AnchoredJournal
	clock   runtimecatalogapp.Clock
}

// NewRepositoryFromProvider resolves only the fixed catalog authority journal.
func NewRepositoryFromProvider(
	ctx context.Context,
	provider anchoredJournalProvider,
	clock runtimecatalogapp.Clock,
) (*Repository, error) {
	if ctx == nil || nilPort(provider) || nilPort(clock) {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	operationID, err := install.NewOperationID(catalogAnchorOperationID)
	if err != nil {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	journal, err := provider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, mapMutationError(err)
	}
	anchored, ok := journal.(*bootstrapadapter.AnchoredJournal)
	if !ok || anchored == nil {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	return NewRepository(anchored, clock)
}

// NewRepository deliberately accepts only a rollback-protected journal.
func NewRepository(
	journal *bootstrapadapter.AnchoredJournal,
	clock runtimecatalogapp.Clock,
) (*Repository, error) {
	if journal == nil || nilPort(clock) {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	return &Repository{journal: journal, clock: clock}, nil
}

// LoadCatalogAnchor re-authenticates and strictly decodes the requested high-water mark.
func (r *Repository) LoadCatalogAnchor(
	ctx context.Context,
	catalogID string,
) (runtimecatalogapp.CatalogAnchor, error) {
	if ctx == nil || r == nil || r.journal == nil || nilPort(r.clock) || !validCatalogID(catalogID) {
		return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	snapshot, err := r.journal.LoadLatest(ctx)
	if err != nil {
		return runtimecatalogapp.CatalogAnchor{}, mapLoadError(err)
	}
	anchors, err := decodeSnapshot(snapshot)
	if err != nil {
		return runtimecatalogapp.CatalogAnchor{}, err
	}
	anchor, found := anchors[catalogID]
	if !found {
		return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorNotFound
	}
	return anchor, nil
}

// CompareAndSwapCatalogAnchor persists exactly one monotonic successor.
func (r *Repository) CompareAndSwapCatalogAnchor(
	ctx context.Context,
	expected *runtimecatalogapp.CatalogAnchor,
	next runtimecatalogapp.CatalogAnchor,
) error {
	if ctx == nil || r == nil || r.journal == nil || nilPort(r.clock) || !validAnchor(next) ||
		expected != nil && (!validAnchor(*expected) || expected.CatalogID() != next.CatalogID() ||
			next.Sequence() <= expected.Sequence()) {
		return runtimecatalogapp.ErrCatalogAnchorIntegrity
	}

	previousRevision := uint64(0)
	anchors := make(anchorSet, maximumCatalogAnchors)
	snapshot, loadError := r.journal.LoadLatest(ctx)
	switch {
	case errors.Is(loadError, installjournal.ErrNotFound):
	case loadError != nil:
		return mapMutationError(loadError)
	default:
		var decodeError error
		anchors, decodeError = decodeSnapshot(snapshot)
		if decodeError != nil {
			return decodeError
		}
		previousRevision = snapshot.Revision
	}

	current, found := anchors[next.CatalogID()]
	switch {
	case found && expected == nil, !found && expected != nil:
		return runtimecatalogapp.ErrCatalogAnchorConflict
	case found && !sameAnchor(current, *expected):
		return runtimecatalogapp.ErrCatalogAnchorConflict
	}
	anchors[next.CatalogID()] = next
	payload, err := encodeAnchors(anchors)
	if err != nil || previousRevision == ^uint64(0) {
		return runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return runtimecatalogapp.ErrDependencyUnavailable
	}
	revision := previousRevision + 1
	if err := r.journal.Append(ctx, previousRevision, installjournal.Snapshot{
		OperationID: catalogAnchorOperationID,
		Revision:    revision,
		CapturedAt:  capturedAt,
		Payload:     payload,
	}); err != nil {
		return mapMutationError(err)
	}
	if err := r.journal.ConfirmDurable(ctx, catalogAnchorOperationID, revision); err != nil {
		return mapMutationError(err)
	}
	return nil
}

type snapshotDocument struct {
	SchemaVersion uint16           `json:"schema_version"`
	Anchors       []anchorDocument `json:"anchors"`
}

type anchorDocument struct {
	CatalogID      string `json:"catalog_id"`
	Sequence       uint64 `json:"sequence"`
	ManifestDigest string `json:"manifest_digest"`
}

type anchorSet map[string]runtimecatalogapp.CatalogAnchor

func encodeAnchors(anchors anchorSet) ([]byte, error) {
	if len(anchors) == 0 || len(anchors) > maximumCatalogAnchors {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	identifiers := make([]string, 0, len(anchors))
	for identifier, anchor := range anchors {
		if identifier != anchor.CatalogID() || !validAnchor(anchor) {
			return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
		}
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	document := snapshotDocument{SchemaVersion: catalogAnchorSchema, Anchors: make([]anchorDocument, 0, len(identifiers))}
	for _, identifier := range identifiers {
		anchor := anchors[identifier]
		document.Anchors = append(document.Anchors, anchorDocument{
			CatalogID: identifier, Sequence: anchor.Sequence(), ManifestDigest: anchor.ManifestDigest().Hex(),
		})
	}
	return json.Marshal(document)
}

func decodeSnapshot(snapshot installjournal.Snapshot) (anchorSet, error) {
	if snapshot.OperationID != catalogAnchorOperationID || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() ||
		len(snapshot.Payload) == 0 || len(snapshot.Payload) > maximumSnapshotBytes || !json.Valid(snapshot.Payload) {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Payload))
	decoder.DisallowUnknownFields()
	var document snapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, snapshot.Payload) || document.SchemaVersion != catalogAnchorSchema ||
		len(document.Anchors) == 0 || len(document.Anchors) > maximumCatalogAnchors {
		return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
	}
	anchors := make(anchorSet, len(document.Anchors))
	previousID := ""
	for _, entry := range document.Anchors {
		if !validCatalogID(entry.CatalogID) || entry.CatalogID <= previousID || entry.Sequence == 0 ||
			entry.Sequence > maximumSafeJSONInteger {
			return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
		}
		digest, parseError := runtimecatalog.ParseDigest(entry.ManifestDigest)
		if parseError != nil {
			return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
		}
		anchor, anchorError := runtimecatalogapp.NewCatalogAnchor(entry.CatalogID, entry.Sequence, digest)
		if anchorError != nil {
			return nil, runtimecatalogapp.ErrCatalogAnchorIntegrity
		}
		anchors[entry.CatalogID] = anchor
		previousID = entry.CatalogID
	}
	return anchors, nil
}

func validAnchor(anchor runtimecatalogapp.CatalogAnchor) bool {
	if anchor.Sequence() == 0 || anchor.Sequence() > maximumSafeJSONInteger || anchor.ManifestDigest().IsZero() {
		return false
	}
	restored, err := runtimecatalogapp.NewCatalogAnchor(anchor.CatalogID(), anchor.Sequence(), anchor.ManifestDigest())
	return err == nil && sameAnchor(anchor, restored)
}

func sameAnchor(left, right runtimecatalogapp.CatalogAnchor) bool {
	return left.CatalogID() == right.CatalogID() && left.Sequence() == right.Sequence() &&
		left.ManifestDigest().Equal(right.ManifestDigest())
}

func validCatalogID(value string) bool {
	_, err := runtimecatalogapp.NewCatalogAnchor(value, 1, runtimecatalog.DigestBytes([]byte("catalog-id-validation")))
	return err == nil
}

func mapLoadError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return runtimecatalogapp.ErrCatalogAnchorNotFound
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return fmt.Errorf("%w: authenticated state rejected", runtimecatalogapp.ErrCatalogAnchorIntegrity)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: protected state unavailable", runtimecatalogapp.ErrDependencyUnavailable)
	}
}

func mapMutationError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrConflict):
		return runtimecatalogapp.ErrCatalogAnchorConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return fmt.Errorf("%w: authenticated state rejected", runtimecatalogapp.ErrCatalogAnchorIntegrity)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: protected state unavailable", runtimecatalogapp.ErrDependencyUnavailable)
	}
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Array, reflect.Bool, reflect.Complex128, reflect.Complex64, reflect.Float32,
		reflect.Float64, reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int8,
		reflect.Invalid, reflect.String, reflect.Struct, reflect.Uint, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uint8, reflect.Uintptr, reflect.UnsafePointer:
		return false
	}
	return false
}

var _ runtimecatalogapp.AntiRollbackRepository = (*Repository)(nil)
