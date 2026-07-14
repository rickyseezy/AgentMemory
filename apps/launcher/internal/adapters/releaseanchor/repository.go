// Package releaseanchor persists the accepted release high-water mark through
// the same authenticated, rollback-protected journal boundary as installation
// state. The composition root must supply an AnchoredJournal; this adapter does
// not accept an ordinary file or weaken that trust boundary.
package releaseanchor

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
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	// This fixed UUIDv7-shaped authority is a purpose-separated journal
	// namespace, not a user installation operation. Using the same validated
	// locator/key/rollback boundary prevents the release anchor from falling
	// back to an ordinary file.
	releaseAnchorOperationID = "019f5f30-0000-7000-8000-000000000001"
	releaseAnchorSchema      = uint16(1)
	maximumSafeJSONInteger   = uint64(1<<53 - 1)
	maximumReleaseChannels   = 5
)

// Repository implements optimistic release-anchor persistence. The journal's
// expected revision is the compare-and-swap token; release sequence is the
// independently authenticated product anti-rollback value.
type Repository struct {
	journal *bootstrapadapter.AnchoredJournal
	clock   releaseverify.Clock
}

type anchoredJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// NewRepositoryFromProvider resolves the fixed release-anchor authority from
// a platform-protected journal provider and rejects any undecorated journal.
func NewRepositoryFromProvider(
	ctx context.Context,
	provider anchoredJournalProvider,
	clock releaseverify.Clock,
) (*Repository, error) {
	if ctx == nil || nilProvider(provider) || nilClock(clock) {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	operationID, err := install.NewOperationID(releaseAnchorOperationID)
	if err != nil {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	journal, err := provider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, mapMutationError(err)
	}
	anchored, ok := journal.(*bootstrapadapter.AnchoredJournal)
	if !ok || anchored == nil {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	return NewRepository(anchored, clock)
}

// NewRepository accepts only the concrete rollback-protected journal
// decorator. An undecorated Journal could authenticate bytes yet still permit
// whole-file rollback, so it is intentionally not representable here.
func NewRepository(
	journal *bootstrapadapter.AnchoredJournal,
	clock releaseverify.Clock,
) (*Repository, error) {
	if journal == nil || nilClock(clock) {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	return &Repository{journal: journal, clock: clock}, nil
}

// LoadReleaseAnchor re-authenticates the journal and its protected rollback
// anchor before decoding a canonical, closed snapshot.
func (r *Repository) LoadReleaseAnchor(
	ctx context.Context,
	channel releaseinventory.ReleaseChannel,
) (releaseverify.ReleaseAnchor, error) {
	if ctx == nil || r == nil || r.journal == nil || nilClock(r.clock) || !channel.Valid() {
		return releaseverify.ReleaseAnchor{}, releaseverify.ErrReleaseAnchorIntegrity
	}
	snapshot, err := r.journal.LoadLatest(ctx)
	if err != nil {
		return releaseverify.ReleaseAnchor{}, mapLoadError(err)
	}
	anchors, err := decodeSnapshot(snapshot)
	if err != nil {
		return releaseverify.ReleaseAnchor{}, err
	}
	anchor, found := anchors[channel]
	if !found {
		return releaseverify.ReleaseAnchor{}, releaseverify.ErrReleaseAnchorNotFound
	}
	return anchor, nil
}

// CompareAndSwapReleaseAnchor persists exactly one monotonic successor. A
// missing expected anchor authorizes only the first write; a non-nil expected
// anchor must exactly equal the currently authenticated value.
func (r *Repository) CompareAndSwapReleaseAnchor(
	ctx context.Context,
	expected *releaseverify.ReleaseAnchor,
	next releaseverify.ReleaseAnchor,
) error {
	if ctx == nil || r == nil || r.journal == nil || nilClock(r.clock) || !validAnchor(next) ||
		expected != nil && (!validAnchor(*expected) || expected.Channel() != next.Channel() ||
			next.Sequence() <= expected.Sequence()) {
		return releaseverify.ErrReleaseAnchorIntegrity
	}

	previousRevision := uint64(0)
	anchors := make(anchorSet, maximumReleaseChannels)
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

	current, found := anchors[next.Channel()]
	switch {
	case found && expected == nil:
		return releaseverify.ErrReleaseAnchorConflict
	case !found && expected != nil:
		return releaseverify.ErrReleaseAnchorConflict
	case found && !sameAnchor(current, *expected):
		return releaseverify.ErrReleaseAnchorConflict
	}
	anchors[next.Channel()] = next
	payload, err := encodeAnchors(anchors)
	if err != nil || previousRevision == ^uint64(0) {
		return releaseverify.ErrReleaseAnchorIntegrity
	}
	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return releaseverify.ErrDependencyUnavailable
	}
	revision := previousRevision + 1
	if err := r.journal.Append(ctx, previousRevision, installjournal.Snapshot{
		OperationID: releaseAnchorOperationID,
		Revision:    revision,
		CapturedAt:  capturedAt,
		Payload:     payload,
	}); err != nil {
		return mapMutationError(err)
	}
	if err := r.journal.ConfirmDurable(ctx, releaseAnchorOperationID, revision); err != nil {
		return mapMutationError(err)
	}
	return nil
}

type snapshotDocument struct {
	SchemaVersion uint16           `json:"schema_version"`
	Anchors       []anchorDocument `json:"anchors"`
}

type anchorDocument struct {
	Channel        releaseinventory.ReleaseChannel `json:"channel"`
	Sequence       uint64                          `json:"sequence"`
	ManifestDigest string                          `json:"manifest_digest"`
	ReleaseID      string                          `json:"release_id"`
}

type anchorSet map[releaseinventory.ReleaseChannel]releaseverify.ReleaseAnchor

func encodeAnchors(anchors anchorSet) ([]byte, error) {
	if len(anchors) == 0 || len(anchors) > maximumReleaseChannels {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	channels := make([]releaseinventory.ReleaseChannel, 0, len(anchors))
	for channel, anchor := range anchors {
		if channel != anchor.Channel() || !validAnchor(anchor) {
			return nil, releaseverify.ErrReleaseAnchorIntegrity
		}
		channels = append(channels, channel)
	}
	sort.Slice(channels, func(left, right int) bool { return channels[left] < channels[right] })
	document := snapshotDocument{SchemaVersion: releaseAnchorSchema, Anchors: make([]anchorDocument, 0, len(channels))}
	for _, channel := range channels {
		anchor := anchors[channel]
		document.Anchors = append(document.Anchors, anchorDocument{
			Channel: channel, Sequence: anchor.Sequence(),
			ManifestDigest: anchor.ManifestDigest().Hex(), ReleaseID: anchor.ReleaseID(),
		})
	}
	return json.Marshal(document)
}

func decodeSnapshot(snapshot installjournal.Snapshot) (anchorSet, error) {
	if snapshot.OperationID != releaseAnchorOperationID || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() ||
		len(snapshot.Payload) == 0 || len(snapshot.Payload) > 8192 || !json.Valid(snapshot.Payload) {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Payload))
	decoder.DisallowUnknownFields()
	var document snapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, snapshot.Payload) || document.SchemaVersion != releaseAnchorSchema ||
		len(document.Anchors) == 0 || len(document.Anchors) > maximumReleaseChannels {
		return nil, releaseverify.ErrReleaseAnchorIntegrity
	}
	anchors := make(anchorSet, len(document.Anchors))
	previousChannel := releaseinventory.ReleaseChannel("")
	for _, entry := range document.Anchors {
		if !entry.Channel.Valid() || entry.Channel <= previousChannel || entry.Sequence == 0 ||
			entry.Sequence > maximumSafeJSONInteger {
			return nil, releaseverify.ErrReleaseAnchorIntegrity
		}
		digest, parseError := releaseinventory.ParseDigest(entry.ManifestDigest)
		if parseError != nil {
			return nil, releaseverify.ErrReleaseAnchorIntegrity
		}
		anchor, anchorError := releaseverify.NewReleaseAnchor(
			entry.Channel, entry.Sequence, digest, entry.ReleaseID,
		)
		if anchorError != nil {
			return nil, releaseverify.ErrReleaseAnchorIntegrity
		}
		anchors[entry.Channel] = anchor
		previousChannel = entry.Channel
	}
	return anchors, nil
}

func validAnchor(anchor releaseverify.ReleaseAnchor) bool {
	if anchor.Sequence() == 0 || anchor.Sequence() > maximumSafeJSONInteger || anchor.ManifestDigest().IsZero() {
		return false
	}
	restored, err := releaseverify.NewReleaseAnchor(
		anchor.Channel(), anchor.Sequence(), anchor.ManifestDigest(), anchor.ReleaseID(),
	)
	return err == nil && sameAnchor(anchor, restored)
}

func sameAnchor(left, right releaseverify.ReleaseAnchor) bool {
	return left.Channel() == right.Channel() && left.Sequence() == right.Sequence() && left.ReleaseID() == right.ReleaseID() &&
		left.ManifestDigest().Equal(right.ManifestDigest())
}

func nilProvider(provider anchoredJournalProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func mapLoadError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return releaseverify.ErrReleaseAnchorNotFound
	case errors.Is(err, installjournal.ErrCorrupt),
		errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return fmt.Errorf("%w: authenticated state rejected", releaseverify.ErrReleaseAnchorIntegrity)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: protected state unavailable", releaseverify.ErrDependencyUnavailable)
	}
}

func mapMutationError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrConflict):
		return releaseverify.ErrReleaseAnchorConflict
	case errors.Is(err, installjournal.ErrCorrupt),
		errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return fmt.Errorf("%w: authenticated state rejected", releaseverify.ErrReleaseAnchorIntegrity)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: protected state unavailable", releaseverify.ErrDependencyUnavailable)
	}
}

func nilClock(clock releaseverify.Clock) bool {
	if clock == nil {
		return true
	}
	value := reflect.ValueOf(clock)
	//nolint:exhaustive // Non-nilable reflection kinds are intentionally handled by default.
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ releaseverify.AntiRollbackRepository = (*Repository)(nil)
