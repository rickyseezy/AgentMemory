package bootstrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// AnchoredJournal composes an authenticated journal with an independent,
// monotonic rollback anchor. The required production order is:
//
//	caller-held installation lock -> AnchoredJournal -> authenticated journal
//	                                      -> protected rollback-anchor store
//
// The caller-held lock is mandatory because separate decorator values cannot
// coordinate processes. The local mutex prevents interleaving on one value.
type AnchoredJournal struct {
	inner       journalport.Journal
	anchors     bootstrapport.RollbackAnchorStore
	keyRef      install.BootstrapKeyRef
	operationID install.OperationID
	owner       install.OwnerBinding
	mu          sync.Mutex
}

var _ journalport.Journal = (*AnchoredJournal)(nil)

// NewAnchoredJournal binds one journal to one operation, owner, protected key,
// and rollback store. Production providers must return this decorator rather
// than exposing the underlying journal directly.
func NewAnchoredJournal(
	inner journalport.Journal,
	anchors bootstrapport.RollbackAnchorStore,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (*AnchoredJournal, error) {
	if nilDependency(inner) || nilDependency(anchors) || keyRef.IsZero() || operationID.IsZero() || owner.IsZero() {
		return nil, journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"configure rollback protection",
			errors.New("journal, anchor store, key reference, operation, and owner are required"),
		)
	}
	return &AnchoredJournal{
		inner:       inner,
		anchors:     anchors,
		keyRef:      keyRef,
		operationID: operationID,
		owner:       owner,
	}, nil
}

// Append authenticates and reconciles the current pair before updating the
// journal first and its anchor second. A crash between those writes leaves the
// only recoverable mismatch: an authenticated journal exactly one revision
// ahead of its anchor.
func (j *AnchoredJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	if err := j.validateNextSnapshot(expectedPreviousRevision, snapshot); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	current, err := j.loadAndReconcile(ctx)
	switch {
	case err == nil:
		if current.Revision != expectedPreviousRevision {
			return journalport.NewError(
				journalport.ErrorConflict,
				"append anchored journal",
				fmt.Errorf("expected revision %d, found %d", expectedPreviousRevision, current.Revision),
			)
		}
	case errors.Is(err, journalport.ErrNotFound):
		if expectedPreviousRevision != 0 {
			return journalport.NewError(
				journalport.ErrorConflict,
				"append anchored journal",
				errors.New("journal does not contain the expected predecessor"),
			)
		}
	default:
		return err
	}

	if err := j.inner.Append(ctx, expectedPreviousRevision, snapshot); err != nil {
		// Do not guess whether a failed append committed. A later LoadLatest or
		// ConfirmDurable authenticates the journal and repairs only a one-step
		// journal-ahead crash window.
		return err
	}
	return j.advanceToSnapshot(ctx, expectedPreviousRevision, snapshot)
}

// LoadLatest rejects anchor-ahead rollback and repairs only the journal-ahead
// by one state produced by the documented write order.
func (j *AnchoredJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.loadAndReconcile(ctx)
}

// ConfirmDurable confirms the exact journal revision only after reconciling
// its protected anchor, then verifies the anchor remains exact.
func (j *AnchoredJournal) ConfirmDurable(ctx context.Context, operationID string, revision uint64) error {
	if operationID != j.operationID.String() || revision == 0 {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"confirm anchored journal",
			errors.New("bound operation and positive revision are required"),
		)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	snapshot, err := j.loadAndReconcile(ctx)
	if err != nil {
		return err
	}
	if snapshot.OperationID != operationID || snapshot.Revision != revision {
		return journalport.NewError(
			journalport.ErrorConflict,
			"confirm anchored journal",
			errors.New("journal revision changed before durability confirmation"),
		)
	}
	if err := j.inner.ConfirmDurable(ctx, operationID, revision); err != nil {
		return err
	}
	return j.requireExactAnchor(ctx, snapshot)
}

func (j *AnchoredJournal) validateNextSnapshot(
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	if expectedPreviousRevision == math.MaxUint64 || snapshot.OperationID != j.operationID.String() ||
		snapshot.Revision != expectedPreviousRevision+1 || snapshot.CapturedAt.IsZero() || !json.Valid(snapshot.Payload) {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"append anchored journal",
			errors.New("snapshot does not match the bound operation or next revision"),
		)
	}
	return nil
}

func (j *AnchoredJournal) loadAndReconcile(ctx context.Context) (journalport.Snapshot, error) {
	snapshot, err := j.inner.LoadLatest(ctx)
	if err != nil {
		if !errors.Is(err, journalport.ErrNotFound) {
			return journalport.Snapshot{}, err
		}
		_, anchorError := j.anchors.Load(ctx, j.keyRef, j.operationID, j.owner)
		switch {
		case errors.Is(anchorError, bootstrapport.ErrNotFound):
			return journalport.Snapshot{}, err
		case anchorError == nil:
			return journalport.Snapshot{}, rollbackCorrupt("rollback anchor exists without its journal", nil)
		default:
			return journalport.Snapshot{}, mapAnchorError("load anchor without journal", anchorError)
		}
	}
	if snapshot.OperationID != j.operationID.String() || snapshot.Revision == 0 ||
		snapshot.CapturedAt.IsZero() || !json.Valid(snapshot.Payload) {
		return journalport.Snapshot{}, rollbackCorrupt("journal snapshot violates its rollback binding", nil)
	}
	if err := j.reconcileSnapshot(ctx, snapshot); err != nil {
		return journalport.Snapshot{}, err
	}
	return snapshot, nil
}

func (j *AnchoredJournal) reconcileSnapshot(ctx context.Context, snapshot journalport.Snapshot) error {
	expected, err := j.anchorForSnapshot(snapshot)
	if err != nil {
		return err
	}
	current, err := j.anchors.Load(ctx, j.keyRef, j.operationID, j.owner)
	if errors.Is(err, bootstrapport.ErrNotFound) {
		if snapshot.Revision != 1 {
			return rollbackCorrupt("rollback anchor is missing beyond the one-step crash window", nil)
		}
		return j.recoverAnchor(ctx, 0, expected, snapshot)
	}
	if err != nil {
		return mapAnchorError("load rollback anchor", err)
	}
	if current.OperationID() != j.operationID || !current.Owner().Equal(j.owner) {
		return rollbackCorrupt("rollback anchor identity changed", nil)
	}
	switch {
	case current.Sequence() == snapshot.Revision:
		if !current.StateDigest().Equal(expected.StateDigest()) {
			return rollbackCorrupt("journal state differs at the anchored sequence", nil)
		}
		if err := j.anchors.ConfirmDurable(ctx, j.keyRef, expected); err != nil {
			return mapAnchorError("confirm rollback anchor", err)
		}
		return nil
	case current.Sequence() < math.MaxUint64 && current.Sequence()+1 == snapshot.Revision:
		return j.recoverAnchor(ctx, current.Sequence(), expected, snapshot)
	default:
		return rollbackCorrupt("journal and rollback anchor sequences are inconsistent", nil)
	}
}

func (j *AnchoredJournal) recoverAnchor(
	ctx context.Context,
	expectedSequence uint64,
	next install.RollbackAnchor,
	snapshot journalport.Snapshot,
) error {
	if err := j.inner.ConfirmDurable(ctx, snapshot.OperationID, snapshot.Revision); err != nil {
		return err
	}
	return j.advanceAnchor(ctx, expectedSequence, next)
}

func (j *AnchoredJournal) advanceToSnapshot(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	anchor, err := j.anchorForSnapshot(snapshot)
	if err != nil {
		return err
	}
	return j.advanceAnchor(ctx, expectedPreviousRevision, anchor)
}

func (j *AnchoredJournal) advanceAnchor(
	ctx context.Context,
	expectedSequence uint64,
	next install.RollbackAnchor,
) error {
	err := j.anchors.Advance(ctx, j.keyRef, expectedSequence, next)
	if err == nil {
		return nil
	}
	// Advance may report an ambiguous post-commit error. Re-reading accepts
	// only the exact intended anchor; every other outcome preserves the error.
	observed, loadError := j.anchors.Load(ctx, j.keyRef, j.operationID, j.owner)
	if loadError == nil && exactAnchor(observed, next) {
		if confirmError := j.anchors.ConfirmDurable(ctx, j.keyRef, next); confirmError != nil {
			return mapAnchorError("confirm ambiguous rollback anchor", confirmError)
		}
		return nil
	}
	return mapAnchorError("advance rollback anchor", err)
}

func (j *AnchoredJournal) requireExactAnchor(ctx context.Context, snapshot journalport.Snapshot) error {
	expected, err := j.anchorForSnapshot(snapshot)
	if err != nil {
		return err
	}
	observed, err := j.anchors.Load(ctx, j.keyRef, j.operationID, j.owner)
	if err != nil {
		return mapAnchorError("confirm rollback anchor", err)
	}
	if !exactAnchor(observed, expected) {
		return rollbackCorrupt("rollback anchor changed during durability confirmation", nil)
	}
	if err := j.anchors.ConfirmDurable(ctx, j.keyRef, expected); err != nil {
		return mapAnchorError("confirm rollback anchor", err)
	}
	return nil
}

func (j *AnchoredJournal) anchorForSnapshot(snapshot journalport.Snapshot) (install.RollbackAnchor, error) {
	digest, err := journalSnapshotDigest(snapshot)
	if err != nil {
		return install.RollbackAnchor{}, journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"digest rollback state",
			err,
		)
	}
	anchor, err := install.NewRollbackAnchor(j.operationID, j.owner, snapshot.Revision, digest)
	if err != nil {
		return install.RollbackAnchor{}, journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"bind rollback state",
			err,
		)
	}
	return anchor, nil
}

func journalSnapshotDigest(snapshot journalport.Snapshot) (install.Digest, error) {
	if snapshot.OperationID == "" || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() || !json.Valid(snapshot.Payload) {
		return install.Digest{}, errors.New("journal snapshot is not canonicalizable")
	}
	var compactPayload bytes.Buffer
	if err := json.Compact(&compactPayload, snapshot.Payload); err != nil {
		return install.Digest{}, err
	}
	canonical := make([]byte, 0, len(snapshot.OperationID)+compactPayload.Len()+96)
	canonical = append(canonical, "agentmemory:rollback-journal-state:v1\x00"...)
	canonical = appendRollbackField(canonical, []byte(snapshot.OperationID))
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, snapshot.Revision)
	canonical = append(canonical, revision...)
	canonical = appendRollbackField(canonical, []byte(snapshot.CapturedAt.UTC().Format(timeFormatRFC3339Nano)))
	canonical = appendRollbackField(canonical, compactPayload.Bytes())
	return install.DigestBytes(canonical), nil
}

const timeFormatRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

func appendRollbackField(destination, value []byte) []byte {
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(value)))
	destination = append(destination, length...)
	return append(destination, value...)
}

func exactAnchor(observed, expected install.RollbackAnchor) bool {
	return observed.OperationID() == expected.OperationID() && observed.Owner().Equal(expected.Owner()) &&
		observed.Sequence() == expected.Sequence() && observed.StateDigest().Equal(expected.StateDigest())
}

func mapAnchorError(operation string, err error) error {
	switch {
	case errors.Is(err, bootstrapport.ErrIntegrity):
		return rollbackCorrupt(operation, err)
	case errors.Is(err, bootstrapport.ErrConflict):
		return journalport.NewError(journalport.ErrorConflict, operation, err)
	case errors.Is(err, bootstrapport.ErrNotFound):
		return journalport.NewError(journalport.ErrorCorrupt, operation, err)
	default:
		return journalport.NewError(journalport.ErrorIO, operation, err)
	}
}

func rollbackCorrupt(message string, cause error) error {
	if cause == nil {
		cause = errors.New(message)
	} else {
		cause = fmt.Errorf("%s: %w", message, cause)
	}
	return journalport.NewError(journalport.ErrorCorrupt, "verify rollback protection", cause)
}
