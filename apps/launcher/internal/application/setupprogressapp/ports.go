package setupprogressapp

import (
	"context"
	"errors"
)

var (
	// ErrAuthorityConflict reports a durable concurrent decision or CAS race.
	ErrAuthorityConflict = errors.New("setup progress authority conflict")
	// ErrAuthorityIntegrity reports contradictory durable binding or sequence state.
	ErrAuthorityIntegrity = errors.New("setup progress authority integrity violation")
)

// SnapshotAuthority is the only source of current and future setup state. It
// must durably enforce exact binding and strictly monotonic snapshot sequence.
type SnapshotAuthority interface {
	CurrentSnapshot(context.Context, Binding) (Snapshot, error)
	WaitSnapshotAfter(context.Context, Binding, uint64) (Snapshot, error)
}

// DecisionAuthority durably and idempotently applies the closed decision. The
// same UUID must always return the same receipt; competing decisions must CAS.
type DecisionAuthority interface {
	ApplyDecision(context.Context, DecisionCommand) (DecisionReceipt, error)
}
