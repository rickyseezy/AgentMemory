// Package rebootevidence joins the authenticated PF-001 aggregate to freshly
// verified native launcher and journal objects.
package rebootevidence

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

// OperationRepository authenticates the machine-bound, rollback-checked
// operation journal before object hashes are projected.
type OperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
}

// JournalLocator derives a closed path from the operation identifier.
type JournalLocator interface {
	JournalPath(install.OperationID) (string, error)
}

// VerifiedObject is an owner-verified regular file and its content digest.
type VerifiedObject struct {
	Path   string
	Digest install.Digest
}

func (o VerifiedObject) valid() bool { return o.Path != "" && !o.Digest.IsZero() }

// ObjectVerifier owns native no-follow opening, owner/ACL checks, executable
// resolution, and streaming SHA-256 calculation.
type ObjectVerifier interface {
	VerifyLauncher(context.Context) (VerifiedObject, error)
	VerifyJournal(context.Context, string) (VerifiedObject, error)
}

// Resolver implements rebootapp.EvidenceResolver.
type Resolver struct {
	operations OperationRepository
	locator    JournalLocator
	verifier   ObjectVerifier
}

// New rejects every partial or typed-nil adapter composition.
func New(operations OperationRepository, locator JournalLocator, verifier ObjectVerifier) (*Resolver, error) {
	if nilCapability(operations) || nilCapability(locator) || nilCapability(verifier) {
		return nil, rebootapp.ErrIntegrity
	}
	return &Resolver{operations: operations, locator: locator, verifier: verifier}, nil
}

// Resolve verifies the journal aggregate before reading any native object.
func (r *Resolver) Resolve(ctx context.Context, binding rebootapp.Binding) (rebootapp.Evidence, error) {
	if r == nil || ctx == nil || binding.OperationID.IsZero() || binding.PlanDigest.IsZero() ||
		binding.AggregateVersion == 0 || binding.ResumeReceipt.IsZero() {
		return rebootapp.Evidence{}, rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return rebootapp.Evidence{}, err
	}
	operation, err := r.operations.Load(ctx, binding.OperationID)
	if err != nil {
		return rebootapp.Evidence{}, mapBoundary(err)
	}
	if operation == nil || operation.ID() != binding.OperationID ||
		!operation.PlanDigest().Equal(binding.PlanDigest) || operation.AggregateVersion() != binding.AggregateVersion ||
		operation.State() != install.StateRebootPending {
		return rebootapp.Evidence{}, rebootapp.ErrIntegrity
	}
	checkpoint, exists := operation.Snapshot().RebootCheckpoint()
	if !exists || !checkpoint.PlanDigest().Equal(binding.PlanDigest) ||
		!checkpoint.ReceiptDigest().Equal(binding.ResumeReceipt) ||
		checkpoint.Phase() != operation.CurrentPhase() || checkpoint.Attempt() != operation.Attempt() {
		return rebootapp.Evidence{}, rebootapp.ErrIntegrity
	}
	journalPath, err := r.locator.JournalPath(binding.OperationID)
	if err != nil || journalPath == "" {
		return rebootapp.Evidence{}, mapBoundary(err)
	}
	launcher, err := r.verifier.VerifyLauncher(ctx)
	if err != nil {
		return rebootapp.Evidence{}, mapBoundary(err)
	}
	journal, err := r.verifier.VerifyJournal(ctx, journalPath)
	if err != nil {
		return rebootapp.Evidence{}, mapBoundary(err)
	}
	if !launcher.valid() || !journal.valid() || journal.Path != journalPath || launcher.Path == journal.Path {
		return rebootapp.Evidence{}, rebootapp.ErrIntegrity
	}
	return rebootapp.Evidence{Binding: binding, Verification: rebootcontinuationVerification(
		binding.OperationID, launcher, journal,
	)}, nil
}

func rebootcontinuationVerification(
	operationID install.OperationID,
	launcher VerifiedObject,
	journal VerifiedObject,
) rebootcontinuation.Verification {
	return rebootcontinuation.Verification{
		OperationID: operationID, LauncherPath: launcher.Path, LauncherDigest: launcher.Digest,
		JournalPath: journal.Path, JournalDigest: journal.Digest,
	}
}

func mapBoundary(err error) error {
	switch {
	case err == nil:
		return rebootapp.ErrUnavailable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, installapp.ErrOperationIntegrity), errors.Is(err, rebootapp.ErrIntegrity):
		return rebootapp.ErrIntegrity
	default:
		return rebootapp.ErrUnavailable
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Concrete non-nilable capabilities are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ rebootapp.EvidenceResolver = (*Resolver)(nil)
