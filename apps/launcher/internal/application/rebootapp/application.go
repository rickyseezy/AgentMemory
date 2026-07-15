// Package rebootapp orchestrates the PF-001 reboot/login continuation without
// importing host filesystem, process, registry, or service-manager behavior.
package rebootapp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

var (
	// ErrIntegrity means a binding, protected object, or persisted record could
	// not be authenticated exactly.
	ErrIntegrity = errors.New("reboot continuation integrity violation")
	// ErrConflict means a different continuation already owns the operation.
	ErrConflict = errors.New("reboot continuation conflict")
	// ErrUnavailable sanitizes a platform or persistence boundary failure.
	ErrUnavailable = errors.New("reboot continuation unavailable")
	// ErrRecordNotFound is the repository's closed absence result.
	ErrRecordNotFound = errors.New("reboot continuation record not found")
	// ErrRecordIntegrity is returned for malformed or unauthentic durable state.
	ErrRecordIntegrity = errors.New("reboot continuation record integrity violation")
	// ErrRecordConflict is returned for compare-and-swap drift.
	ErrRecordConflict = errors.New("reboot continuation record conflict")
)

// Binding is the authenticated RebootPending aggregate checkpoint. These
// fields are verified against the protected install journal but are never
// copied into the platform login payload.
type Binding struct {
	OperationID      install.OperationID
	PlanDigest       install.PlanDigest
	AggregateVersion uint64
	ResumeReceipt    install.Digest
}

func (b Binding) valid() bool {
	return !b.OperationID.IsZero() && !b.PlanDigest.IsZero() && b.AggregateVersion > 0 && !b.ResumeReceipt.IsZero()
}

// Evidence is resolved afresh from the installed launcher and authenticated
// operation journal immediately before registration and consumption.
type Evidence struct {
	Binding      Binding
	Verification rebootcontinuation.Verification
}

func (e Evidence) validFor(binding Binding) bool {
	return binding.valid() && e.Binding == binding && e.Verification.OperationID == binding.OperationID
}

// Clock is an explicit UTC time source.
type Clock interface{ Now() time.Time }

// Entropy supplies random non-secret bytes. Implementations must never reuse
// output across calls.
type Entropy interface {
	Bytes(context.Context, int) ([]byte, error)
}

// EvidenceResolver verifies owner, machine-bound journal authentication,
// current RebootPending state, executable/journal paths, and their hashes.
type EvidenceResolver interface {
	Resolve(context.Context, Binding) (Evidence, error)
}

// RecordRepository durably publishes and atomically claims an owner-only
// continuation. Claim must be idempotent for the same exact record so a crash
// after claim can recover while the aggregate is still RebootPending.
type RecordRepository interface {
	Load(context.Context, install.OperationID) (rebootcontinuation.Record, error)
	Publish(context.Context, rebootcontinuation.Record) error
	Claim(context.Context, rebootcontinuation.Record) error
	Delete(context.Context, install.OperationID) error
}

// LoginRegistrar owns the platform's per-user login continuation facility.
type LoginRegistrar interface {
	Register(context.Context, rebootcontinuation.Record) error
	Remove(context.Context, install.OperationID) error
}

// Dependencies are mandatory clean-architecture ports.
type Dependencies struct {
	Clock     Clock
	Entropy   Entropy
	Evidence  EvidenceResolver
	Records   RecordRepository
	Registrar LoginRegistrar
}

// Application is the production RebootCoordinator use case.
type Application struct{ dependencies Dependencies }

// New rejects every partial or typed-nil composition.
func New(dependencies Dependencies) (*Application, error) {
	for _, dependency := range []any{
		dependencies.Clock, dependencies.Entropy, dependencies.Evidence,
		dependencies.Records, dependencies.Registrar,
	} {
		if nilCapability(dependency) {
			return nil, ErrIntegrity
		}
	}
	return &Application{dependencies: dependencies}, nil
}

// Register persists a verified continuation before reconciling its native
// login entry. Same-record replay never rotates the nonce or expiry.
func (a *Application) Register(ctx context.Context, binding Binding) error {
	if a == nil || ctx == nil || !binding.valid() {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	evidence, err := a.resolve(ctx, binding)
	if err != nil {
		return err
	}
	now := a.dependencies.Clock.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return ErrIntegrity
	}
	existing, loadError := a.dependencies.Records.Load(ctx, binding.OperationID)
	switch {
	case loadError == nil:
		if verifyError := existing.Verify(evidence.Verification, now); verifyError == nil {
			return mapBoundary(a.dependencies.Registrar.Register(ctx, existing))
		}
		if !existing.Expired(now) {
			return ErrIntegrity
		}
		if cleanupError := a.remove(ctx, binding.OperationID); cleanupError != nil {
			return cleanupError
		}
	case errors.Is(loadError, ErrRecordNotFound):
	case loadError != nil:
		return mapBoundary(loadError)
	}
	random, entropyError := a.dependencies.Entropy.Bytes(ctx, 32)
	if entropyError != nil {
		return mapBoundary(entropyError)
	}
	nonce, nonceError := rebootcontinuation.NewNonce(random)
	if nonceError != nil {
		return ErrIntegrity
	}
	record, recordError := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: evidence.Verification.LauncherPath, LauncherDigest: evidence.Verification.LauncherDigest,
		OperationID: binding.OperationID, JournalPath: evidence.Verification.JournalPath,
		JournalDigest: evidence.Verification.JournalDigest, ExpiresAt: now.Add(rebootcontinuation.MaximumLifetime),
		Nonce: nonce,
	}, now)
	if recordError != nil {
		return ErrIntegrity
	}
	if publishError := a.dependencies.Records.Publish(ctx, record); publishError != nil {
		return mapBoundary(publishError)
	}
	return mapBoundary(a.dependencies.Registrar.Register(ctx, record))
}

// Consume re-verifies every protected fact and atomically claims the nonce.
// The login entry deliberately remains until the caller durably advances the
// aggregate beyond RebootPending; that closes the crash window between claim
// and the first resumed aggregate checkpoint.
func (a *Application) Consume(ctx context.Context, binding Binding) error {
	if a == nil || ctx == nil || !binding.valid() {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	evidence, err := a.resolve(ctx, binding)
	if err != nil {
		return err
	}
	record, err := a.dependencies.Records.Load(ctx, binding.OperationID)
	if err != nil {
		return mapBoundary(err)
	}
	now := a.dependencies.Clock.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return ErrIntegrity
	}
	if verifyError := record.Verify(evidence.Verification, now); verifyError != nil {
		if record.Expired(now) {
			_ = a.remove(context.WithoutCancel(ctx), binding.OperationID)
		}
		return ErrIntegrity
	}
	if err = a.dependencies.Records.Claim(ctx, record); err != nil {
		return mapBoundary(err)
	}
	return nil
}

// Remove idempotently removes active/claimed records and the platform entry
// after success, cancellation, expiry, or terminal failure.
func (a *Application) Remove(ctx context.Context, operationID install.OperationID) error {
	if a == nil || ctx == nil || operationID.IsZero() {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.remove(ctx, operationID)
}

func (a *Application) resolve(ctx context.Context, binding Binding) (Evidence, error) {
	evidence, err := a.dependencies.Evidence.Resolve(ctx, binding)
	if err != nil {
		return Evidence{}, mapBoundary(err)
	}
	if !evidence.validFor(binding) {
		return Evidence{}, ErrIntegrity
	}
	return evidence, nil
}

func (a *Application) remove(ctx context.Context, operationID install.OperationID) error {
	if err := a.dependencies.Records.Delete(ctx, operationID); err != nil && !errors.Is(err, ErrRecordNotFound) {
		return mapBoundary(err)
	}
	if err := a.dependencies.Registrar.Remove(ctx, operationID); err != nil && !errors.Is(err, ErrRecordNotFound) {
		return mapBoundary(err)
	}
	return nil
}

func mapBoundary(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrIntegrity), errors.Is(err, ErrRecordIntegrity):
		return ErrIntegrity
	case errors.Is(err, ErrConflict), errors.Is(err, ErrRecordConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Concrete non-nilable values are valid capabilities.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
