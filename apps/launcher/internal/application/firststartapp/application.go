// Package firststartapp establishes the durable PF-001 authority required by
// the first MCP invocation. It owns no platform or installation side effects.
package firststartapp

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var (
	// ErrIntegrity means a release-derived authority is absent, malformed, or substituted.
	ErrIntegrity = errors.New("first-start authority integrity violation")
	// ErrUnavailable means a complete trusted release or durable adapter is unavailable.
	ErrUnavailable = errors.New("first-start authority unavailable")
	// ErrConflict means durable state belongs to another plan or installation.
	ErrConflict = errors.New("first-start authority conflict")
)

// PreparedInstallation is an immutable plan produced from the verified packaged
// release and stable per-host generation state. Prepare must return the same
// plan after a crash until that installation becomes active or is abandoned by
// an explicit recovery use case.
type PreparedInstallation struct {
	canonical      []byte
	digest         install.PlanDigest
	operationID    install.OperationID
	installationID string
	host           agentconfigdomain.AgentHost
}

// NewPreparedInstallation validates the complete canonical authority.
func NewPreparedInstallation(
	canonical []byte,
	operationID install.OperationID,
	installationID string,
	host agentconfigdomain.AgentHost,
) (PreparedInstallation, error) {
	digest, err := install.BindPlan(canonical)
	if err != nil || !host.Valid() || operationID.IsZero() || installationID == "" {
		return PreparedInstallation{}, ErrIntegrity
	}
	return PreparedInstallation{
		canonical: append([]byte(nil), canonical...), digest: digest,
		operationID: operationID, installationID: installationID, host: host,
	}, nil
}

// CanonicalPlan returns caller-owned exact plan bytes.
func (p PreparedInstallation) CanonicalPlan() []byte { return append([]byte(nil), p.canonical...) }

// PlanDigest returns the exact canonical-plan binding.
func (p PreparedInstallation) PlanDigest() install.PlanDigest { return p.digest }

// OperationID returns the sole installation operation identity.
func (p PreparedInstallation) OperationID() install.OperationID { return p.operationID }

// InstallationID returns the stable local installation identity.
func (p PreparedInstallation) InstallationID() string { return p.installationID }

// Host returns the selected agent-host adapter.
func (p PreparedInstallation) Host() agentconfigdomain.AgentHost { return p.host }

// Valid reauthenticates every immutable preparation binding.
func (p PreparedInstallation) Valid() bool {
	digest, err := install.BindPlan(p.canonical)
	return err == nil && digest.Equal(p.digest) && !p.operationID.IsZero() &&
		p.installationID != "" && p.host.Valid()
}

// AuthorityPreparer verifies the packaged release and durably selects stable
// per-host identifiers before returning a plan. It must never trust MCP input.
type AuthorityPreparer interface {
	Prepare(context.Context, agentconfigdomain.AgentHost) (PreparedInstallation, error)
}

// PlanRepository durably publishes exact canonical plan bytes once.
type PlanRepository interface {
	SavePreparedPlan(context.Context, PreparedInstallation) error
}

// OperationRepository is the shared aggregate CAS authority used by the installer.
type OperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
	Save(context.Context, install.OperationSnapshot) error
}

// BootstrapBinding is the protected host pointer projection.
type BootstrapBinding struct {
	Sequence       uint64
	Host           agentconfigdomain.AgentHost
	InstallationID string
	OperationID    install.OperationID
	PlanDigest     install.PlanDigest
}

// BootstrapPublisher performs an idempotent compare-and-swap publication.
type BootstrapPublisher interface {
	PublishBootstrap(context.Context, install.Digest, BootstrapBinding) error
}

// InstallationSupervisor starts or rejoins exactly one plan-bound installer
// worker and returns promptly. It owns worker lifetime and de-duplication.
type InstallationSupervisor interface {
	EnsureRunning(context.Context, installapp.InstallCommand) error
}

// Dependencies are mandatory Clean Architecture ports.
type Dependencies struct {
	Preparer   AuthorityPreparer
	Plans      PlanRepository
	Operations OperationRepository
	Pointers   BootstrapPublisher
	Supervisor InstallationSupervisor
}

// Application establishes or replays the first-start authority.
type Application struct{ dependencies Dependencies }

// New refuses partial or typed-nil production composition.
func New(dependencies Dependencies) (*Application, error) {
	for _, dependency := range []any{
		dependencies.Preparer, dependencies.Plans, dependencies.Operations,
		dependencies.Pointers, dependencies.Supervisor,
	} {
		if nilCapability(dependency) {
			return nil, ErrIntegrity
		}
	}
	return &Application{dependencies: dependencies}, nil
}

// EnsureBootstrap executes the only legal publication order. Every step is
// idempotent so process death between any two calls is safely replayable.
func (a *Application) EnsureBootstrap(ctx context.Context, host agentconfigdomain.AgentHost) error {
	if a == nil || ctx == nil || !host.Valid() {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prepared, err := a.dependencies.Preparer.Prepare(ctx, host)
	if err != nil {
		return mapBoundary(err)
	}
	if !prepared.Valid() || prepared.Host() != host {
		return ErrIntegrity
	}
	if err = a.dependencies.Plans.SavePreparedPlan(ctx, prepared); err != nil {
		return mapBoundary(err)
	}
	if err = a.ensureOperation(ctx, prepared); err != nil {
		return err
	}
	binding := BootstrapBinding{
		Sequence: 1, Host: host, InstallationID: prepared.InstallationID(),
		OperationID: prepared.OperationID(), PlanDigest: prepared.PlanDigest(),
	}
	if err = a.dependencies.Pointers.PublishBootstrap(ctx, install.Digest{}, binding); err != nil {
		return mapBoundary(err)
	}
	command := installapp.InstallCommand{
		OperationID: prepared.OperationID().String(), CanonicalPlan: prepared.CanonicalPlan(),
	}
	if err = a.dependencies.Supervisor.EnsureRunning(ctx, command); err != nil {
		return mapBoundary(err)
	}
	return nil
}

func (a *Application) ensureOperation(ctx context.Context, plan PreparedInstallation) error {
	operation, err := a.dependencies.Operations.Load(ctx, plan.OperationID())
	switch {
	case err == nil && operation != nil:
		if !operation.PlanDigest().Equal(plan.PlanDigest()) || operation.ID() != plan.OperationID() {
			return ErrConflict
		}
		return nil
	case err == nil:
		return ErrIntegrity
	case errors.Is(err, installapp.ErrOperationNotFound):
		operation, err = install.NewOperation(plan.OperationID(), plan.PlanDigest())
		if err != nil {
			return ErrIntegrity
		}
		if err = a.dependencies.Operations.Save(ctx, operation.Snapshot()); err != nil {
			return mapBoundary(err)
		}
		return nil
	default:
		return mapBoundary(err)
	}
}

func mapBoundary(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrIntegrity) || errors.Is(err, installapp.ErrOperationIntegrity) {
		return ErrIntegrity
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, installapp.ErrOperationConflict) {
		return ErrConflict
	}
	return ErrUnavailable
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
