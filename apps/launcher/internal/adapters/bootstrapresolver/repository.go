// Package bootstrapresolver stores and resolves the protected per-agent
// bootstrap pointer used before the active Brain can serve MCP sessions.
package bootstrapresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	bindingSchemaVersion = uint16(1)
	maximumBindingBytes  = 16 * 1024
)

// JournalProvider supplies a purpose-separated, authenticated and rollback-
// anchored journal. Production must not share this root with operation state.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// PlanAuthority exposes only the immutable fields the resolver must bind.
type PlanAuthority interface {
	Digest() install.PlanDigest
	OperationID() install.OperationID
	InstallationID() string
	AgentHost() agentconfigdomain.AgentHost
	CanonicalBytes() []byte
}

// PlanAuthorityRepository authenticates immutable canonical installation plans.
type PlanAuthorityRepository interface {
	LoadPlan(context.Context, install.PlanDigest) (PlanAuthority, error)
}

// OperationAuthority authenticates the resumable operation selected by a binding.
type OperationAuthority interface {
	VerifyOperation(context.Context, install.OperationID, install.PlanDigest) error
}

// Clock supplies durable snapshot timestamps.
type Clock interface{ Now() time.Time }

// Binding is one immutable successor in an agent host's current pointer.
type Binding struct {
	sequence       uint64
	host           agentconfigdomain.AgentHost
	installationID string
	operationID    install.OperationID
	planDigest     install.PlanDigest
}

// NewBinding validates the complete pointer without consulting infrastructure.
func NewBinding(
	sequence uint64,
	host agentconfigdomain.AgentHost,
	installationID string,
	operationID install.OperationID,
	planDigest install.PlanDigest,
) (Binding, error) {
	if sequence == 0 || !host.Valid() || installationID == "" || operationID.IsZero() || planDigest.IsZero() {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return Binding{sequence: sequence, host: host, installationID: installationID,
		operationID: operationID, planDigest: planDigest}, nil
}

// Sequence returns the monotonic per-host pointer sequence.
func (b Binding) Sequence() uint64 { return b.sequence }

// Host returns the exact agent integration selected by this pointer.
func (b Binding) Host() agentconfigdomain.AgentHost { return b.host }

// InstallationID returns the local Brain installation identity.
func (b Binding) InstallationID() string { return b.installationID }

// OperationID returns the exact install operation.
func (b Binding) OperationID() install.OperationID { return b.operationID }

// PlanDigest returns the immutable plan binding.
func (b Binding) PlanDigest() install.PlanDigest { return b.planDigest }

// Digest binds the exact canonical pointer document for compare-and-swap.
func (b Binding) Digest() install.Digest {
	canonical, err := encodeBinding(b)
	if err != nil {
		return install.Digest{}
	}
	return install.DigestBytes(canonical)
}

// Repository resolves and mutates one per-host protected bootstrap pointer.
type Repository struct {
	journals   JournalProvider
	plans      PlanAuthorityRepository
	operations OperationAuthority
	clock      Clock
}

// New constructs a resolver only from complete protected authorities.
func New(journals JournalProvider, plans PlanAuthorityRepository, operations OperationAuthority, clock Clock) (*Repository, error) {
	if nilCapability(journals) || nilCapability(plans) || nilCapability(operations) || nilCapability(clock) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return &Repository{journals: journals, plans: plans, operations: operations, clock: clock}, nil
}

// Publish performs a monotonic compare-and-swap for exactly one agent host.
// Zero expected digest is accepted only for sequence one.
func (r *Repository) Publish(ctx context.Context, expected install.Digest, next Binding) error {
	if r == nil || ctx == nil || next.Digest().IsZero() {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal, pointerID, err := r.journal(ctx, next.host)
	if err != nil {
		return err
	}
	canonical, err := encodeBinding(next)
	if err != nil || len(canonical) > maximumBindingBytes {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	expectedRevision := uint64(0)
	currentSnapshot, loadErr := journal.LoadLatest(ctx)
	switch {
	case errors.Is(loadErr, installjournal.ErrNotFound):
		if !expected.IsZero() || next.sequence != 1 {
			return mcpbootstrapapp.ErrBootstrapConflict
		}
	case loadErr != nil:
		return mapJournalError(loadErr)
	default:
		current, decodeErr := decodeSnapshot(currentSnapshot, pointerID)
		if decodeErr != nil {
			return mcpbootstrapapp.ErrBootstrapIntegrity
		}
		currentCanonical, _ := encodeBinding(current)
		if bytes.Equal(currentCanonical, canonical) {
			return mapJournalError(journal.ConfirmDurable(ctx, pointerID.String(), currentSnapshot.Revision))
		}
		if expected.IsZero() || !current.Digest().Equal(expected) || current.sequence == ^uint64(0) ||
			next.sequence != current.sequence+1 || next.host != current.host ||
			next.installationID != current.installationID {
			return mcpbootstrapapp.ErrBootstrapConflict
		}
		expectedRevision = currentSnapshot.Revision
	}
	capturedAt := r.clock.Now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() || next.sequence != expectedRevision+1 {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := journal.Append(ctx, expectedRevision, installjournal.Snapshot{
		OperationID: pointerID.String(), Revision: next.sequence, CapturedAt: capturedAt, Payload: canonical,
	}); err != nil {
		return mapJournalError(err)
	}
	return nil
}

// ResolveBootstrap authenticates pointer, plan, and operation and rejects any
// cross-host, cross-installation, cross-plan, or cross-operation substitution.
func (r *Repository) ResolveBootstrap(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (mcpbootstrapapp.ResolvedBootstrap, error) {
	if r == nil || ctx == nil || !host.Valid() {
		return mcpbootstrapapp.ResolvedBootstrap{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return mcpbootstrapapp.ResolvedBootstrap{}, err
	}
	journal, pointerID, err := r.journal(ctx, host)
	if err != nil {
		return mcpbootstrapapp.ResolvedBootstrap{}, err
	}
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return mcpbootstrapapp.ResolvedBootstrap{}, mapJournalError(err)
	}
	binding, err := decodeSnapshot(snapshot, pointerID)
	if err != nil || binding.host != host {
		return mcpbootstrapapp.ResolvedBootstrap{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := journal.ConfirmDurable(ctx, pointerID.String(), snapshot.Revision); err != nil {
		return mcpbootstrapapp.ResolvedBootstrap{}, mapJournalError(err)
	}
	plan, err := r.plans.LoadPlan(ctx, binding.planDigest)
	if err != nil || !plan.Digest().Equal(binding.planDigest) || plan.OperationID() != binding.operationID ||
		plan.InstallationID() != binding.installationID || plan.AgentHost() != host {
		return mcpbootstrapapp.ResolvedBootstrap{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := r.operations.VerifyOperation(ctx, binding.operationID, binding.planDigest); err != nil {
		return mcpbootstrapapp.ResolvedBootstrap{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return mcpbootstrapapp.NewResolvedBootstrap(
		binding.installationID, binding.operationID, binding.planDigest, plan.CanonicalBytes(),
	)
}

func (r *Repository) journal(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (installjournal.Journal, install.OperationID, error) {
	pointerID, err := pointerOperationID(host)
	if err != nil || nilCapability(r.journals) {
		return nil, install.OperationID{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	journal, err := r.journals.JournalFor(ctx, pointerID)
	if err != nil {
		return nil, install.OperationID{}, mapJournalError(err)
	}
	if nilCapability(journal) {
		return nil, install.OperationID{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return journal, pointerID, nil
}

func pointerOperationID(host agentconfigdomain.AgentHost) (install.OperationID, error) {
	if !host.Valid() {
		return install.OperationID{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	id, err := install.NewOperationID("bootstrap-current-" + string(host) + "-v1")
	if err != nil {
		return install.OperationID{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return id, nil
}

type bindingDocument struct {
	SchemaVersion  uint16 `json:"schema_version"`
	Sequence       uint64 `json:"sequence"`
	Host           string `json:"host"`
	InstallationID string `json:"installation_id"`
	OperationID    string `json:"operation_id"`
	PlanDigest     string `json:"plan_digest"`
}

func encodeBinding(binding Binding) ([]byte, error) {
	if binding.sequence == 0 || !binding.host.Valid() || binding.installationID == "" ||
		binding.operationID.IsZero() || binding.planDigest.IsZero() {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return json.Marshal(bindingDocument{SchemaVersion: bindingSchemaVersion, Sequence: binding.sequence,
		Host: string(binding.host), InstallationID: binding.installationID,
		OperationID: binding.operationID.String(), PlanDigest: binding.planDigest.String()})
}

func decodeSnapshot(snapshot installjournal.Snapshot, pointerID install.OperationID) (Binding, error) {
	if snapshot.OperationID != pointerID.String() || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() ||
		len(snapshot.Payload) == 0 || len(snapshot.Payload) > maximumBindingBytes {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	var document bindingDocument
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.More() {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, snapshot.Payload) || document.SchemaVersion != bindingSchemaVersion ||
		document.Sequence != snapshot.Revision {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	operationID, err := install.NewOperationID(document.OperationID)
	if err != nil {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	planDigest, err := install.ParsePlanDigest(document.PlanDigest)
	if err != nil {
		return Binding{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return NewBinding(document.Sequence, agentconfigdomain.AgentHost(document.Host), document.InstallationID,
		operationID, planDigest)
}

func mapJournalError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return mcpbootstrapapp.ErrBootstrapNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return mcpbootstrapapp.ErrBootstrapConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return mcpbootstrapapp.ErrBootstrapIntegrity
	default:
		return mcpbootstrapapp.ErrBootstrapUnavailable
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var _ mcpbootstrapapp.BootstrapResolver = (*Repository)(nil)
