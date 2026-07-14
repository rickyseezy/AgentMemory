// Package firststart adapts protected plan and bootstrap repositories to the
// pristine-start application boundary.
package firststart

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrapresolver"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

type planSaver interface {
	Save(context.Context, installplan.Plan) error
}

// PlanRepository authenticates the application DTO as a canonical domain plan
// immediately before durable publication.
type PlanRepository struct{ saver planSaver }

// NewPlanRepository creates the authenticated canonical-plan publication adapter.
func NewPlanRepository(saver planSaver) (*PlanRepository, error) {
	if nilCapability(saver) {
		return nil, firststartapp.ErrIntegrity
	}
	return &PlanRepository{saver: saver}, nil
}

// SavePreparedPlan authenticates and immutably publishes an exact prepared plan.
func (r *PlanRepository) SavePreparedPlan(ctx context.Context, prepared firststartapp.PreparedInstallation) error {
	if r == nil || ctx == nil || !prepared.Valid() {
		return firststartapp.ErrIntegrity
	}
	plan, err := installplan.DecodeV1(prepared.CanonicalPlan())
	if err != nil || plan.OperationID() != prepared.OperationID() ||
		plan.InstallationID() != prepared.InstallationID() ||
		plan.AgentConfiguration().AgentHost() != prepared.Host() ||
		!plan.Digest().Equal(prepared.PlanDigest()) {
		return firststartapp.ErrIntegrity
	}
	if err := r.saver.Save(ctx, plan); err != nil {
		return errors.New("prepared plan could not be published")
	}
	return nil
}

type pointerPublisher interface {
	Publish(context.Context, install.Digest, bootstrapresolver.Binding) error
}

// PointerRepository converts the application binding to the protected
// rollback-anchored repository's value object.
type PointerRepository struct{ publisher pointerPublisher }

// NewPointerRepository creates the protected bootstrap-pointer publication adapter.
func NewPointerRepository(publisher pointerPublisher) (*PointerRepository, error) {
	if nilCapability(publisher) {
		return nil, firststartapp.ErrIntegrity
	}
	return &PointerRepository{publisher: publisher}, nil
}

// PublishBootstrap converts and publishes one exact monotonic host binding.
func (r *PointerRepository) PublishBootstrap(
	ctx context.Context,
	expected install.Digest,
	input firststartapp.BootstrapBinding,
) error {
	if r == nil || ctx == nil {
		return firststartapp.ErrIntegrity
	}
	binding, err := bootstrapresolver.NewBinding(
		input.Sequence, input.Host, input.InstallationID, input.OperationID, input.PlanDigest,
	)
	if err != nil {
		return firststartapp.ErrIntegrity
	}
	if err := r.publisher.Publish(ctx, expected, binding); err != nil {
		return errors.New("protected bootstrap pointer could not be published")
	}
	return nil
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
