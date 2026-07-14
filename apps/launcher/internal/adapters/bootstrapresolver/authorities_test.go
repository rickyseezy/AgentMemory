package bootstrapresolver

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001BootstrapPlanRepositoryAdapterFailsClosedOnInvalidAuthority(t *testing.T) {
	t.Parallel()
	var typedNil *canonicalPlanRepositoryStub
	for name, repository := range map[string]CanonicalPlanRepository{
		"nil":       nil,
		"typed nil": typedNil,
	} {
		if _, err := NewPlanRepositoryAdapter(repository); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s constructor error=%v", name, err)
		}
	}
	repository := &canonicalPlanRepositoryStub{}
	adapter, err := NewPlanRepositoryAdapter(repository)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := install.BindPlan([]byte("canonical-plan"))
	if _, err := adapter.LoadPlan(context.Background(), install.PlanDigest{}); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("zero digest error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves the adapter fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := adapter.LoadPlan(nil, digest); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.LoadPlan(cancelled, digest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
	repository.err = errors.New("private repository failure")
	if _, err := adapter.LoadPlan(context.Background(), digest); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("repository error=%v", err)
	}
	repository.err = nil
	if _, err := adapter.LoadPlan(context.Background(), digest); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("zero plan error=%v", err)
	}
	var nilAdapter *PlanRepositoryAdapter
	if _, err := nilAdapter.LoadPlan(context.Background(), digest); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil adapter error=%v", err)
	}

	projection := planProjection{}
	if !projection.Digest().IsZero() || !projection.OperationID().IsZero() ||
		projection.InstallationID() != "" || projection.AgentHost().Valid() ||
		projection.CanonicalBytes() != nil {
		t.Fatal("zero projection manufactured authority")
	}
}

func TestPF001BootstrapOperationAuthorityAuthenticatesExactAggregateBinding(t *testing.T) {
	t.Parallel()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	digest, _ := install.BindPlan([]byte("canonical-plan"))
	operation, _ := install.NewOperation(operationID, digest)
	repository := &operationRepositoryStub{operation: operation}
	adapter, err := NewOperationAuthorityAdapter(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.VerifyOperation(context.Background(), operationID, digest); err != nil {
		t.Fatalf("VerifyOperation() error=%v", err)
	}
	foreign, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	for name, run := range map[string]func() error{
		"zero operation": func() error {
			return adapter.VerifyOperation(context.Background(), install.OperationID{}, digest)
		},
		"zero plan": func() error {
			return adapter.VerifyOperation(context.Background(), operationID, install.PlanDigest{})
		},
		"foreign identity": func() error {
			repository.operation = operation
			return adapter.VerifyOperation(context.Background(), foreign, digest)
		},
		"nil aggregate": func() error {
			repository.operation = nil
			return adapter.VerifyOperation(context.Background(), operationID, digest)
		},
		"repository failure": func() error {
			repository.err = errors.New("private failure")
			return adapter.VerifyOperation(context.Background(), operationID, digest)
		},
	} {
		repository.operation, repository.err = operation, nil
		if err := run(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	repository.operation, repository.err = operation, nil
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := adapter.VerifyOperation(cancelled, operationID, digest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var nilAdapter *OperationAuthorityAdapter
	if err := nilAdapter.VerifyOperation(context.Background(), operationID, digest); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil adapter error=%v", err)
	}
}

func TestPF001BootstrapAuthorityConstructorsRejectTypedNilAndClassifyKinds(t *testing.T) {
	t.Parallel()
	var typedNil *operationRepositoryStub
	if _, err := NewOperationAuthorityAdapter(typedNil); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("typed-nil operation repository error=%v", err)
	}
	if nilAuthority(struct{}{}) || nilAuthority(1) || !nilAuthority(nil) {
		t.Fatal("nilAuthority classified concrete values incorrectly")
	}
	var nilMap map[string]string
	var nilSlice []string
	var nilFunction func()
	for _, value := range []any{nilMap, nilSlice, nilFunction, typedNil} {
		if !nilAuthority(value) {
			t.Fatalf("nilAuthority(%T)=false", value)
		}
	}
}

type canonicalPlanRepositoryStub struct {
	plan installplan.Plan
	err  error
}

func (r *canonicalPlanRepositoryStub) Load(context.Context, install.PlanDigest) (installplan.Plan, error) {
	return r.plan, r.err
}

type operationRepositoryStub struct {
	operation *install.Operation
	err       error
}

func (r *operationRepositoryStub) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.err
}
