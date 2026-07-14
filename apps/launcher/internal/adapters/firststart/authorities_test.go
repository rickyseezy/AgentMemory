package firststart

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrapresolver"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001PointerRepositoryPublishesExactProtectedBinding(t *testing.T) {
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	digest, _ := install.BindPlan([]byte("canonical"))
	publisher := &pointerStub{}
	repository, err := NewPointerRepository(publisher)
	if err != nil {
		t.Fatal(err)
	}
	input := firststartapp.BootstrapBinding{Sequence: 1, Host: agentconfigdomain.AgentHostCodex,
		InstallationID: "019f5f20-1234-7abc-8123-0123456789ab", OperationID: operation, PlanDigest: digest}
	if err := repository.PublishBootstrap(context.Background(), install.Digest{}, input); err != nil {
		t.Fatal(err)
	}
	if publisher.binding.Sequence() != 1 || publisher.binding.Host() != input.Host ||
		publisher.binding.OperationID() != operation || !publisher.binding.PlanDigest().Equal(digest) {
		t.Fatalf("binding=%+v", publisher.binding)
	}
	input.Sequence = 0
	if err := repository.PublishBootstrap(context.Background(), install.Digest{}, input); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("invalid binding error=%v", err)
	}
}

func TestPF001FirstStartAuthorityAdaptersRejectPartialComposition(t *testing.T) {
	var nilSaver *planSaverStub
	var nilPublisher *pointerStub
	if value, err := NewPlanRepository(nilSaver); value != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("plan repository=%v,%v", value, err)
	}
	if value, err := NewPointerRepository(nilPublisher); value != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("pointer repository=%v,%v", value, err)
	}
	planRepository, _ := NewPlanRepository(&planSaverStub{})
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	prepared, _ := firststartapp.NewPreparedInstallation([]byte("not a canonical plan"), operation, "installation", agentconfigdomain.AgentHostCodex)
	if err := planRepository.SavePreparedPlan(context.Background(), prepared); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("invalid plan error=%v", err)
	}
	var absentPlanRepository *PlanRepository
	if err := absentPlanRepository.SavePreparedPlan(context.Background(), prepared); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil plan repository error=%v", err)
	}
	publisher := &pointerStub{err: errors.New("private")}
	pointerRepository, _ := NewPointerRepository(publisher)
	digest, _ := install.BindPlan([]byte("canonical"))
	input := firststartapp.BootstrapBinding{Sequence: 1, Host: agentconfigdomain.AgentHostCodex,
		InstallationID: "019f5f20-1234-7abc-8123-0123456789ab", OperationID: operation, PlanDigest: digest}
	if err := pointerRepository.PublishBootstrap(context.Background(), install.Digest{}, input); err == nil || errors.Is(err, publisher.err) {
		t.Fatalf("publisher error=%v", err)
	}
	var absentPointerRepository *PointerRepository
	if err := absentPointerRepository.PublishBootstrap(context.Background(), install.Digest{}, input); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil pointer repository error=%v", err)
	}
	if nilCapability(struct{}{}) || !nilCapability(nil) {
		t.Fatal("nil capability classification")
	}
}

type pointerStub struct {
	binding bootstrapresolver.Binding
	err     error
}

func (p *pointerStub) Publish(_ context.Context, _ install.Digest, binding bootstrapresolver.Binding) error {
	p.binding = binding
	return p.err
}

type planSaverStub struct {
	plan installplan.Plan
	err  error
}

func (s *planSaverStub) Save(_ context.Context, plan installplan.Plan) error {
	s.plan = plan
	return s.err
}
