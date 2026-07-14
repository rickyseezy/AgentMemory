package firststartapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001FirstStartPublishesDurableAuthorityBeforeStartingInstaller(t *testing.T) {
	plan := firstStartPlan(t)
	order := make([]string, 0, 5)
	fixture := firstStartFixture(plan, &order)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if err = application.EnsureBootstrap(context.Background(), agentconfigdomain.AgentHostCodex); err != nil {
		t.Fatal(err)
	}
	want := []string{"prepare", "plan", "load", "operation", "pointer", "supervisor"}
	if len(order) != len(want) {
		t.Fatalf("order=%q", order)
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("order=%q want=%q", order, want)
		}
	}
	if fixture.pointer.binding.Host != agentconfigdomain.AgentHostCodex ||
		fixture.pointer.binding.OperationID != plan.OperationID() ||
		!fixture.pointer.binding.PlanDigest.Equal(plan.PlanDigest()) ||
		fixture.supervisor.command.OperationID != plan.OperationID().String() {
		t.Fatalf("published=%+v command=%+v", fixture.pointer.binding, fixture.supervisor.command)
	}
}

func TestPF001FirstStartReplayUsesExistingExactOperation(t *testing.T) {
	plan := firstStartPlan(t)
	operation, _ := install.NewOperation(plan.OperationID(), plan.PlanDigest())
	order := make([]string, 0, 5)
	fixture := firstStartFixture(plan, &order)
	fixture.operations.operation = operation
	application, _ := New(fixture.dependencies())
	if err := application.EnsureBootstrap(context.Background(), agentconfigdomain.AgentHostCodex); err != nil {
		t.Fatal(err)
	}
	if fixture.operations.saves != 0 || fixture.supervisor.calls != 1 {
		t.Fatalf("operation saves=%d supervisor=%d", fixture.operations.saves, fixture.supervisor.calls)
	}
	foreign, _ := install.BindPlan([]byte("foreign"))
	fixture.operations.operation, _ = install.NewOperation(plan.OperationID(), foreign)
	if err := application.EnsureBootstrap(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign operation error=%v", err)
	}
}

func TestPF001FirstStartFailsClosedAtEveryBoundary(t *testing.T) {
	plan := firstStartPlan(t)
	baseOrder := []string{}
	base := firstStartFixture(plan, &baseOrder)
	var typedPreparer *firstStartPreparer
	for name, dependencies := range map[string]Dependencies{
		"empty":     {},
		"typed nil": {Preparer: typedPreparer, Plans: base.plans, Operations: base.operations, Pointers: base.pointer, Supervisor: base.supervisor},
	} {
		if application, err := New(dependencies); application != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s New()=%v,%v", name, application, err)
		}
	}
	application, _ := New(base.dependencies())
	if err := application.EnsureBootstrap(context.Background(), agentconfigdomain.AgentHost("bad")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("invalid host error=%v", err)
	}
	for name, mutate := range map[string]func(*firstStartTestFixture){
		"prepare":    func(f *firstStartTestFixture) { f.preparer.err = errors.New("private") },
		"plan":       func(f *firstStartTestFixture) { f.plans.err = errors.New("private") },
		"load":       func(f *firstStartTestFixture) { f.operations.loadErr = installapp.ErrOperationIntegrity },
		"save":       func(f *firstStartTestFixture) { f.operations.saveErr = installapp.ErrOperationConflict },
		"pointer":    func(f *firstStartTestFixture) { f.pointer.err = errors.New("private") },
		"supervisor": func(f *firstStartTestFixture) { f.supervisor.err = errors.New("private") },
	} {
		order := []string{}
		fixture := firstStartFixture(plan, &order)
		mutate(&fixture)
		application, _ := New(fixture.dependencies())
		err := application.EnsureBootstrap(context.Background(), agentconfigdomain.AgentHostCodex)
		if err == nil {
			t.Fatalf("%s boundary accepted", name)
		}
	}
}

// The installplan package already exhaustively tests construction. Reuse its
// canonical fixture through a tiny valid document generated in the same shape.
func firstStartPlan(t *testing.T) PreparedInstallation {
	t.Helper()
	operation, err := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := NewPreparedInstallation(
		[]byte(`{"schema_version":1,"release":"signed-fixture"}`), operation,
		"019f5f20-1234-7abc-8123-0123456789ab", agentconfigdomain.AgentHostCodex,
	)
	if err != nil || !prepared.Valid() {
		t.Fatalf("prepared fixture=%v,%v", prepared, err)
	}
	return prepared
}

type firstStartTestFixture struct {
	preparer   *firstStartPreparer
	plans      *firstStartPlans
	operations *firstStartOperations
	pointer    *firstStartPointer
	supervisor *firstStartSupervisor
}

func firstStartFixture(plan PreparedInstallation, order *[]string) firstStartTestFixture {
	return firstStartTestFixture{
		preparer: &firstStartPreparer{plan: plan, order: order}, plans: &firstStartPlans{order: order},
		operations: &firstStartOperations{order: order}, pointer: &firstStartPointer{order: order},
		supervisor: &firstStartSupervisor{order: order},
	}
}

func (f firstStartTestFixture) dependencies() Dependencies {
	return Dependencies{Preparer: f.preparer, Plans: f.plans, Operations: f.operations, Pointers: f.pointer, Supervisor: f.supervisor}
}

type firstStartPreparer struct {
	plan  PreparedInstallation
	order *[]string
	err   error
}

func (p *firstStartPreparer) Prepare(context.Context, agentconfigdomain.AgentHost) (PreparedInstallation, error) {
	*p.order = append(*p.order, "prepare")
	if p.err != nil {
		return PreparedInstallation{}, p.err
	}
	return p.plan, nil
}

type firstStartPlans struct {
	order *[]string
	err   error
}

func (p *firstStartPlans) SavePreparedPlan(context.Context, PreparedInstallation) error {
	*p.order = append(*p.order, "plan")
	return p.err
}

type firstStartOperations struct {
	order            *[]string
	operation        *install.Operation
	loadErr, saveErr error
	saves            int
}

func (o *firstStartOperations) Load(context.Context, install.OperationID) (*install.Operation, error) {
	*o.order = append(*o.order, "load")
	if o.loadErr != nil {
		return nil, o.loadErr
	}
	if o.operation == nil {
		return nil, installapp.ErrOperationNotFound
	}
	return o.operation, nil
}
func (o *firstStartOperations) Save(_ context.Context, snapshot install.OperationSnapshot) error {
	*o.order = append(*o.order, "operation")
	o.saves++
	if o.saveErr == nil {
		o.operation, _ = install.NewOperation(snapshot.OperationID(), snapshot.PlanDigest())
	}
	return o.saveErr
}

type firstStartPointer struct {
	order   *[]string
	binding BootstrapBinding
	err     error
}

func (p *firstStartPointer) PublishBootstrap(_ context.Context, _ install.Digest, binding BootstrapBinding) error {
	*p.order = append(*p.order, "pointer")
	p.binding = binding
	return p.err
}

type firstStartSupervisor struct {
	order   *[]string
	command installapp.InstallCommand
	calls   int
	err     error
}

func (s *firstStartSupervisor) EnsureRunning(_ context.Context, command installapp.InstallCommand) error {
	*s.order = append(*s.order, "supervisor")
	s.command = command
	s.calls++
	return s.err
}
