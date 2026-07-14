package launcher

import (
	"context"
	"reflect"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrapresolver"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001NativeFirstStartComposesPublicationAndRetryThroughOneSupervisor(t *testing.T) {
	t.Parallel()
	dependencies := nativeFirstStartFixture()
	composition, err := composeNativeFirstStart(dependencies)
	if err != nil || composition.Factory == nil || composition.Supervisor == nil {
		t.Fatalf("composition=%+v error=%v", composition, err)
	}
	if dependencies.Runtime.supervisor != composition.Supervisor || composition.Factory.initializer == nil {
		t.Fatalf("supervisor/initializer binding was not installed: runtime=%+v factory=%+v", dependencies.Runtime, composition.Factory)
	}
	if err := composition.Supervisor.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001NativeFirstStartRejectsEveryIncompleteComposition(t *testing.T) {
	t.Parallel()
	base := nativeFirstStartFixture()
	value := reflect.ValueOf(&base).Elem()
	typeOfDependencies := value.Type()
	for index := 0; index < value.NumField(); index++ {
		candidate := base
		field := reflect.ValueOf(&candidate).Elem().Field(index)
		field.Set(reflect.Zero(field.Type()))
		composition, err := composeNativeFirstStart(candidate)
		if composition.Factory != nil || composition.Supervisor != nil || err == nil {
			t.Fatalf("missing %s accepted: composition=%+v error=%v", typeOfDependencies.Field(index).Name, composition, err)
		}
	}
}

func nativeFirstStartFixture() nativeFirstStartDependencies {
	return nativeFirstStartDependencies{
		Templates: &nativeFirstStartTemplates{},
		Applications: func(context.Context, nativeInstallAuthority) (nativeInstallApplication, error) {
			return &nativeInstallApplicationStub{}, nil
		},
		Resolver: &nativeFirstStartResolver{}, Plans: &nativeFirstStartPlans{},
		Operations: &nativeFirstStartOperations{}, Preparations: &nativeFirstStartPreparations{},
		Binder:  &nativeFirstStartBinder{},
		Runtime: &nativeRuntimeFactory{},
	}
}

type nativeFirstStartTemplates struct{}

func (*nativeFirstStartTemplates) Current(context.Context) (firststartapp.Template, error) {
	return firststartapp.Template{}, nil
}
func (*nativeFirstStartTemplates) Exact(context.Context, install.PlanDigest) (firststartapp.Template, error) {
	return firststartapp.Template{}, nil
}

type nativeFirstStartResolver struct{}

func (*nativeFirstStartResolver) ResolveBootstrap(context.Context, agentconfigdomain.AgentHost) (mcpbootstrapapp.ResolvedBootstrap, error) {
	return mcpbootstrapapp.ResolvedBootstrap{}, mcpbootstrapapp.ErrBootstrapNotFound
}
func (*nativeFirstStartResolver) Publish(context.Context, install.Digest, bootstrapresolver.Binding) error {
	return nil
}

type nativeFirstStartPlans struct{}

func (*nativeFirstStartPlans) Save(context.Context, installplan.Plan) error { return nil }

type nativeFirstStartOperations struct{}

func (*nativeFirstStartOperations) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return nil, installapp.ErrOperationNotFound
}
func (*nativeFirstStartOperations) Save(context.Context, install.OperationSnapshot) error { return nil }

type nativeFirstStartPreparations struct{}

func (*nativeFirstStartPreparations) Load(context.Context, agentconfigdomain.AgentHost) (firststartapp.Preparation, error) {
	return firststartapp.Preparation{}, firststartapp.ErrPreparationNotFound
}
func (*nativeFirstStartPreparations) Acquire(context.Context, firststartapp.Preparation) (firststartapp.Preparation, error) {
	return firststartapp.Preparation{}, nil
}
func (*nativeFirstStartPreparations) ConfirmPlan(context.Context, firststartapp.Preparation, install.PlanDigest) (firststartapp.Preparation, error) {
	return firststartapp.Preparation{}, nil
}

type nativeFirstStartBinder struct{}

func (*nativeFirstStartBinder) Bind(context.Context, firststartapp.Template, firststartapp.Preparation) (firststartapp.PreparedInstallation, error) {
	return firststartapp.PreparedInstallation{}, nil
}
