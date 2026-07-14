package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrapresolver"
	firststartadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/firststart"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installworker"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

type nativeBootstrapAuthority interface {
	mcpbootstrapapp.BootstrapResolver
	Publish(context.Context, install.Digest, bootstrapresolver.Binding) error
}

type nativePreparedPlanRepository interface {
	Save(context.Context, installplan.Plan) error
}

type nativeFirstStartDependencies struct {
	Templates    firststartapp.VerifiedTemplateSource
	Applications nativeInstallApplicationFactory
	Resolver     nativeBootstrapAuthority
	Plans        nativePreparedPlanRepository
	Operations   firststartapp.OperationRepository
	Preparations firststartapp.PreparationRepository
	Binder       firststartapp.PreparationBinder
	Runtime      *nativeRuntimeFactory
}

type nativeFirstStartComposition struct {
	Factory    *Factory
	Supervisor *installworker.Supervisor
}

// composeNativeFirstStart connects pristine release authority to the same
// process-owned supervisor later used by Setup Accept/Retry. Publication and
// execution therefore cannot diverge onto different installer instances.
func composeNativeFirstStart(
	dependencies nativeFirstStartDependencies,
) (nativeFirstStartComposition, error) {
	for _, dependency := range []any{
		dependencies.Templates, dependencies.Applications, dependencies.Resolver,
		dependencies.Plans, dependencies.Operations, dependencies.Preparations,
		dependencies.Binder, dependencies.Runtime,
	} {
		if nilAny(dependency) {
			return nativeFirstStartComposition{}, errNativeInstallerIntegrity
		}
	}
	installer, err := newNativeCommandInstaller(dependencies.Applications)
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	supervisor, err := installworker.New(installer)
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	failed := true
	defer func() {
		if failed {
			_ = supervisor.Close(context.Background())
		}
	}()
	preparer, err := firststartapp.NewPreparer(firststartapp.PreparerDependencies{
		Templates: dependencies.Templates, Identifiers: firststartadapter.NewNativeIdentifierGenerator(),
		Repository: dependencies.Preparations, Binder: dependencies.Binder,
	})
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	planPublisher, err := firststartadapter.NewPlanRepository(dependencies.Plans)
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	pointerPublisher, err := firststartadapter.NewPointerRepository(dependencies.Resolver)
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	initializer, err := firststartapp.New(firststartapp.Dependencies{
		Preparer: preparer, Plans: planPublisher, Operations: dependencies.Operations,
		Pointers: pointerPublisher, Supervisor: supervisor,
	})
	if err != nil {
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	dependencies.Runtime.supervisor = supervisor
	factory, err := NewFirstStartFactory(dependencies.Resolver, dependencies.Runtime, initializer)
	if err != nil {
		dependencies.Runtime.supervisor = nil
		return nativeFirstStartComposition{}, errNativeInstallerIntegrity
	}
	failed = false
	return nativeFirstStartComposition{Factory: factory, Supervisor: supervisor}, nil
}
