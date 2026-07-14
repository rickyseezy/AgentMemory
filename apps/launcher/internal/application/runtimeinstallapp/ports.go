package runtimeinstallapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// ErrOperationNotFound means no durable runtime sub-saga exists.
var ErrOperationNotFound = errors.New("runtime installation operation not found")

// ErrOperationConflict means the optimistic aggregate version changed.
var ErrOperationConflict = errors.New("runtime installation operation conflict")

// ErrOperationIntegrity means stored state cannot be authenticated/restored.
var ErrOperationIntegrity = errors.New("runtime installation operation integrity violation")

// OperationRepository durably stores the runtime sub-saga using optimistic
// aggregate versions and authenticated restoration.
type OperationRepository interface {
	Load(context.Context, string) (*runtimeinstall.Operation, error)
	Save(context.Context, runtimeinstall.OperationSnapshot) error
}

// HostCapabilityProbe performs only read-only platform/resource discovery.
type HostCapabilityProbe interface {
	DetectHost(context.Context, Request) (Output, error)
}

// ContainerRuntimeDetector addresses and inspects a local endpoint explicitly.
type ContainerRuntimeDetector interface {
	DetectRuntime(context.Context, Request) (Output, error)
}

// RuntimeReleaseCatalog verifies and binds the exact runtime install plan.
type RuntimeReleaseCatalog interface {
	PlanRuntime(context.Context, Request) (Output, error)
}

// RuntimeConsentPort obtains a non-preselected, exact-plan-bound decision.
type RuntimeConsentPort interface {
	AwaitRuntimeConsent(context.Context, Request) (Output, error)
}

// RuntimeArtifactFetcher performs allowlisted, resumable acquisition.
type RuntimeArtifactFetcher interface {
	AcquireRuntime(context.Context, Request) (Output, error)
}

// RuntimeArtifactVerifier proves digest and native publisher/package trust.
type RuntimeArtifactVerifier interface {
	VerifyRuntimeArtifact(context.Context, Request) (Output, error)
}

// RuntimePrerequisiteInstaller performs only closed, plan-bound prerequisites.
type RuntimePrerequisiteInstaller interface {
	InstallPrerequisites(context.Context, Request) (Output, error)
}

// ContainerRuntimeInstaller executes the verified vendor/package install plan.
type ContainerRuntimeInstaller interface {
	InstallRuntime(context.Context, Request) (Output, error)
}

// ThirdPartyTermsPort records only an exact terms/plan/principal receipt.
type ThirdPartyTermsPort interface {
	AwaitThirdPartyTerms(context.Context, Request) (Output, error)
}

// ContainerRuntimeController starts the explicit local endpoint without
// changing global context or unrelated runtime settings.
type ContainerRuntimeController interface {
	StartRuntime(context.Context, Request) (Output, error)
}

// RuntimeCapabilityProbe validates Engine, Compose, bind, network, volume,
// persistence, local execution, and security capabilities.
type RuntimeCapabilityProbe interface {
	VerifyRuntimeCapabilities(context.Context, Request) (Output, error)
}
