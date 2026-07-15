package runtimeremovalapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

var (
	// ErrOperationNotFound means the separate removal saga has not been created.
	ErrOperationNotFound = errors.New("managed runtime removal operation not found")
	// ErrOperationConflict means optimistic persistence rejected stale state.
	ErrOperationConflict = errors.New("managed runtime removal operation conflict")
	// ErrIntegrity means protected authority or persisted state is invalid.
	ErrIntegrity = errors.New("managed runtime removal integrity violation")
	// ErrDependenciesExist means the exhaustive scan found a dependency.
	ErrDependenciesExist = errors.New("managed runtime removal dependencies exist")
	// ErrScanUncertain means a mandatory dependency or presence proof is unavailable.
	ErrScanUncertain = errors.New("managed runtime removal scan is uncertain")
)

// OperationRepository persists the separate saga with optimistic CAS.
type OperationRepository interface {
	Load(context.Context, string) (*runtimeremoval.Operation, error)
	Save(context.Context, runtimeremoval.OperationSnapshot) error
}

// RuntimeOwnershipRepository reads finalized PF-006 authority.
type RuntimeOwnershipRepository interface {
	LoadRuntimeOwnership(context.Context, string) (runtimeinstall.RuntimeOwnershipRecord, error)
}

// DependencyScanner returns all seven mandatory dependency categories.
type DependencyScanner interface {
	ScanRuntimeDependencies(context.Context, ScanRequest) (runtimeremoval.DependencyScan, error)
}

// SecondConsentPort obtains a non-preselected impact-specific decision.
type SecondConsentPort interface {
	AwaitManagedRuntimeRemovalConsent(context.Context, runtimeremoval.Plan) (ConsentDecision, error)
}

// RuntimePresenceVerifier proves whether the exact signed runtime remains.
type RuntimePresenceVerifier interface {
	InspectManagedRuntime(context.Context, runtimeremoval.Plan) (PresenceProof, error)
}

// NativeRemover executes only the closed platform action in its authorization.
type NativeRemover interface {
	RemoveManagedRuntime(context.Context, RemovalAuthorization) (NativeRemovalResult, error)
}
