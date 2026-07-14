package resourceapp

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

// Dependencies are mandatory named clean-architecture boundaries.
type Dependencies struct {
	Repository Repository
	Engine     containerengine.ManagedResourcePort
}

// Application creates and verifies the exact ADR-017 resource set one object
// at a time while persisting ownership after every mutation.
type Application struct {
	repository Repository
	engine     containerengine.ManagedResourcePort
}

// New rejects absent and typed-nil dependencies.
func New(dependencies Dependencies) (*Application, error) {
	if nilDependency(dependencies.Repository) || nilDependency(dependencies.Engine) {
		return nil, applicationError(ErrorInvalidCommand, "configure")
	}
	return &Application{repository: dependencies.Repository, engine: dependencies.Engine}, nil
}

// Command contains only verified installation state and an explicitly local
// Docker endpoint. No user path or Docker context is accepted.
type Command struct {
	InstallationID    string
	GenerationID      string
	Release           string
	CreationOperation string
	Endpoint          containerengine.Endpoint
}

// Result is a privacy-safe summary of exact resource reconciliation.
type Result struct {
	InventoryVersion uint64
	InventoryDigest  install.Digest
	Created          uint8
	Recovered        uint8
	Verified         uint8
}

// EnsureNetworkAndVolumes reconciles the internal network and six volumes.
// Pending authenticated intents permit crash recovery; a name alone never
// permits adoption or deletion.
func (a *Application) EnsureNetworkAndVolumes(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || command.Endpoint.String() == "" {
		return Result{}, applicationError(ErrorInvalidCommand, "validate")
	}
	plan, err := resourceinventory.BuildPlan(command.InstallationID, command.GenerationID, command.Release)
	if err != nil || len(plan) != 7 || !validCreationOperation(command.CreationOperation, plan) {
		return Result{}, applicationError(ErrorInvalidCommand, "validate")
	}

	inventory, err := a.loadOrCreate(ctx, command.InstallationID)
	if err != nil {
		return Result{}, err
	}
	result := Result{}
	createdThisAttempt := make([]resourceinventory.Observed, 0, len(plan))

	for _, spec := range plan {
		entry, exists := inventory.Find(spec.Name())
		if !exists {
			previous := inventory.Version()
			if _, beginError := inventory.Begin(spec, command.CreationOperation); beginError != nil {
				return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, ErrorOwnership, "record-intent")
			}
			if saveError := a.save(ctx, previous, inventory); saveError != nil {
				return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, ErrorInventory, "persist-intent")
			}
			entry, _ = inventory.Find(spec.Name())
		}

		switch entry.State() {
		case resourceinventory.EntryPending:
			observed, inspectError := a.engine.Inspect(ctx, command.Endpoint, spec)
			created := false
			recovered := false
			switch {
			case inspectError == nil:
				recovered = true
			case errors.Is(inspectError, containerengine.ErrManagedResourceNotFound):
				observed, inspectError = a.engine.Create(ctx, command.Endpoint, spec)
				created = inspectError == nil
			default:
			}
			if inspectError != nil {
				code := ErrorEngine
				if errors.Is(inspectError, containerengine.ErrManagedResourceCollision) ||
					errors.Is(inspectError, containerengine.ErrManagedResourceResponse) {
					code = ErrorOwnership
				}
				return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, code, "inspect-or-create")
			}
			previous := inventory.Version()
			if _, recordError := inventory.Record(spec, command.CreationOperation, observed); recordError != nil {
				return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, ErrorOwnership, "record-object")
			}
			// This is deliberately the first external call after Create: object ID
			// and labels become authenticated before another resource is touched.
			if saveError := a.save(ctx, previous, inventory); saveError != nil {
				// The durable pending intent enables exact recovery. Without a
				// recorded ID, deletion would be unauthorized, so preserve it.
				return Result{}, applicationError(ErrorInventory, "persist-object")
			}
			if created {
				createdThisAttempt = append(createdThisAttempt, observed)
				result.Created++
			} else if recovered {
				result.Recovered++
			}
		case resourceinventory.EntryRecorded:
			observed, inspectError := a.engine.Inspect(ctx, command.Endpoint, spec)
			if inspectError != nil || inventory.VerifyRecorded(spec, observed) != nil {
				return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, ErrorOwnership, "verify-recorded")
			}
			result.Verified++
		default:
			return a.failWithCompensation(ctx, command.Endpoint, inventory, createdThisAttempt, result, ErrorInventory, "entry-state")
		}
	}
	result.InventoryVersion = inventory.Version()
	result.InventoryDigest, err = inventory.Digest()
	if err != nil || result.InventoryDigest.IsZero() {
		return Result{}, applicationError(ErrorInventory, "digest-inventory")
	}
	return result, nil
}

func (a *Application) loadOrCreate(ctx context.Context, installationID string) (*resourceinventory.Inventory, error) {
	snapshot, err := a.repository.Load(ctx, installationID)
	switch {
	case err == nil:
		inventory, restoreError := resourceinventory.Restore(snapshot)
		if restoreError != nil || inventory.InstallationID() != installationID {
			return nil, applicationError(ErrorInventory, "restore")
		}
		return inventory, nil
	case errors.Is(err, ErrInventoryNotFound):
		inventory, createError := resourceinventory.New(installationID)
		if createError != nil {
			return nil, applicationError(ErrorInvalidCommand, "create-inventory")
		}
		if saveError := a.repository.Save(ctx, 0, inventory.Snapshot()); saveError != nil {
			return nil, mapRepositoryError(saveError, "create-inventory")
		}
		return inventory, nil
	default:
		return nil, mapRepositoryError(err, "load-inventory")
	}
}

func (a *Application) save(ctx context.Context, expected uint64, inventory *resourceinventory.Inventory) error {
	return a.repository.Save(ctx, expected, inventory.Snapshot())
}

func (a *Application) failWithCompensation(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	inventory *resourceinventory.Inventory,
	created []resourceinventory.Observed,
	result Result,
	code ErrorCode,
	operation string,
) (Result, error) {
	for index := len(created) - 1; index >= 0; index-- {
		authorization, err := inventory.AuthorizeRemoval(created[index])
		if err != nil || a.engine.Remove(ctx, endpoint, authorization) != nil {
			return result, applicationError(ErrorCompensation, "remove-created")
		}
		previous := inventory.Version()
		if inventory.ConfirmRemoved(authorization) != nil || a.save(ctx, previous, inventory) != nil {
			return result, applicationError(ErrorCompensation, "persist-removal")
		}
	}
	return result, applicationError(code, operation)
}

func validCreationOperation(value string, plan []resourceinventory.Spec) bool {
	if len(plan) == 0 {
		return false
	}
	inventory, err := resourceinventory.New(plan[0].Labels()["io.agentmemory.installation"])
	if err != nil {
		return false
	}
	_, err = inventory.Begin(plan[0], value)
	return err == nil
}

func mapRepositoryError(err error, operation string) error {
	if errors.Is(err, ErrInventoryIntegrity) || errors.Is(err, ErrInventoryConflict) {
		return applicationError(ErrorInventory, operation)
	}
	return applicationError(ErrorInventory, operation)
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}
