package readinessapp

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

// Dependencies is the complete readiness composition contract.
type Dependencies struct {
	Clock                    Clock
	SQLiteIntegrity          SQLiteIntegrityProbe
	MigrationHead            MigrationHeadProbe
	WritableVolumes          WritableVolumesProbe
	GraphCompatibility       GraphCompatibilityProbe
	KeyAccess                KeyAccessProbe
	AuditAppend              AuditAppendProbe
	DeletionGuard            DeletionGuardProbe
	ExpiredLeaseRecovery     ExpiredLeaseRecoveryProbe
	LocalProviders           LocalProvidersProbe
	SemanticWriteIndexRecall SemanticWriteIndexRecallProbe
	DefaultEgressDenied      DefaultEgressDeniedProbe
	Receipts                 ReceiptRepository
}

// Application executes the complete readiness sequence and persists only a
// successful all-or-nothing receipt.
type Application struct {
	clock                    Clock
	sqliteIntegrity          SQLiteIntegrityProbe
	migrationHead            MigrationHeadProbe
	writableVolumes          WritableVolumesProbe
	graphCompatibility       GraphCompatibilityProbe
	keyAccess                KeyAccessProbe
	auditAppend              AuditAppendProbe
	deletionGuard            DeletionGuardProbe
	expiredLeaseRecovery     ExpiredLeaseRecoveryProbe
	localProviders           LocalProvidersProbe
	semanticWriteIndexRecall SemanticWriteIndexRecallProbe
	defaultEgressDenied      DefaultEgressDeniedProbe
	receipts                 ReceiptRepository
}

// NewApplication rejects every missing or typed-nil production capability.
func NewApplication(dependencies Dependencies) (*Application, error) {
	required := []struct {
		name  string
		value any
	}{
		{name: "clock", value: dependencies.Clock},
		{name: "SQLite integrity", value: dependencies.SQLiteIntegrity},
		{name: "migration head", value: dependencies.MigrationHead},
		{name: "writable volumes", value: dependencies.WritableVolumes},
		{name: "graph compatibility", value: dependencies.GraphCompatibility},
		{name: "key access", value: dependencies.KeyAccess},
		{name: "audit append", value: dependencies.AuditAppend},
		{name: "deletion guard", value: dependencies.DeletionGuard},
		{name: "expired lease recovery", value: dependencies.ExpiredLeaseRecovery},
		{name: "local providers", value: dependencies.LocalProviders},
		{name: "semantic write/index/recall", value: dependencies.SemanticWriteIndexRecall},
		{name: "default egress denied", value: dependencies.DefaultEgressDenied},
		{name: "receipt repository", value: dependencies.Receipts},
	}
	for _, dependency := range required {
		if nilCapability(dependency.value) {
			return nil, fmt.Errorf("readiness dependency %q is required", dependency.name)
		}
	}
	return &Application{
		clock:                    dependencies.Clock,
		sqliteIntegrity:          dependencies.SQLiteIntegrity,
		migrationHead:            dependencies.MigrationHead,
		writableVolumes:          dependencies.WritableVolumes,
		graphCompatibility:       dependencies.GraphCompatibility,
		keyAccess:                dependencies.KeyAccess,
		auditAppend:              dependencies.AuditAppend,
		deletionGuard:            dependencies.DeletionGuard,
		expiredLeaseRecovery:     dependencies.ExpiredLeaseRecovery,
		localProviders:           dependencies.LocalProviders,
		semanticWriteIndexRecall: dependencies.SemanticWriteIndexRecall,
		defaultEgressDenied:      dependencies.DefaultEgressDenied,
		receipts:                 dependencies.Receipts,
	}, nil
}

// Verify executes every gate in normative order. A negative, well-formed
// probe is an expected not-ready result; a broken boundary returns a sanitized
// application error and never creates a receipt.
func (a *Application) Verify(ctx context.Context, command Command) (Verification, error) {
	if ctx == nil {
		return Verification{}, applicationError(ErrorCodeInvalidArgument, false)
	}
	startedAt := a.clock.Now()
	request := newProbeRequest(command, startedAt)
	if startedAt.IsZero() || request.OperationID().IsZero() || request.PlanDigest().IsZero() ||
		request.ReleaseID() == "" || request.GenerationID() == "" ||
		request.ManifestDigest().IsZero() || request.ComposeDigest().IsZero() {
		return Verification{}, applicationError(ErrorCodeInvalidArgument, false)
	}

	checks := []func(context.Context, ProbeRequest) (readiness.Result, error){
		a.sqliteIntegrity.ProbeSQLiteIntegrity,
		a.migrationHead.ProbeMigrationHead,
		a.writableVolumes.ProbeWritableVolumes,
		a.graphCompatibility.ProbeGraphCompatibility,
		a.keyAccess.ProbeKeyAccess,
		a.auditAppend.ProbeAuditAppend,
		a.deletionGuard.ProbeDeletionGuard,
		a.expiredLeaseRecovery.ProbeExpiredLeaseRecovery,
		a.localProviders.ProbeLocalProviders,
		a.semanticWriteIndexRecall.ProbeSemanticWriteIndexRecall,
		a.defaultEgressDenied.ProbeDefaultEgressDenied,
	}
	results := make([]readiness.Result, 0, len(checks))
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return Verification{}, applicationError(ErrorCodeDeadlineExceeded, true)
		}
		result, err := check(ctx, request)
		if err != nil {
			return Verification{}, mapProbeError(err)
		}
		results = append(results, result)
	}

	evaluatedAt := a.clock.Now()
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID:    command.OperationID,
		PlanDigest:     command.PlanDigest,
		ReleaseID:      command.ReleaseID,
		GenerationID:   command.GenerationID,
		ManifestDigest: command.ManifestDigest,
		ComposeDigest:  command.ComposeDigest,
		EvaluatedAt:    evaluatedAt,
		Results:        results,
	})
	if len(failures) != 0 {
		return Verification{failures: append([]readiness.Failure(nil), failures...)}, nil
	}
	if receipt.IsZero() {
		return Verification{}, applicationError(ErrorCodeInternal, false)
	}
	if err := a.receipts.SaveReadinessReceipt(ctx, receipt); err != nil {
		return Verification{}, mapReceiptError(err)
	}
	return Verification{ready: true, receipt: receipt}, nil
}

func mapProbeError(err error) *ApplicationError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return applicationError(ErrorCodeDeadlineExceeded, true)
	}
	return applicationError(ErrorCodeDependencyUnavailable, true)
}

func mapReceiptError(err error) *ApplicationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	case errors.Is(err, ErrReceiptConflict):
		return applicationError(ErrorCodeConflict, true)
	case errors.Is(err, ErrReceiptIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false)
	default:
		return applicationError(ErrorCodeInternal, false)
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}
