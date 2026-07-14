// Package readinessapp orchestrates PF-001's complete readiness proof.
package readinessapp

import (
	"context"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

var (
	// ErrReceiptConflict reports an optimistic readiness-receipt race.
	ErrReceiptConflict = errors.New("readiness receipt conflict")
	// ErrReceiptIntegrity reports unauthentic or contradictory receipt state.
	ErrReceiptIntegrity = errors.New("readiness receipt integrity violation")
)

// Clock provides explicit policy time.
type Clock interface {
	Now() time.Time
}

// SQLiteIntegrityProbe checks the canonical SQLite database.
type SQLiteIntegrityProbe interface {
	ProbeSQLiteIntegrity(context.Context, ProbeRequest) (readiness.Result, error)
}

// MigrationHeadProbe checks the exact schema/migration head.
type MigrationHeadProbe interface {
	ProbeMigrationHead(context.Context, ProbeRequest) (readiness.Result, error)
}

// WritableVolumesProbe checks the expected owned persistent volumes.
type WritableVolumesProbe interface {
	ProbeWritableVolumes(context.Context, ProbeRequest) (readiness.Result, error)
}

// GraphCompatibilityProbe checks Neo4j schema and driver compatibility.
type GraphCompatibilityProbe interface {
	ProbeGraphCompatibility(context.Context, ProbeRequest) (readiness.Result, error)
}

// KeyAccessProbe checks protected key-reference usability from Core.
type KeyAccessProbe interface {
	ProbeKeyAccess(context.Context, ProbeRequest) (readiness.Result, error)
}

// AuditAppendProbe performs and verifies a governed audit append.
type AuditAppendProbe interface {
	ProbeAuditAppend(context.Context, ProbeRequest) (readiness.Result, error)
}

// DeletionGuardProbe proves deleted content remains excluded.
type DeletionGuardProbe interface {
	ProbeDeletionGuard(context.Context, ProbeRequest) (readiness.Result, error)
}

// ExpiredLeaseRecoveryProbe proves interrupted session recovery.
type ExpiredLeaseRecoveryProbe interface {
	ProbeExpiredLeaseRecovery(context.Context, ProbeRequest) (readiness.Result, error)
}

// LocalProvidersProbe live-probes all three offline provider roles.
type LocalProvidersProbe interface {
	ProbeLocalProviders(context.Context, ProbeRequest) (readiness.Result, error)
}

// SemanticWriteIndexRecallProbe proves a complete local memory round-trip.
type SemanticWriteIndexRecallProbe interface {
	ProbeSemanticWriteIndexRecall(context.Context, ProbeRequest) (readiness.Result, error)
}

// DefaultEgressDeniedProbe proves the default topology has no external route.
type DefaultEgressDeniedProbe interface {
	ProbeDefaultEgressDenied(context.Context, ProbeRequest) (readiness.Result, error)
}

// ReceiptRepository durably and idempotently records the successful receipt.
// It must reject a different receipt for the same operation/release binding.
type ReceiptRepository interface {
	SaveReadinessReceipt(context.Context, readiness.Receipt) error
}
