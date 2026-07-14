// Package readiness defines PF-001's all-or-nothing product readiness proof.
// Container running/healthy state is deliberately insufficient.
package readiness

import (
	"errors"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const maximumBindingLength = 128

// Probe is the closed set of independently evidenced PF-001 readiness gates.
type Probe uint8

const (
	// ProbeUnknown is the invalid zero value.
	ProbeUnknown Probe = iota
	// ProbeSQLiteIntegrity proves canonical SQLite integrity.
	ProbeSQLiteIntegrity
	// ProbeMigrationHead proves every required migration is active.
	ProbeMigrationHead
	// ProbeWritableVolumes proves the expected owned data volumes are writable.
	ProbeWritableVolumes
	// ProbeGraphCompatibility proves Neo4j schema and driver compatibility.
	ProbeGraphCompatibility
	// ProbeKeyAccess proves the running core can use protected key references.
	ProbeKeyAccess
	// ProbeAuditAppend proves a governed audit record can be committed.
	ProbeAuditAppend
	// ProbeDeletionGuard proves deleted content cannot be recalled or rebuilt.
	ProbeDeletionGuard
	// ProbeExpiredLeaseRecovery proves interrupted session recovery.
	ProbeExpiredLeaseRecovery
	// ProbeLocalProviders proves embedding, reranking, and extraction locally.
	ProbeLocalProviders
	// ProbeSemanticWriteIndexRecall proves the complete default memory path.
	ProbeSemanticWriteIndexRecall
	// ProbeDefaultEgressDenied proves the default stack has no external route.
	ProbeDefaultEgressDenied
)

// RequiredProbes returns a copy in normative execution order.
func RequiredProbes() []Probe {
	return []Probe{
		ProbeSQLiteIntegrity,
		ProbeMigrationHead,
		ProbeWritableVolumes,
		ProbeGraphCompatibility,
		ProbeKeyAccess,
		ProbeAuditAppend,
		ProbeDeletionGuard,
		ProbeExpiredLeaseRecovery,
		ProbeLocalProviders,
		ProbeSemanticWriteIndexRecall,
		ProbeDefaultEgressDenied,
	}
}

// String returns the stable evidence key.
func (p Probe) String() string {
	switch p {
	case ProbeSQLiteIntegrity:
		return "sqlite_integrity"
	case ProbeMigrationHead:
		return "migration_head"
	case ProbeWritableVolumes:
		return "writable_volumes"
	case ProbeGraphCompatibility:
		return "graph_compatibility"
	case ProbeKeyAccess:
		return "key_access"
	case ProbeAuditAppend:
		return "audit_append"
	case ProbeDeletionGuard:
		return "deletion_guard"
	case ProbeExpiredLeaseRecovery:
		return "expired_lease_recovery"
	case ProbeLocalProviders:
		return "local_providers"
	case ProbeSemanticWriteIndexRecall:
		return "semantic_write_index_recall"
	case ProbeDefaultEgressDenied:
		return "default_egress_denied"
	case ProbeUnknown:
	}
	return "unknown"
}

// Valid reports whether a probe belongs to the closed gate.
func (p Probe) Valid() bool {
	return p >= ProbeSQLiteIntegrity && p <= ProbeDefaultEgressDenied
}

// Status is a closed probe outcome.
type Status uint8

const (
	// StatusUnknown is the invalid zero value.
	StatusUnknown Status = iota
	// StatusPassed records independently verified success.
	StatusPassed
	// StatusFailed records an observed readiness failure.
	StatusFailed
)

// ResultInput is copied into one immutable evidence result.
type ResultInput struct {
	Probe          Probe
	Status         Status
	OperationID    install.OperationID
	PlanDigest     install.PlanDigest
	ReleaseID      string
	GenerationID   string
	ManifestDigest install.Digest
	ComposeDigest  install.Digest
	EvidenceDigest install.Digest
	ObservedAt     time.Time
}

// Result is one independently evidenced, release/generation-bound probe.
type Result struct {
	probe          Probe
	status         Status
	operationID    install.OperationID
	planDigest     install.PlanDigest
	releaseID      string
	generationID   string
	manifestDigest install.Digest
	composeDigest  install.Digest
	evidenceDigest install.Digest
	observedAt     time.Time
}

// NewResult rejects unbound, timeless, or synthetic readiness evidence.
func NewResult(input ResultInput) (Result, error) {
	if !input.Probe.Valid() || (input.Status != StatusPassed && input.Status != StatusFailed) ||
		input.OperationID.IsZero() || input.PlanDigest.IsZero() ||
		!validBinding(input.ReleaseID) || !validUUIDv7(input.GenerationID) ||
		input.ManifestDigest.IsZero() || input.ComposeDigest.IsZero() || input.EvidenceDigest.IsZero() ||
		input.ObservedAt.IsZero() {
		return Result{}, errors.New("readiness probe result is invalid")
	}
	return Result{
		probe:          input.Probe,
		status:         input.Status,
		operationID:    input.OperationID,
		planDigest:     input.PlanDigest,
		releaseID:      input.ReleaseID,
		generationID:   input.GenerationID,
		manifestDigest: input.ManifestDigest,
		composeDigest:  input.ComposeDigest,
		evidenceDigest: input.EvidenceDigest,
		observedAt:     input.ObservedAt.UTC().Truncate(time.Microsecond),
	}, nil
}

// Probe returns the closed check identity.
func (r Result) Probe() Probe { return r.probe }

// Status returns the verified check outcome.
func (r Result) Status() Status { return r.status }

// OperationID returns the installation operation binding.
func (r Result) OperationID() install.OperationID { return r.operationID }

// PlanDigest returns the installation plan binding.
func (r Result) PlanDigest() install.PlanDigest { return r.planDigest }

// ReleaseID returns the signed release identity.
func (r Result) ReleaseID() string { return r.releaseID }

// GenerationID returns the UUIDv7 data-generation binding.
func (r Result) GenerationID() string { return r.generationID }

// ManifestDigest returns the signed release-manifest binding.
func (r Result) ManifestDigest() install.Digest { return r.manifestDigest }

// ComposeDigest returns the exact normalized Compose binding.
func (r Result) ComposeDigest() install.Digest { return r.composeDigest }

// EvidenceDigest returns the probe-specific evidence binding.
func (r Result) EvidenceDigest() install.Digest { return r.evidenceDigest }

// ObservedAt returns the normalized evidence time.
func (r Result) ObservedAt() time.Time { return r.observedAt }

func validBinding(value string) bool {
	if value == "" || len(value) > maximumBindingLength || value != strings.TrimSpace(value) {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '_' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
