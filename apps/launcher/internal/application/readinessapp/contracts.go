package readinessapp

import (
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

// Command binds one readiness evaluation to the current PF-001 operation.
type Command struct {
	OperationID    install.OperationID
	PlanDigest     install.PlanDigest
	ReleaseID      string
	GenerationID   string
	ManifestDigest install.Digest
	ComposeDigest  install.Digest
	// CoreEndpoint and APICredentialPath are used only by the production
	// remote-Core readiness adapter. In-process probe applications deliberately
	// ignore both protected transport references.
	CoreEndpoint      string
	APICredentialPath string
}

// ProbeRequest is immutable and contains no credential, path, or content.
type ProbeRequest struct {
	operationID    install.OperationID
	planDigest     install.PlanDigest
	releaseID      string
	generationID   string
	manifestDigest install.Digest
	composeDigest  install.Digest
	startedAt      time.Time
}

func newProbeRequest(command Command, startedAt time.Time) ProbeRequest {
	return ProbeRequest{
		operationID:    command.OperationID,
		planDigest:     command.PlanDigest,
		releaseID:      command.ReleaseID,
		generationID:   command.GenerationID,
		manifestDigest: command.ManifestDigest,
		composeDigest:  command.ComposeDigest,
		startedAt:      startedAt,
	}
}

// OperationID returns the installation operation binding.
func (r ProbeRequest) OperationID() install.OperationID { return r.operationID }

// PlanDigest returns the installation plan binding.
func (r ProbeRequest) PlanDigest() install.PlanDigest { return r.planDigest }

// ReleaseID returns the verified release identity.
func (r ProbeRequest) ReleaseID() string { return r.releaseID }

// GenerationID returns the UUIDv7 data-generation identity.
func (r ProbeRequest) GenerationID() string { return r.generationID }

// ManifestDigest returns the signed release-manifest binding.
func (r ProbeRequest) ManifestDigest() install.Digest { return r.manifestDigest }

// ComposeDigest returns the exact normalized Compose binding.
func (r ProbeRequest) ComposeDigest() install.Digest { return r.composeDigest }

// StartedAt returns the normalized evaluation start time.
func (r ProbeRequest) StartedAt() time.Time { return r.startedAt }

// Verification returns either one complete receipt or deterministic failures.
type Verification struct {
	ready    bool
	receipt  readiness.Receipt
	failures []readiness.Failure
}

// NewReadyVerification creates a valid successful value for an outer
// application adapter or contract double.
func NewReadyVerification(receipt readiness.Receipt) Verification {
	if receipt.IsZero() {
		return Verification{}
	}
	return Verification{ready: true, receipt: receipt}
}

// NewNotReadyVerification creates a defensive-copy negative gate value.
func NewNotReadyVerification(failures []readiness.Failure) Verification {
	if len(failures) == 0 {
		return Verification{}
	}
	return Verification{failures: append([]readiness.Failure(nil), failures...)}
}

// Ready reports whether every readiness gate passed and was persisted.
func (v Verification) Ready() bool { return v.ready }

// Receipt returns the complete proof or the zero value when not ready.
func (v Verification) Receipt() readiness.Receipt { return v.receipt }

// Failures returns a caller-owned copy of privacy-safe gate failures.
func (v Verification) Failures() []readiness.Failure {
	return append([]readiness.Failure(nil), v.failures...)
}
