package activereleaseapp

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Command binds activation to one persisted readiness proof and one signed,
// monotonic release/resource state. ActivatedAt is supplied by the Clock.
type Command struct {
	OperationID              install.OperationID
	PlanDigest               install.PlanDigest
	InstallationID           string
	ReleaseID                string
	GenerationID             string
	ManifestDigest           install.Digest
	ComposeDigest            install.Digest
	ReadinessReceiptDigest   install.Digest
	RuntimeEndpoint          string
	ReleaseSequence          uint64
	ResourceInventoryVersion uint64
	ResourceInventoryDigest  install.Digest
	SecurityEpoch            uint64
}

// Status is the closed activation result vocabulary.
type Status uint8

const (
	// StatusUnknown is the invalid zero value.
	StatusUnknown Status = iota
	// StatusCommitted means both host and Core durably match the target.
	StatusCommitted
)

// Result is safe for the PF-001 phase adapter and contains no raw diagnostics.
type Result struct {
	Status        Status
	AlreadyActive bool
	PointerDigest install.Digest
}
