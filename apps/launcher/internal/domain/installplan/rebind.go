package installplan

import (
	"encoding/json"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// RebindInput contains only per-installation facts that cannot be signed into
// one redistributable release template.
type RebindInput struct {
	OperationID        install.OperationID
	InstallationID     string
	GenerationID       string
	RuntimeEndpoint    string
	SecurityEpoch      uint64
	HostStorageTarget  string
	Product            ProductInput
	Capacity           CapacityInput
	AgentConfiguration AgentConfigurationInput
}

// RebindV1 creates a per-host canonical authority while preserving every
// release-signed policy, artifact, source, total, and trust envelope from the
// verified template. Runtime ownership deliberately starts undetermined and is
// resolved once from authenticated EnsureContainerRuntime evidence.
func RebindV1(template Plan, input RebindInput) (Plan, error) {
	if template.Digest().IsZero() || len(template.CanonicalBytes()) == 0 {
		return Plan{}, ErrIntegrity
	}
	var document canonicalPlan
	if err := json.Unmarshal(template.CanonicalBytes(), &document); err != nil {
		return Plan{}, ErrIntegrity
	}
	base, err := inputFromDocument(document)
	if err != nil {
		return Plan{}, ErrIntegrity
	}
	base.OperationID = input.OperationID
	base.InstallationID = input.InstallationID
	base.GenerationID = input.GenerationID
	base.RuntimeEndpoint = input.RuntimeEndpoint
	base.RuntimeOwnership = install.RuntimeOwnershipUndetermined
	base.SecurityEpoch = input.SecurityEpoch
	base.HostStorageTarget = input.HostStorageTarget
	base.Product = input.Product
	base.Artifacts.Capacity = input.Capacity
	base.AgentConfiguration = input.AgentConfiguration
	return NewV1(base)
}
