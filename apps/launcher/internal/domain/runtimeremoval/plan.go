// Package runtimeremoval defines the fail-closed, separately consented
// lifecycle for removing a container runtime previously provisioned by
// AgentMemory. It has no host, process, persistence, or UI capabilities.
package runtimeremoval

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	planSchemaVersion = uint16(1)
	// ImpactConfirmation is the Desktop-specific destructive impact retained as
	// the original public name for schema-v1 compatibility.
	ImpactConfirmation = "remove-managed-runtime-and-local-runtime-data"
	// ImpactPreserveLocalRuntimeData is the Linux Engine package-removal impact;
	// package removal intentionally retains Docker and containerd data roots.
	ImpactPreserveLocalRuntimeData = "remove-managed-runtime-software-preserve-local-runtime-data"
)

// DependencyKind is the closed exhaustive dependency-scan vocabulary.
type DependencyKind uint8

const (
	// DependencyUnknown is the invalid zero category.
	DependencyUnknown DependencyKind = iota
	// DependencyContainers represents every container at the exact endpoint.
	DependencyContainers
	// DependencyImages represents every local image at the exact endpoint.
	DependencyImages
	// DependencyVolumes represents every local volume at the exact endpoint.
	DependencyVolumes
	// DependencyNetworks represents every non-built-in network at the endpoint.
	DependencyNetworks
	// DependencyContexts represents non-default contexts bound to the endpoint.
	DependencyContexts
	// DependencyComposeProjects represents every Compose project at the endpoint.
	DependencyComposeProjects
	// DependencyActiveClients represents native socket/pipe client connections.
	DependencyActiveClients
)

var orderedDependencies = [...]DependencyKind{
	DependencyContainers,
	DependencyImages,
	DependencyVolumes,
	DependencyNetworks,
	DependencyContexts,
	DependencyComposeProjects,
	DependencyActiveClients,
}

// OrderedDependencyKinds returns the mandatory scan categories.
func OrderedDependencyKinds() []DependencyKind {
	return append([]DependencyKind(nil), orderedDependencies[:]...)
}

func (k DependencyKind) String() string {
	switch k {
	case DependencyContainers:
		return "containers"
	case DependencyImages:
		return "images"
	case DependencyVolumes:
		return "volumes"
	case DependencyNetworks:
		return "networks"
	case DependencyContexts:
		return "contexts"
	case DependencyComposeProjects:
		return "compose_projects"
	case DependencyActiveClients:
		return "active_clients"
	case DependencyUnknown:
	}
	return "unknown"
}

// DependencyProofInput is a bounded, privacy-safe scan result. Count is the
// number of dependencies that would be destroyed or disconnected by removal;
// EvidenceDigest binds the complete native/CLI observation.
type DependencyProofInput struct {
	Kind           DependencyKind
	Count          uint64
	EvidenceDigest runtimeinstall.Hash
	Complete       bool
}

// DependencyProof is an immutable validated category result.
type DependencyProof struct{ input DependencyProofInput }

func newDependencyProof(input DependencyProofInput) (DependencyProof, error) {
	if !slices.Contains(orderedDependencies[:], input.Kind) || input.EvidenceDigest.IsZero() || !input.Complete {
		return DependencyProof{}, errors.New("runtime dependency proof is incomplete")
	}
	return DependencyProof{input: input}, nil
}

// Kind returns the closed scan category.
func (p DependencyProof) Kind() DependencyKind { return p.input.Kind }

// Count returns the exact number of removal dependencies.
func (p DependencyProof) Count() uint64 { return p.input.Count }

// EvidenceDigest returns the complete category observation digest.
func (p DependencyProof) EvidenceDigest() runtimeinstall.Hash { return p.input.EvidenceDigest }

// DependencyScanInput binds an exhaustive scan to one ownership record and endpoint.
type DependencyScanInput struct {
	OwnershipRecordDigest runtimeinstall.Hash
	Endpoint              string
	Proofs                []DependencyProofInput
}

// DependencyScan is an exhaustive immutable dependency observation.
type DependencyScan struct {
	ownershipRecordDigest runtimeinstall.Hash
	endpoint              string
	proofs                []DependencyProof
	digest                runtimeinstall.Hash
}

// NewDependencyScan rejects missing, duplicate, reordered, or uncertain categories.
func NewDependencyScan(input DependencyScanInput) (DependencyScan, error) {
	if input.OwnershipRecordDigest.IsZero() || !safeText(input.Endpoint, 2048) ||
		len(input.Proofs) != len(orderedDependencies) {
		return DependencyScan{}, errors.New("runtime dependency scan is incomplete")
	}
	proofs := make([]DependencyProof, 0, len(input.Proofs))
	for index, raw := range input.Proofs {
		if raw.Kind != orderedDependencies[index] {
			return DependencyScan{}, errors.New("runtime dependency scan order is invalid")
		}
		proof, err := newDependencyProof(raw)
		if err != nil {
			return DependencyScan{}, err
		}
		proofs = append(proofs, proof)
	}
	scan := DependencyScan{
		ownershipRecordDigest: input.OwnershipRecordDigest,
		endpoint:              input.Endpoint,
		proofs:                proofs,
	}
	scan.digest = scan.computeDigest()
	if scan.digest.IsZero() {
		return DependencyScan{}, errors.New("runtime dependency scan digest is unavailable")
	}
	return scan, nil
}

// OwnershipRecordDigest returns the exact protected ownership binding.
func (s DependencyScan) OwnershipRecordDigest() runtimeinstall.Hash { return s.ownershipRecordDigest }

// Endpoint returns the explicitly addressed local runtime endpoint.
func (s DependencyScan) Endpoint() string { return s.endpoint }

// Proofs returns an immutable-by-copy category set.
func (s DependencyScan) Proofs() []DependencyProof {
	return append([]DependencyProof(nil), s.proofs...)
}

// Digest returns the canonical exhaustive-scan digest.
func (s DependencyScan) Digest() runtimeinstall.Hash { return s.digest }

// SafeToRemove reports true only when every mandatory category is complete and empty.
func (s DependencyScan) SafeToRemove() bool {
	if len(s.proofs) != len(orderedDependencies) || s.digest.IsZero() || s.digest != s.computeDigest() {
		return false
	}
	for index, proof := range s.proofs {
		if proof.Kind() != orderedDependencies[index] || proof.Count() != 0 || proof.EvidenceDigest().IsZero() {
			return false
		}
	}
	return true
}

func (s DependencyScan) computeDigest() runtimeinstall.Hash {
	document := struct {
		Schema    string                `json:"schema"`
		Ownership string                `json:"ownership"`
		Endpoint  string                `json:"endpoint"`
		Proofs    []dependencyProofJSON `json:"proofs"`
	}{
		Schema: "agentmemory.runtime-dependency-scan.v1", Ownership: s.ownershipRecordDigest.String(),
		Endpoint: s.endpoint, Proofs: make([]dependencyProofJSON, 0, len(s.proofs)),
	}
	for _, proof := range s.proofs {
		document.Proofs = append(document.Proofs, dependencyProofJSON{
			Kind: proof.Kind().String(), Count: proof.Count(), Evidence: proof.EvidenceDigest().String(), Complete: true,
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}
	}
	return sha256.Sum256(encoded)
}

type dependencyProofJSON struct {
	Kind     string `json:"kind"`
	Count    uint64 `json:"count"`
	Evidence string `json:"evidence"`
	Complete bool   `json:"complete"`
}

// Plan is the immutable second-operation authority displayed for consent.
type Plan struct {
	operationID          install.OperationID
	sourceOperationID    string
	canonicalRuntimePlan []byte
	runtimePlanDigest    runtimeinstall.Hash
	ownershipDigest      runtimeinstall.Hash
	scanDigest           runtimeinstall.Hash
	platform             runtimeinstall.Platform
	product              string
	version              string
	endpoint             string
	artifactDigest       runtimeinstall.Hash
	digest               runtimeinstall.Hash
}

// PlanSnapshot is the strict persistence projection of one separately
// consented removal authority. The runtime plan bytes are retained so crash
// recovery never has to rebuild authority from mutable host observations.
type PlanSnapshot struct {
	SchemaVersion        uint16                  `json:"schema_version"`
	OperationID          string                  `json:"operation_id"`
	SourceOperationID    string                  `json:"source_operation_id"`
	CanonicalRuntimePlan []byte                  `json:"canonical_runtime_plan"`
	RuntimePlanDigest    runtimeinstall.Hash     `json:"runtime_plan_digest"`
	OwnershipDigest      runtimeinstall.Hash     `json:"ownership_digest"`
	ScanDigest           runtimeinstall.Hash     `json:"scan_digest"`
	Platform             runtimeinstall.Platform `json:"platform"`
	Product              string                  `json:"product"`
	Version              string                  `json:"version"`
	Endpoint             string                  `json:"endpoint"`
	ArtifactDigest       runtimeinstall.Hash     `json:"artifact_digest"`
	Digest               runtimeinstall.Hash     `json:"digest"`
}

// NewPlan accepts only a finalized AgentMemory-provisioned runtime and an
// exhaustive empty scan bound to the same exact endpoint.
func NewPlan(
	operationID install.OperationID,
	canonicalRuntimePlan []byte,
	ownership runtimeinstall.RuntimeOwnershipRecord,
	scan DependencyScan,
) (Plan, error) {
	runtimePlan, err := runtimeinstall.DecodePlanV1(canonicalRuntimePlan)
	if operationID.IsZero() || err != nil || ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownership.OperationState() != runtimeinstall.OperationStateReady ||
		ownership.Disposition() != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		ownership.PlanDigest() != runtimePlan.Digest() || ownership.Digest().IsZero() ||
		scan.OwnershipRecordDigest() != ownership.Digest() || scan.Endpoint() != ownership.Endpoint() ||
		!scan.SafeToRemove() || runtimePlan.Product() != ownership.Vendor() ||
		runtimePlan.Version() != ownership.Version() || runtimePlan.Channel() != ownership.Channel() ||
		(runtimePlan.Platform() != runtimeinstall.PlatformLinux && runtimePlan.Platform() != runtimeinstall.PlatformDarwin &&
			runtimePlan.Platform() != runtimeinstall.PlatformWindows) {
		return Plan{}, errors.New("managed runtime removal plan is not authorized")
	}
	plan := Plan{
		operationID: operationID, sourceOperationID: ownership.OperationID(),
		canonicalRuntimePlan: runtimePlan.CanonicalBytes(), runtimePlanDigest: runtimePlan.Digest(),
		ownershipDigest: ownership.Digest(), scanDigest: scan.Digest(), platform: runtimePlan.Platform(),
		product: ownership.Vendor(), version: ownership.Version(), endpoint: ownership.Endpoint(),
		artifactDigest: ownership.ArtifactDigest(),
	}
	plan.digest = plan.computeDigest()
	if plan.digest.IsZero() {
		return Plan{}, errors.New("managed runtime removal plan digest is unavailable")
	}
	return plan, nil
}

// OperationID returns the distinct destructive-operation identity.
func (p Plan) OperationID() install.OperationID { return p.operationID }

// SourceOperationID returns the runtime installation operation being removed.
func (p Plan) SourceOperationID() string { return p.sourceOperationID }

// CanonicalRuntimePlan returns caller-owned original provisioning authority.
func (p Plan) CanonicalRuntimePlan() []byte { return append([]byte(nil), p.canonicalRuntimePlan...) }

// RuntimePlanDigest returns the original PF-006 plan binding.
func (p Plan) RuntimePlanDigest() runtimeinstall.Hash { return p.runtimePlanDigest }

// OwnershipRecordDigest returns the finalized protected ownership binding.
func (p Plan) OwnershipRecordDigest() runtimeinstall.Hash { return p.ownershipDigest }

// ScanDigest returns the first exhaustive empty dependency scan.
func (p Plan) ScanDigest() runtimeinstall.Hash { return p.scanDigest }

// Platform selects the closed native removal adapter.
func (p Plan) Platform() runtimeinstall.Platform { return p.platform }

// Product returns the signed runtime product.
func (p Plan) Product() string { return p.product }

// Version returns the signed runtime version.
func (p Plan) Version() string { return p.version }

// Endpoint returns the explicit local endpoint.
func (p Plan) Endpoint() string { return p.endpoint }

// ArtifactDigest returns the signed installed runtime artifact/package-set identity.
func (p Plan) ArtifactDigest() runtimeinstall.Hash { return p.artifactDigest }

// ImpactConfirmation returns the mandatory destructive-impact statement ID.
func (p Plan) ImpactConfirmation() string {
	if p.platform == runtimeinstall.PlatformLinux {
		return ImpactPreserveLocalRuntimeData
	}
	return ImpactConfirmation
}

// Digest returns the complete separate removal-plan binding.
func (p Plan) Digest() runtimeinstall.Hash { return p.digest }

// Snapshot returns an immutable-by-copy persistence projection.
func (p Plan) Snapshot() PlanSnapshot {
	return PlanSnapshot{
		SchemaVersion: planSchemaVersion, OperationID: p.operationID.String(),
		SourceOperationID: p.sourceOperationID, CanonicalRuntimePlan: p.CanonicalRuntimePlan(),
		RuntimePlanDigest: p.runtimePlanDigest, OwnershipDigest: p.ownershipDigest,
		ScanDigest: p.scanDigest, Platform: p.platform, Product: p.product, Version: p.version,
		Endpoint: p.endpoint, ArtifactDigest: p.artifactDigest, Digest: p.digest,
	}
}

// RestorePlan rejects non-canonical or internally inconsistent persisted
// authority. It intentionally needs no live host observation.
func RestorePlan(snapshot PlanSnapshot) (Plan, error) {
	operationID, err := install.NewOperationID(snapshot.OperationID)
	if err != nil || snapshot.SchemaVersion != planSchemaVersion {
		return Plan{}, errors.New("managed runtime removal plan snapshot identity is invalid")
	}
	plan := Plan{
		operationID: operationID, sourceOperationID: snapshot.SourceOperationID,
		canonicalRuntimePlan: append([]byte(nil), snapshot.CanonicalRuntimePlan...),
		runtimePlanDigest:    snapshot.RuntimePlanDigest, ownershipDigest: snapshot.OwnershipDigest,
		scanDigest: snapshot.ScanDigest, platform: snapshot.Platform, product: snapshot.Product,
		version: snapshot.Version, endpoint: snapshot.Endpoint, artifactDigest: snapshot.ArtifactDigest,
		digest: snapshot.Digest,
	}
	if !plan.Valid() {
		return Plan{}, errors.New("managed runtime removal plan snapshot is invalid")
	}
	return plan, nil
}

// Valid revalidates canonical bytes and every immutable digest.
func (p Plan) Valid() bool {
	runtimePlan, err := runtimeinstall.DecodePlanV1(p.canonicalRuntimePlan)
	sourceOperationID, sourceError := install.NewOperationID(p.sourceOperationID)
	return err == nil && !p.operationID.IsZero() && p.sourceOperationID != "" &&
		sourceError == nil && sourceOperationID != p.operationID &&
		runtimePlan.Digest() == p.runtimePlanDigest && runtimePlan.Platform() == p.platform &&
		runtimePlan.Product() == p.product && runtimePlan.Version() == p.version &&
		!p.ownershipDigest.IsZero() && !p.scanDigest.IsZero() && !p.artifactDigest.IsZero() &&
		safeText(p.endpoint, 2048) && p.digest == p.computeDigest() && !p.digest.IsZero()
}

func (p Plan) computeDigest() runtimeinstall.Hash {
	document := struct {
		Schema          uint16 `json:"schema_version"`
		Operation       string `json:"operation_id"`
		SourceOperation string `json:"source_operation_id"`
		RuntimePlan     string `json:"runtime_plan_digest"`
		Ownership       string `json:"ownership_record_digest"`
		Scan            string `json:"scan_digest"`
		Platform        string `json:"platform"`
		Product         string `json:"product"`
		Version         string `json:"version"`
		Endpoint        string `json:"endpoint"`
		Artifact        string `json:"artifact_digest"`
		Impact          string `json:"impact_confirmation"`
	}{
		Schema: planSchemaVersion, Operation: p.operationID.String(), SourceOperation: p.sourceOperationID,
		RuntimePlan: p.runtimePlanDigest.String(), Ownership: p.ownershipDigest.String(), Scan: p.scanDigest.String(),
		Platform: p.platform.String(), Product: p.product, Version: p.version, Endpoint: p.endpoint,
		Artifact: p.artifactDigest.String(), Impact: p.ImpactConfirmation(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}
	}
	return sha256.Sum256(encoded)
}

func safeText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}
