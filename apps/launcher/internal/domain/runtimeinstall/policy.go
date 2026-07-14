// Package runtimeinstall contains the platform-neutral policy and state for
// PF-001/PF-006 container-runtime provisioning.
package runtimeinstall

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	minimumCPU             = uint16(4)
	minimumTotalMemory     = uint64(16 * 1024 * 1024 * 1024)
	minimumAvailableMemory = uint64(12 * 1024 * 1024 * 1024)
	minimumFreeDisk        = uint64(30 * 1024 * 1024 * 1024)
)

// Hash is a SHA-256 binding used for plans, catalogs, terms, and artifacts.
type Hash [sha256.Size]byte

// Sum hashes canonical bytes.
func Sum(value []byte) Hash { return sha256.Sum256(value) }

// IsZero reports whether the binding is absent.
func (h Hash) IsZero() bool { return h == Hash{} }

// Platform is a closed certified operating-system family.
type Platform uint8

const (
	// PlatformUnknown is the invalid zero value.
	PlatformUnknown Platform = iota
	// PlatformDarwin identifies a certified macOS host.
	PlatformDarwin
	// PlatformLinux identifies a certified Linux host.
	PlatformLinux
	// PlatformWindows identifies a certified Windows host.
	PlatformWindows
)

func (p Platform) String() string {
	switch p {
	case PlatformDarwin:
		return "darwin"
	case PlatformLinux:
		return "linux"
	case PlatformWindows:
		return "windows"
	case PlatformUnknown:
	}
	return "unknown"
}

// Architecture is a closed certified machine architecture.
type Architecture uint8

const (
	// ArchitectureUnknown is the invalid zero value.
	ArchitectureUnknown Architecture = iota
	// ArchitectureAMD64 identifies x86-64.
	ArchitectureAMD64
	// ArchitectureARM64 identifies AArch64.
	ArchitectureARM64
)

func (a Architecture) String() string {
	switch a {
	case ArchitectureAMD64:
		return "amd64"
	case ArchitectureARM64:
		return "arm64"
	case ArchitectureUnknown:
	}
	return "unknown"
}

// HostCapabilities contains only independently probed, non-secret host facts.
type HostCapabilities struct {
	platform         Platform
	architecture     Architecture
	osVersion        string
	certified        bool
	virtualization   bool
	localFilesystem  bool
	atRestEncryption bool
	cpus             uint16
	totalMemory      uint64
	availableMemory  uint64
	freeDisk         uint64
}

// NewHostCapabilities validates a read-only host probe result.
func NewHostCapabilities(
	platform Platform,
	architecture Architecture,
	osVersion string,
	certified bool,
	virtualization bool,
	localFilesystem bool,
	atRestEncryption bool,
	cpus uint16,
	totalMemory uint64,
	availableMemory uint64,
	freeDisk uint64,
) (HostCapabilities, error) {
	if platform == PlatformUnknown || architecture == ArchitectureUnknown {
		return HostCapabilities{}, errors.New("host platform and architecture are required")
	}
	if strings.TrimSpace(osVersion) == "" || strings.TrimSpace(osVersion) != osVersion || len(osVersion) > 128 {
		return HostCapabilities{}, errors.New("host OS version is required")
	}
	if cpus == 0 || totalMemory == 0 || availableMemory > totalMemory {
		return HostCapabilities{}, errors.New("host resource facts are invalid")
	}
	return HostCapabilities{
		platform:         platform,
		architecture:     architecture,
		osVersion:        osVersion,
		certified:        certified,
		virtualization:   virtualization,
		localFilesystem:  localFilesystem,
		atRestEncryption: atRestEncryption,
		cpus:             cpus,
		totalMemory:      totalMemory,
		availableMemory:  availableMemory,
		freeDisk:         freeDisk,
	}, nil
}

// Platform returns the probed operating-system family.
func (h HostCapabilities) Platform() Platform { return h.platform }

// Architecture returns the probed machine architecture.
func (h HostCapabilities) Architecture() Architecture { return h.architecture }

// OSVersion returns the bounded non-secret OS release string.
func (h HostCapabilities) OSVersion() string { return h.osVersion }

// RuntimeCondition is the observed local runtime state.
type RuntimeCondition uint8

const (
	// RuntimeConditionUnknown is the invalid zero value.
	RuntimeConditionUnknown RuntimeCondition = iota
	// RuntimeConditionAbsent means no candidate local runtime exists.
	RuntimeConditionAbsent
	// RuntimeConditionRunning means a candidate daemon is running.
	RuntimeConditionRunning
	// RuntimeConditionStopped means a compatible candidate is stopped.
	RuntimeConditionStopped
	// RuntimeConditionIncompatible means a local candidate fails compatibility.
	RuntimeConditionIncompatible
	// RuntimeConditionDamaged means an owned runtime requires repair.
	RuntimeConditionDamaged
)

// OwnershipDisposition records whether AgentMemory may repair runtime state.
type OwnershipDisposition uint8

const (
	// OwnershipUnknown is the invalid zero value.
	OwnershipUnknown OwnershipDisposition = iota
	// OwnershipReusedExternal preserves a pre-existing runtime.
	OwnershipReusedExternal
	// OwnershipProvisionedByAgentMemory permits only recorded managed repairs.
	OwnershipProvisionedByAgentMemory
)

// RuntimeDiscovery is a capability-based observation, never a PATH-only guess.
type RuntimeDiscovery struct {
	condition            RuntimeCondition
	product              string
	version              string
	endpoint             string
	localEndpoint        bool
	publisherVerified    bool
	capabilitiesVerified bool
	ownership            OwnershipDisposition
	unrelatedWorkloads   uint32
}

// NewAbsentRuntimeDiscovery creates the only valid empty discovery.
func NewAbsentRuntimeDiscovery() RuntimeDiscovery {
	return RuntimeDiscovery{condition: RuntimeConditionAbsent}
}

// NewRuntimeDiscovery validates a concrete runtime observation.
func NewRuntimeDiscovery(
	condition RuntimeCondition,
	product string,
	version string,
	endpoint string,
	localEndpoint bool,
	publisherVerified bool,
	capabilitiesVerified bool,
	ownership OwnershipDisposition,
	unrelatedWorkloads uint32,
) (RuntimeDiscovery, error) {
	if condition == RuntimeConditionUnknown || condition == RuntimeConditionAbsent {
		return RuntimeDiscovery{}, errors.New("concrete runtime condition is required")
	}
	if strings.TrimSpace(product) == "" || strings.TrimSpace(product) != product ||
		strings.TrimSpace(version) == "" || strings.TrimSpace(version) != version ||
		strings.TrimSpace(endpoint) == "" || strings.TrimSpace(endpoint) != endpoint {
		return RuntimeDiscovery{}, errors.New("runtime product, version, and endpoint are required")
	}
	if len(product) > 128 || len(version) > 128 || len(endpoint) > 2048 {
		return RuntimeDiscovery{}, errors.New("runtime discovery field exceeds its limit")
	}
	if ownership == OwnershipUnknown {
		return RuntimeDiscovery{}, errors.New("runtime ownership is required")
	}
	return RuntimeDiscovery{
		condition:            condition,
		product:              product,
		version:              version,
		endpoint:             endpoint,
		localEndpoint:        localEndpoint,
		publisherVerified:    publisherVerified,
		capabilitiesVerified: capabilitiesVerified,
		ownership:            ownership,
		unrelatedWorkloads:   unrelatedWorkloads,
	}, nil
}

// CertifiedRuntime is one already signature-verified catalog selection.
type CertifiedRuntime struct {
	platform        Platform
	architecture    Architecture
	product         string
	version         string
	channel         string
	catalogSequence uint64
	catalogDigest   Hash
	termsDigest     Hash
	downloadBytes   uint64
	expandedBytes   uint64
}

// NewCertifiedRuntime validates an immutable signed-catalog selection.
func NewCertifiedRuntime(
	platform Platform,
	architecture Architecture,
	product string,
	version string,
	channel string,
	catalogSequence uint64,
	catalogDigest Hash,
	termsDigest Hash,
	downloadBytes uint64,
	expandedBytes uint64,
) (CertifiedRuntime, error) {
	if platform == PlatformUnknown || architecture == ArchitectureUnknown {
		return CertifiedRuntime{}, errors.New("catalog platform and architecture are required")
	}
	if strings.TrimSpace(product) == "" || strings.TrimSpace(product) != product ||
		strings.TrimSpace(version) == "" || strings.TrimSpace(version) != version || channel != "stable" {
		return CertifiedRuntime{}, errors.New("catalog requires a product, exact version, and stable channel")
	}
	if catalogSequence == 0 || catalogDigest.IsZero() || termsDigest.IsZero() {
		return CertifiedRuntime{}, errors.New("catalog sequence and trust digests are required")
	}
	if downloadBytes == 0 || expandedBytes < downloadBytes {
		return CertifiedRuntime{}, errors.New("catalog size bounds are invalid")
	}
	return CertifiedRuntime{
		platform:        platform,
		architecture:    architecture,
		product:         product,
		version:         version,
		channel:         channel,
		catalogSequence: catalogSequence,
		catalogDigest:   catalogDigest,
		termsDigest:     termsDigest,
		downloadBytes:   downloadBytes,
		expandedBytes:   expandedBytes,
	}, nil
}

// Platform returns the catalog target OS.
func (c CertifiedRuntime) Platform() Platform { return c.platform }

// Architecture returns the catalog target CPU architecture.
func (c CertifiedRuntime) Architecture() Architecture { return c.architecture }

// CatalogSequence returns the anti-rollback sequence.
func (c CertifiedRuntime) CatalogSequence() uint64 { return c.catalogSequence }

// CatalogDigest returns the exact signature-verified catalog manifest binding.
func (c CertifiedRuntime) CatalogDigest() Hash { return c.catalogDigest }

// TermsDigest returns the exact third-party terms binding.
func (c CertifiedRuntime) TermsDigest() Hash { return c.termsDigest }

// DownloadBytes returns the declared acquisition size.
func (c CertifiedRuntime) DownloadBytes() uint64 { return c.downloadBytes }

// ExpandedBytes returns the declared installed size.
func (c CertifiedRuntime) ExpandedBytes() uint64 { return c.expandedBytes }

// PlanAction is the closed set of runtime mutations available to PF-001.
type PlanAction uint8

const (
	// PlanActionUnknown is the invalid zero value.
	PlanActionUnknown PlanAction = iota
	// PlanActionAdoptCompatible preserves a verified running external runtime.
	PlanActionAdoptCompatible
	// PlanActionStartCompatible starts a verified stopped external runtime.
	PlanActionStartCompatible
	// PlanActionInstallCertified installs the exact signed catalog entry.
	PlanActionInstallCertified
	// PlanActionRepairManaged repairs only recorded AgentMemory-owned state.
	PlanActionRepairManaged
	// PlanActionBlock prohibits runtime mutation.
	PlanActionBlock
)

func (a PlanAction) String() string {
	switch a {
	case PlanActionAdoptCompatible:
		return "adopt_compatible"
	case PlanActionStartCompatible:
		return "start_compatible"
	case PlanActionInstallCertified:
		return "install_certified"
	case PlanActionRepairManaged:
		return "repair_managed"
	case PlanActionBlock:
		return "block"
	case PlanActionUnknown:
	}
	return "unknown"
}

// DecisionCode is safe to translate into one plain-language next action.
type DecisionCode uint8

const (
	// DecisionOK means the selected action satisfies policy.
	DecisionOK DecisionCode = iota
	// DecisionUnsupportedPlatform blocks an uncertified OS tuple.
	DecisionUnsupportedPlatform
	// DecisionVirtualizationUnavailable blocks without virtualization.
	DecisionVirtualizationUnavailable
	// DecisionNonLocalFilesystem blocks unsafe persistence.
	DecisionNonLocalFilesystem
	// DecisionEncryptionUnattested blocks searchable data without at-rest protection.
	DecisionEncryptionUnattested
	// DecisionInsufficientCPU blocks below the certified CPU floor.
	DecisionInsufficientCPU
	// DecisionInsufficientMemory blocks below the certified memory floor.
	DecisionInsufficientMemory
	// DecisionInsufficientDisk blocks below the certified disk floor.
	DecisionInsufficientDisk
	// DecisionRuntimeRemote rejects a daemon that is not proven local.
	DecisionRuntimeRemote
	// DecisionRuntimeUntrusted rejects an unverified runtime publisher/package.
	DecisionRuntimeUntrusted
	// DecisionRuntimeConflict preserves an incompatible external runtime.
	DecisionRuntimeConflict
	// DecisionCatalogMismatch rejects a catalog for another platform tuple.
	DecisionCatalogMismatch
)

func (c DecisionCode) String() string {
	switch c {
	case DecisionOK:
		return "ok"
	case DecisionUnsupportedPlatform:
		return "unsupported_platform"
	case DecisionVirtualizationUnavailable:
		return "virtualization_unavailable"
	case DecisionNonLocalFilesystem:
		return "nonlocal_filesystem"
	case DecisionEncryptionUnattested:
		return "encryption_unattested"
	case DecisionInsufficientCPU:
		return "insufficient_cpu"
	case DecisionInsufficientMemory:
		return "insufficient_memory"
	case DecisionInsufficientDisk:
		return "insufficient_disk"
	case DecisionRuntimeRemote:
		return "runtime_remote"
	case DecisionRuntimeUntrusted:
		return "runtime_untrusted"
	case DecisionRuntimeConflict:
		return "runtime_conflict"
	case DecisionCatalogMismatch:
		return "catalog_mismatch"
	}
	return "unknown"
}

// Plan is a deterministic, exact-catalog-bound runtime decision.
type Plan struct {
	action       PlanAction
	decisionCode DecisionCode
	digest       Hash
	canonical    []byte
	catalogHash  Hash
}

// Action returns the closed mutation decision.
func (p Plan) Action() PlanAction { return p.action }

// DecisionCode returns the privacy-safe policy explanation.
func (p Plan) DecisionCode() DecisionCode { return p.decisionCode }

// Digest returns the binding over every material plan input.
func (p Plan) Digest() Hash { return p.digest }

// CanonicalBytes returns caller-owned strict schema-v1 execution authority.
// It is empty only for a fail-closed decision produced from invalid zero facts.
func (p Plan) CanonicalBytes() []byte { return append([]byte(nil), p.canonical...) }

// CatalogDigest returns the exact verified catalog bound into the plan.
func (p Plan) CatalogDigest() Hash { return p.catalogHash }

// PlanPolicy chooses a closed action from verified facts.
type PlanPolicy struct{}

// NewPlanPolicy constructs the stateless deterministic policy.
func NewPlanPolicy() PlanPolicy { return PlanPolicy{} }

// Decide fails closed. No caller can override a Block decision by supplying a
// binary name, PATH entry, or version string.
func (PlanPolicy) Decide(
	host HostCapabilities,
	discovery RuntimeDiscovery,
	catalog CertifiedRuntime,
) Plan {
	if plan, err := NewPlanV1(host, discovery, catalog); err == nil {
		return plan
	}
	// Preserve the historical total policy API while failing closed for invalid
	// zero-value facts. Production execution requires non-empty CanonicalBytes.
	action, code := decideRuntimeAction(host, discovery, catalog)
	if action != PlanActionBlock {
		action, code = PlanActionBlock, DecisionUnsupportedPlatform
	}
	return Plan{
		action:       action,
		decisionCode: code,
		digest:       Sum([]byte("agentmemory.invalid-runtime-plan.v1")),
	}
}

func decideRuntimeAction(
	host HostCapabilities,
	discovery RuntimeDiscovery,
	catalog CertifiedRuntime,
) (PlanAction, DecisionCode) {
	switch {
	case !host.certified:
		return PlanActionBlock, DecisionUnsupportedPlatform
	case !host.virtualization:
		return PlanActionBlock, DecisionVirtualizationUnavailable
	case !host.localFilesystem:
		return PlanActionBlock, DecisionNonLocalFilesystem
	case !host.atRestEncryption:
		return PlanActionBlock, DecisionEncryptionUnattested
	case host.cpus < minimumCPU:
		return PlanActionBlock, DecisionInsufficientCPU
	case host.totalMemory < minimumTotalMemory || host.availableMemory < minimumAvailableMemory:
		return PlanActionBlock, DecisionInsufficientMemory
	case host.freeDisk < minimumFreeDisk:
		return PlanActionBlock, DecisionInsufficientDisk
	case host.platform != catalog.platform || host.architecture != catalog.architecture:
		return PlanActionBlock, DecisionCatalogMismatch
	case discovery.condition == RuntimeConditionAbsent:
		return PlanActionInstallCertified, DecisionOK
	case !discovery.localEndpoint:
		return PlanActionBlock, DecisionRuntimeRemote
	case !discovery.publisherVerified:
		return PlanActionBlock, DecisionRuntimeUntrusted
	case discovery.condition == RuntimeConditionRunning && discovery.capabilitiesVerified:
		return PlanActionAdoptCompatible, DecisionOK
	case discovery.condition == RuntimeConditionStopped && discovery.capabilitiesVerified:
		return PlanActionStartCompatible, DecisionOK
	case discovery.condition == RuntimeConditionDamaged && discovery.ownership == OwnershipProvisionedByAgentMemory:
		return PlanActionRepairManaged, DecisionOK
	default:
		return PlanActionBlock, DecisionRuntimeConflict
	}
}

func (h Hash) String() string { return fmt.Sprintf("%x", h[:]) }
