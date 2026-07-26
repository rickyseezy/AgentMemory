// Package provideradapter owns the PRO-002 custom-provider trust and sandbox model.
package provideradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

const (
	// SupportedProtocolMajor is the single protocol major this launcher certifies.
	SupportedProtocolMajor     uint16 = 1
	maximumMemoryBytes                = 8 * 1024 * 1024 * 1024
	maximumCPUsMilli                  = 8000
	maximumPIDs                       = 512
	maximumTimeoutMilliseconds        = 300000
	maximumScratchBytes               = 1024 * 1024 * 1024
)

var (
	adapterIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	imagePattern     = regexp.MustCompile(`^([a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+)@sha256:([0-9a-f]{64})$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// ErrInvalidManifest is intentionally safe and contains no submitted package material.
	ErrInvalidManifest = errors.New("custom provider adapter manifest is invalid")
	// ErrInvalidDeployment is intentionally safe and contains no host/runtime detail.
	ErrInvalidDeployment = errors.New("custom provider adapter deployment is invalid")
)

// Digest is one immutable SHA-256 identity.
type Digest [sha256.Size]byte

// DigestBytes hashes exact bytes.
func DigestBytes(value []byte) Digest { return sha256.Sum256(value) }

// ParseDigest requires canonical lowercase SHA-256 text.
func ParseDigest(value string) (Digest, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
		return Digest{}, ErrInvalidManifest
	}
	var result Digest
	copy(result[:], decoded)
	return result, nil
}

// Hex returns canonical lowercase text.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// IsZero reports an absent digest.
func (d Digest) IsZero() bool { return d == Digest{} }

// Equal compares fixed-size identities.
func (d Digest) Equal(other Digest) bool { return d == other }

// Transport is a closed language-neutral protocol carrier.
type Transport string

const (
	// TransportFramedStdio uses four-byte length-prefixed JSON-RPC over standard I/O.
	TransportFramedStdio Transport = "framed_stdio"
	// TransportAuthenticatedHTTP uses the same schema over authenticated internal HTTP.
	TransportAuthenticatedHTTP Transport = "authenticated_http"
)

// Operation is the closed provider protocol method vocabulary.
type Operation string

const (
	// OperationGetManifest returns the runtime's signed capability manifest.
	OperationGetManifest Operation = "get_manifest"
	// OperationValidateConfiguration validates profile configuration without activation.
	OperationValidateConfiguration Operation = "validate_configuration"
	// OperationProbe returns live model and output-contract evidence.
	OperationProbe Operation = "probe"
	// OperationHealth checks runtime liveness and readiness.
	OperationHealth Operation = "health"
	// OperationListModels lists immutable supported model identities.
	OperationListModels Operation = "list_models"
	// OperationEmbedDocuments produces document-purpose vectors.
	OperationEmbedDocuments Operation = "embed_documents"
	// OperationEmbedQueries produces query-purpose vectors.
	OperationEmbedQueries Operation = "embed_queries"
	// OperationRerank scores ordered candidates.
	OperationRerank Operation = "rerank"
	// OperationEstimateCost estimates provider usage without execution.
	OperationEstimateCost Operation = "estimate_cost"
	// OperationCancel cancels one in-flight operation identity.
	OperationCancel Operation = "cancel"
	// OperationShutdown requests a bounded graceful stop.
	OperationShutdown Operation = "shutdown"
)

var validOperations = map[Operation]struct{}{
	OperationGetManifest: {}, OperationValidateConfiguration: {}, OperationProbe: {},
	OperationHealth: {}, OperationListModels: {}, OperationEmbedDocuments: {},
	OperationEmbedQueries: {}, OperationRerank: {}, OperationEstimateCost: {},
	OperationCancel: {}, OperationShutdown: {},
}

// ProtocolRangeInput is the manifest wire form.
type ProtocolRangeInput struct{ Minimum, Maximum uint16 }

// ProtocolRange is a validated inclusive compatibility range.
type ProtocolRange struct{ minimum, maximum uint16 }

// Minimum returns the inclusive minimum protocol major.
func (p ProtocolRange) Minimum() uint16 { return p.minimum }

// Maximum returns the inclusive maximum protocol major.
func (p ProtocolRange) Maximum() uint16 { return p.maximum }

// PermissionInput is deliberately closed; every dangerous Docker permission is explicit.
type PermissionInput struct {
	GatewayAccess, HostNetwork, PublishPort, DockerSocket, ProjectMount bool
	WritableMount, AdditionalSecrets, DirectEgress, Privileged          bool
}

// LimitInput contains mandatory finite sandbox limits.
type LimitInput struct {
	CPUsMilli, PIDs, TimeoutMilliseconds uint32
	MemoryBytes, ScratchBytes            uint64
}

// EvidenceInput binds every supply-chain decision to exact bytes.
type EvidenceInput struct {
	SignatureBundle, CycloneDXSBOM, SPDXSBOM Digest
	Provenance, License, Vulnerability       Digest
}

func (e EvidenceInput) valid() bool {
	return !e.SignatureBundle.IsZero() && !e.CycloneDXSBOM.IsZero() &&
		!e.SPDXSBOM.IsZero() && !e.Provenance.IsZero() && !e.License.IsZero() &&
		!e.Vulnerability.IsZero()
}

// ManifestInput is untrusted package metadata accepted by the domain constructor.
type ManifestInput struct {
	AdapterID, Image string
	ImageDigest      Digest
	Protocol         ProtocolRangeInput
	Transport        Transport
	Operations       []Operation
	Permissions      PermissionInput
	Limits           LimitInput
	Evidence         EvidenceInput
}

// Manifest is an immutable, digest-addressed custom adapter contract.
type Manifest struct {
	input      ManifestInput
	protocol   ProtocolRange
	operations map[Operation]struct{}
	digest     Digest
}

// NewManifest validates supply-chain completeness, compatibility, and permissions.
func NewManifest(input ManifestInput) (Manifest, error) {
	match := imagePattern.FindStringSubmatch(input.Image)
	if !adapterIDPattern.MatchString(input.AdapterID) || len(match) != 3 ||
		input.ImageDigest.IsZero() || match[2] != input.ImageDigest.Hex() ||
		input.Protocol.Minimum == 0 || input.Protocol.Minimum > input.Protocol.Maximum ||
		input.Protocol.Minimum > SupportedProtocolMajor || input.Protocol.Maximum < SupportedProtocolMajor ||
		(input.Transport != TransportFramedStdio && input.Transport != TransportAuthenticatedHTTP) ||
		!input.Evidence.valid() || !validPermissions(input.Permissions) || !validLimits(input.Limits) {
		return Manifest{}, ErrInvalidManifest
	}
	operations := make(map[Operation]struct{}, len(input.Operations))
	for _, operation := range input.Operations {
		if _, valid := validOperations[operation]; !valid {
			return Manifest{}, ErrInvalidManifest
		}
		if _, duplicate := operations[operation]; duplicate {
			return Manifest{}, ErrInvalidManifest
		}
		operations[operation] = struct{}{}
	}
	for _, required := range []Operation{
		OperationGetManifest, OperationValidateConfiguration, OperationProbe,
		OperationHealth, OperationCancel, OperationShutdown,
	} {
		if _, present := operations[required]; !present {
			return Manifest{}, ErrInvalidManifest
		}
	}
	if _, embedDocuments := operations[OperationEmbedDocuments]; !embedDocuments {
		if _, embedQueries := operations[OperationEmbedQueries]; !embedQueries {
			if _, rerank := operations[OperationRerank]; !rerank {
				return Manifest{}, ErrInvalidManifest
			}
		}
	}
	copyInput := input
	copyInput.Operations = slices.Clone(input.Operations)
	slices.Sort(copyInput.Operations)
	canonical, err := json.Marshal(copyInput)
	if err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	return Manifest{
		input: copyInput, protocol: ProtocolRange{input.Protocol.Minimum, input.Protocol.Maximum},
		operations: operations, digest: DigestBytes(canonical),
	}, nil
}

func validPermissions(value PermissionInput) bool {
	return !value.HostNetwork && !value.PublishPort && !value.DockerSocket &&
		!value.ProjectMount && !value.WritableMount && !value.AdditionalSecrets &&
		!value.DirectEgress && !value.Privileged
}

func validLimits(value LimitInput) bool {
	return value.CPUsMilli > 0 && value.CPUsMilli <= maximumCPUsMilli &&
		value.MemoryBytes >= 64*1024*1024 && value.MemoryBytes <= maximumMemoryBytes &&
		value.PIDs > 0 && value.PIDs <= maximumPIDs && value.TimeoutMilliseconds >= 100 &&
		value.TimeoutMilliseconds <= maximumTimeoutMilliseconds && value.ScratchBytes > 0 &&
		value.ScratchBytes <= maximumScratchBytes
}

// AdapterID returns the validated stable adapter identifier.
func (m Manifest) AdapterID() string { return m.input.AdapterID }

// Image returns the digest-pinned OCI reference.
func (m Manifest) Image() string { return m.input.Image }

// ImageDigest returns the exact OCI descriptor digest.
func (m Manifest) ImageDigest() Digest { return m.input.ImageDigest }

// Digest returns the canonical manifest identity.
func (m Manifest) Digest() Digest { return m.digest }

// Protocol returns the certified compatibility range.
func (m Manifest) Protocol() ProtocolRange { return m.protocol }

// Transport returns the selected closed protocol carrier.
func (m Manifest) Transport() Transport { return m.input.Transport }

// Evidence returns all immutable supply-chain evidence identities.
func (m Manifest) Evidence() EvidenceInput { return m.input.Evidence }

// GatewayAccess reports whether mediated provider egress was requested.
func (m Manifest) GatewayAccess() bool { return m.input.Permissions.GatewayAccess }

// Limits returns the finite requested sandbox resources.
func (m Manifest) Limits() LimitInput { return m.input.Limits }

// Supports reports whether the adapter declared an operation.
func (m Manifest) Supports(value Operation) bool { _, found := m.operations[value]; return found }

// Operations returns a caller-owned stable capability list.
func (m Manifest) Operations() []Operation { return slices.Clone(m.input.Operations) }

// DeploymentPlan generates the only supported custom-adapter container shape.
func (m Manifest) DeploymentPlan(installationID string) (DeploymentPlan, error) {
	if uuidPattern.FindString(installationID) == "" || m.digest.IsZero() {
		return DeploymentPlan{}, ErrInvalidDeployment
	}
	identity, err := composeplan.NewIdentity(installationID, installationID)
	if err != nil {
		return DeploymentPlan{}, ErrInvalidDeployment
	}
	nameDigest := DigestBytes([]byte(installationID + "\x00" + m.AdapterID() + "\x00" + m.digest.Hex()))
	capability := ""
	if m.GatewayAccess() {
		capability = identity.StableVolumeName("provider-adapter-egress")
	}
	input := deploymentPlanDocument{
		Project: identity.ProjectName(), Service: "custom-provider-" + nameDigest.Hex()[:20],
		Image: m.Image(), User: "65532:65532", ReadOnly: true, NoNewPrivileges: true,
		Network: "am_internal", ExternalNetwork: identity.NetworkName("internal"), ScratchTarget: "/tmp",
		ScratchBytes: m.input.Limits.ScratchBytes, CPUsMilli: m.input.Limits.CPUsMilli,
		MemoryBytes: m.input.Limits.MemoryBytes, PIDs: m.input.Limits.PIDs,
		TimeoutMilliseconds: m.input.Limits.TimeoutMilliseconds, CapabilitySecret: capability,
		Transport: m.Transport(), ManifestDigest: m.Digest().Hex(),
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return DeploymentPlan{}, fmt.Errorf("%w", ErrInvalidDeployment)
	}
	return DeploymentPlan{document: input, digest: DigestBytes(canonical)}, nil
}

type deploymentPlanDocument struct {
	Project, Service, Image, User, Network, ExternalNetwork string
	ScratchTarget, CapabilitySecret                         string
	ReadOnly, NoNewPrivileges                               bool
	ScratchBytes, MemoryBytes                               uint64
	CPUsMilli, PIDs, TimeoutMilliseconds                    uint32
	Transport                                               Transport
	ManifestDigest                                          string
}

// DeploymentPlan is immutable and contains no user-supplied Compose document.
type DeploymentPlan struct {
	document deploymentPlanDocument
	digest   Digest
}

// Valid reports whether the plan came from the closed constructor.
func (p DeploymentPlan) Valid() bool { return !p.digest.IsZero() }

// Digest returns the canonical plan identity.
func (p DeploymentPlan) Digest() Digest { return p.digest }

// ProjectName returns the installation-scoped Compose project.
func (p DeploymentPlan) ProjectName() string { return p.document.Project }

// ServiceName returns the digest-derived service name.
func (p DeploymentPlan) ServiceName() string { return p.document.Service }

// Image returns the exact digest-pinned OCI reference.
func (p DeploymentPlan) Image() string { return p.document.Image }

// User returns the fixed non-root UID and GID.
func (p DeploymentPlan) User() string { return p.document.User }

// ReadOnlyRootFS reports the mandatory root filesystem policy.
func (p DeploymentPlan) ReadOnlyRootFS() bool { return p.document.ReadOnly }

// NoNewPrivileges reports the mandatory privilege-escalation policy.
func (p DeploymentPlan) NoNewPrivileges() bool { return p.document.NoNewPrivileges }

// Privileged always reports false because the plan cannot express it.
func (p DeploymentPlan) Privileged() bool { return false }

// HostNetwork always reports false because the plan cannot express it.
func (p DeploymentPlan) HostNetwork() bool { return false }

// PublishPort always reports false because the plan cannot express it.
func (p DeploymentPlan) PublishPort() bool { return false }

// Network returns the sole logical internal network.
func (p DeploymentPlan) Network() string { return p.document.Network }

// ExternalNetwork returns the installation-scoped existing network name.
func (p DeploymentPlan) ExternalNetwork() string { return p.document.ExternalNetwork }

// ScratchTarget returns the only writable filesystem target.
func (p DeploymentPlan) ScratchTarget() string { return p.document.ScratchTarget }

// ScratchBytes returns the tmpfs byte ceiling.
func (p DeploymentPlan) ScratchBytes() uint64 { return p.document.ScratchBytes }

// CPUsMilli returns the CPU ceiling in thousandths of a CPU.
func (p DeploymentPlan) CPUsMilli() uint32 { return p.document.CPUsMilli }

// MemoryBytes returns the hard memory ceiling.
func (p DeploymentPlan) MemoryBytes() uint64 { return p.document.MemoryBytes }

// PIDs returns the hard process-count ceiling.
func (p DeploymentPlan) PIDs() uint32 { return p.document.PIDs }

// TimeoutMilliseconds returns the operation deadline ceiling.
func (p DeploymentPlan) TimeoutMilliseconds() uint32 { return p.document.TimeoutMilliseconds }

// CapabilitySecret returns the fixed gateway capability identifier or empty text.
func (p DeploymentPlan) CapabilitySecret() string { return p.document.CapabilitySecret }

// Transport returns the certified language-neutral carrier.
func (p DeploymentPlan) Transport() Transport { return p.document.Transport }
