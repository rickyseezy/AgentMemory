package installplanapp

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	runtimeAuthoritySchemaVersion = uint16(2)
	runtimeAuthorityDomain        = "agentmemory.runtime-plan-authority.v2"
)

// RuntimeEvidenceRequest identifies the exact parent authority and signed
// runtime-catalog resource an evidence resolver must verify.
type RuntimeEvidenceRequest struct {
	OperationID            install.OperationID
	ParentPlanDigest       install.PlanDigest
	RuntimeCatalogID       string
	RuntimeCatalogDigest   install.Digest
	SignedHostPlan         hostverification.SignedPlan
	HostEvidenceDigest     install.Digest
	HostStorageTarget      string
	RuntimeEndpoint        string
	SignedRelease          releaseinventory.SignedManifest
	RuntimeCatalogResource releaseinventory.Resource
}

// RuntimeExecutionAuthority is the complete read-only input required to
// re-verify and execute one persisted PF-006 plan after a process restart.
// It deliberately carries the signed outer release/catalog resource as well
// as the immutable nested authority; execution must not trust an in-memory
// catalog retained from the planning call.
type RuntimeExecutionAuthority struct {
	request   RuntimeEvidenceRequest
	authority RuntimePlanAuthority
}

// NewRuntimeExecutionAuthority joins a current parent request to one already
// authenticated persisted nested authority. This constructor is public so
// infrastructure verification can be tested without exposing mutable fields.
func NewRuntimeExecutionAuthority(
	request RuntimeEvidenceRequest,
	authority RuntimePlanAuthority,
) (RuntimeExecutionAuthority, error) {
	plan := authority.Plan()
	catalogDigest, err := install.ParseDigest(plan.CatalogDigest().String())
	if err != nil || request.OperationID.IsZero() || request.ParentPlanDigest.IsZero() ||
		request.OperationID != authority.OperationID() ||
		!request.ParentPlanDigest.Equal(authority.ParentPlanDigest()) ||
		request.RuntimeCatalogID == "" || request.RuntimeCatalogID != request.RuntimeCatalogResource.ID() ||
		request.RuntimeCatalogDigest.IsZero() ||
		request.RuntimeCatalogResource.Digest().Hex() != request.RuntimeCatalogDigest.String() ||
		!request.RuntimeCatalogDigest.Equal(authority.CatalogResourceEvidenceDigest()) ||
		request.HostEvidenceDigest.IsZero() ||
		!request.HostEvidenceDigest.Equal(authority.HostEvidenceDigest()) ||
		request.HostStorageTarget == "" || request.RuntimeEndpoint == "" ||
		!authority.SignedCatalogEvidenceDigest().Equal(catalogDigest) {
		return RuntimeExecutionAuthority{}, ErrRuntimePlanIntegrity
	}
	return RuntimeExecutionAuthority{request: request, authority: authority}, nil
}

// Request returns the exact parent evidence and signed catalog resource that
// must be verified again before platform capabilities are constructed.
func (a RuntimeExecutionAuthority) Request() RuntimeEvidenceRequest { return a.request }

// RuntimeAuthority returns the persisted operation-scoped nested authority.
func (a RuntimeExecutionAuthority) RuntimeAuthority() RuntimePlanAuthority { return a.authority }

// RuntimeEvidenceResolver performs the read-only verified host/runtime
// discovery and signed-catalog projection needed to derive a runtime plan.
type RuntimeEvidenceResolver interface {
	ResolveRuntimeEvidence(context.Context, RuntimeEvidenceRequest) (RuntimeEvidence, error)
}

// RuntimeEvidence contains only constructor-validated typed facts and their
// authenticated evidence bindings.
type RuntimeEvidence struct {
	host                    runtimeinstall.HostCapabilities
	discovery               runtimeinstall.RuntimeDiscovery
	catalog                 runtimeinstall.CertifiedRuntime
	hostEvidence            install.Digest
	discoveryEvidence       install.Digest
	catalogResourceEvidence install.Digest
	signedCatalogEvidence   install.Digest
}

// NewRuntimeEvidence rejects unbound facts and requires the signed catalog
// evidence to be the exact verified catalog manifest used by the plan.
func NewRuntimeEvidence(
	host runtimeinstall.HostCapabilities,
	discovery runtimeinstall.RuntimeDiscovery,
	catalog runtimeinstall.CertifiedRuntime,
	hostEvidence install.Digest,
	discoveryEvidence install.Digest,
	catalogResourceEvidence install.Digest,
	signedCatalogEvidence install.Digest,
) (RuntimeEvidence, error) {
	plan, err := runtimeinstall.NewPlanV1(host, discovery, catalog)
	catalogDigest, digestError := install.ParseDigest(catalog.CatalogDigest().String())
	if err != nil || digestError != nil || len(plan.CanonicalBytes()) == 0 || hostEvidence.IsZero() ||
		discoveryEvidence.IsZero() || catalogResourceEvidence.IsZero() || signedCatalogEvidence.IsZero() ||
		!signedCatalogEvidence.Equal(catalogDigest) {
		return RuntimeEvidence{}, ErrRuntimePlanIntegrity
	}
	return RuntimeEvidence{
		host: host, discovery: discovery, catalog: catalog,
		hostEvidence: hostEvidence, discoveryEvidence: discoveryEvidence,
		catalogResourceEvidence: catalogResourceEvidence,
		signedCatalogEvidence:   signedCatalogEvidence,
	}, nil
}

// Host returns immutable typed host facts.
func (e RuntimeEvidence) Host() runtimeinstall.HostCapabilities { return e.host }

// Discovery returns immutable typed local runtime facts.
func (e RuntimeEvidence) Discovery() runtimeinstall.RuntimeDiscovery { return e.discovery }

// Catalog returns the immutable verified catalog selection.
func (e RuntimeEvidence) Catalog() runtimeinstall.CertifiedRuntime { return e.catalog }

// HostEvidenceDigest returns the PF-001 host verification output binding.
func (e RuntimeEvidence) HostEvidenceDigest() install.Digest { return e.hostEvidence }

// DiscoveryEvidenceDigest returns the authenticated runtime discovery binding.
func (e RuntimeEvidence) DiscoveryEvidenceDigest() install.Digest { return e.discoveryEvidence }

// CatalogResourceEvidenceDigest returns the verified outer signed-envelope
// resource digest bound by the parent release.
func (e RuntimeEvidence) CatalogResourceEvidenceDigest() install.Digest {
	return e.catalogResourceEvidence
}

// SignedCatalogEvidenceDigest returns the exact verified signed catalog digest.
func (e RuntimeEvidence) SignedCatalogEvidenceDigest() install.Digest { return e.signedCatalogEvidence }

// RuntimePlanAuthorityRecord is the persistence-neutral immutable authority.
type RuntimePlanAuthorityRecord struct {
	SchemaVersion                 uint16
	OperationID                   string
	ParentPlanDigest              string
	CanonicalPlan                 []byte
	HostEvidenceDigest            string
	DiscoveryEvidenceDigest       string
	CatalogResourceEvidenceDigest string
	SignedCatalogEvidenceDigest   string
	BindingDigest                 string
}

// RuntimePlanAuthority binds one strict nested plan and all evidence to one
// operation and one PF-001 parent plan.
type RuntimePlanAuthority struct {
	operationID             install.OperationID
	parentPlanDigest        install.PlanDigest
	plan                    runtimeinstall.Plan
	hostEvidence            install.Digest
	discoveryEvidence       install.Digest
	catalogResourceEvidence install.Digest
	signedCatalogEvidence   install.Digest
	binding                 install.Digest
}

// NewRuntimePlanAuthority constructs one immutable operation-scoped binding.
func NewRuntimePlanAuthority(
	operationID install.OperationID,
	parent install.PlanDigest,
	plan runtimeinstall.Plan,
	hostEvidence install.Digest,
	discoveryEvidence install.Digest,
	catalogResourceEvidence install.Digest,
	signedCatalogEvidence install.Digest,
) (RuntimePlanAuthority, error) {
	canonical := plan.CanonicalBytes()
	decoded, err := runtimeinstall.DecodePlanV1(canonical)
	catalogDigest, digestError := install.ParseDigest(decoded.CatalogDigest().String())
	if operationID.IsZero() || parent.IsZero() || err != nil || len(canonical) == 0 ||
		decoded.Digest() != plan.Digest() || hostEvidence.IsZero() || discoveryEvidence.IsZero() ||
		catalogResourceEvidence.IsZero() || signedCatalogEvidence.IsZero() || digestError != nil ||
		!signedCatalogEvidence.Equal(catalogDigest) {
		return RuntimePlanAuthority{}, ErrRuntimePlanIntegrity
	}
	authority := RuntimePlanAuthority{
		operationID: operationID, parentPlanDigest: parent, plan: decoded,
		hostEvidence: hostEvidence, discoveryEvidence: discoveryEvidence,
		catalogResourceEvidence: catalogResourceEvidence,
		signedCatalogEvidence:   signedCatalogEvidence,
	}
	authority.binding = runtimeAuthorityBinding(authority)
	return authority, nil
}

// RestoreRuntimePlanAuthority authenticates all persisted fields and exact plan bytes.
func RestoreRuntimePlanAuthority(record RuntimePlanAuthorityRecord) (RuntimePlanAuthority, error) {
	if record.SchemaVersion != runtimeAuthoritySchemaVersion {
		return RuntimePlanAuthority{}, ErrRuntimePlanIntegrity
	}
	operationID, operationError := install.NewOperationID(record.OperationID)
	parent, parentError := install.ParsePlanDigest(record.ParentPlanDigest)
	host, hostError := install.ParseDigest(record.HostEvidenceDigest)
	discovery, discoveryError := install.ParseDigest(record.DiscoveryEvidenceDigest)
	resource, resourceError := install.ParseDigest(record.CatalogResourceEvidenceDigest)
	catalog, catalogError := install.ParseDigest(record.SignedCatalogEvidenceDigest)
	binding, bindingError := install.ParseDigest(record.BindingDigest)
	plan, planError := runtimeinstall.DecodePlanV1(record.CanonicalPlan)
	if operationError != nil || parentError != nil || hostError != nil || discoveryError != nil || resourceError != nil ||
		catalogError != nil || bindingError != nil || planError != nil {
		return RuntimePlanAuthority{}, ErrRuntimePlanIntegrity
	}
	authority, err := NewRuntimePlanAuthority(operationID, parent, plan, host, discovery, resource, catalog)
	if err != nil || !authority.binding.Equal(binding) {
		return RuntimePlanAuthority{}, ErrRuntimePlanIntegrity
	}
	return authority, nil
}

// Record returns a caller-owned persistence projection.
func (a RuntimePlanAuthority) Record() RuntimePlanAuthorityRecord {
	return RuntimePlanAuthorityRecord{
		SchemaVersion: runtimeAuthoritySchemaVersion,
		OperationID:   a.operationID.String(), ParentPlanDigest: a.parentPlanDigest.String(),
		CanonicalPlan: a.plan.CanonicalBytes(), HostEvidenceDigest: a.hostEvidence.String(),
		DiscoveryEvidenceDigest:       a.discoveryEvidence.String(),
		CatalogResourceEvidenceDigest: a.catalogResourceEvidence.String(),
		SignedCatalogEvidenceDigest:   a.signedCatalogEvidence.String(), BindingDigest: a.binding.String(),
	}
}

// OperationID returns the sole operation authorized by this record.
func (a RuntimePlanAuthority) OperationID() install.OperationID { return a.operationID }

// ParentPlanDigest returns the exact PF-001 plan binding.
func (a RuntimePlanAuthority) ParentPlanDigest() install.PlanDigest { return a.parentPlanDigest }

// Plan returns the immutable decoded nested execution authority.
func (a RuntimePlanAuthority) Plan() runtimeinstall.Plan { return a.plan }

// HostEvidenceDigest returns the authenticated host proof binding.
func (a RuntimePlanAuthority) HostEvidenceDigest() install.Digest { return a.hostEvidence }

// DiscoveryEvidenceDigest returns the authenticated runtime observation binding.
func (a RuntimePlanAuthority) DiscoveryEvidenceDigest() install.Digest { return a.discoveryEvidence }

// CatalogResourceEvidenceDigest returns the exact outer release-resource binding.
func (a RuntimePlanAuthority) CatalogResourceEvidenceDigest() install.Digest {
	return a.catalogResourceEvidence
}

// SignedCatalogEvidenceDigest returns the exact verified catalog binding.
func (a RuntimePlanAuthority) SignedCatalogEvidenceDigest() install.Digest {
	return a.signedCatalogEvidence
}

// BindingDigest returns the complete deterministic authority authentication digest.
func (a RuntimePlanAuthority) BindingDigest() install.Digest { return a.binding }

// Equal compares complete authenticated authority rather than mutable DTOs.
func (a RuntimePlanAuthority) Equal(other RuntimePlanAuthority) bool {
	return !a.binding.IsZero() && a.binding.Equal(other.binding)
}

func runtimeAuthorityBinding(authority RuntimePlanAuthority) install.Digest {
	var canonical bytes.Buffer
	writeRuntimeAuthorityField(&canonical, runtimeAuthorityDomain)
	writeRuntimeAuthorityField(&canonical, authority.operationID.String())
	writeRuntimeAuthorityField(&canonical, authority.parentPlanDigest.String())
	writeRuntimeAuthorityField(&canonical, authority.plan.Digest().String())
	writeRuntimeAuthorityField(&canonical, authority.hostEvidence.String())
	writeRuntimeAuthorityField(&canonical, authority.discoveryEvidence.String())
	writeRuntimeAuthorityField(&canonical, authority.catalogResourceEvidence.String())
	writeRuntimeAuthorityField(&canonical, authority.signedCatalogEvidence.String())
	return install.DigestBytes(canonical.Bytes())
}

func writeRuntimeAuthorityField(output *bytes.Buffer, value string) {
	_ = binary.Write(output, binary.BigEndian, uint64(len(value)))
	_, _ = output.WriteString(value)
}
