// Package composeplan validates the signed PF-001 default Compose topology.
package composeplan

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ServiceName is a closed default-profile service identity.
type ServiceName string

const (
	// ServiceCore is the only persistent application/API service.
	ServiceCore ServiceName = "core"
	// ServiceNeo4j owns only the graph projection.
	ServiceNeo4j ServiceName = "neo4j"
	// ServiceLocalEmbedding is the required offline embedding provider.
	ServiceLocalEmbedding ServiceName = "local-embedding"
	// ServiceLocalReranker is the required offline reranking provider.
	ServiceLocalReranker ServiceName = "local-reranker"
	// ServiceLocalExtractor is the required offline extraction provider.
	ServiceLocalExtractor ServiceName = "local-extractor"
	// ServiceMigrate is the signed one-shot schema migration service.
	ServiceMigrate ServiceName = "migrate"
	// ServiceSecretProjector is the signed one-shot helper that copies protected
	// host sources into per-consumer engine volumes before any product mutation.
	ServiceSecretProjector ServiceName = "secret-projector"
	// ServiceProviderGateway is the only service permitted an external route.
	ServiceProviderGateway ServiceName = "provider-gateway"
)

// NetworkName is a signed logical network identity.
type NetworkName string

const (
	// NetworkInternal is the no-egress application network.
	NetworkInternal NetworkName = "am_internal"
	// NetworkEgress exists only in an authorized remote-provider profile.
	NetworkEgress NetworkName = "am_egress"
)

const (
	// LabelInstallation binds a resource to one installation UUID.
	LabelInstallation = "io.agentmemory.installation"
	// LabelRelease binds a resource to one signed release.
	LabelRelease = "io.agentmemory.release"
	// LabelGeneration binds a resource to one data generation.
	LabelGeneration = "io.agentmemory.generation"
	// LabelPurpose records the signed resource purpose.
	LabelPurpose = "io.agentmemory.purpose"
	// LabelManaged marks exact AgentMemory inventory members.
	LabelManaged = "io.agentmemory.managed"
	// SecretInstallationRootKey is the Core-only installation encryption root.
	SecretInstallationRootKey = "agentmemory_installation_root_key"
	// SecretAPICredential authenticates the launcher to Core's loopback API.
	SecretAPICredential = "agentmemory_api_credential"
	// SecretAttestationHMACKey authenticates the offline egress attestation.
	SecretAttestationHMACKey = "agentmemory_attestation_hmac_key"
	// SecretNeo4jPassword is shared only by Core, migrate, and Neo4j.
	SecretNeo4jPassword = "agentmemory_neo4j_password"
	// SecretEmbeddingCapability authenticates Core to the embedding sidecar.
	SecretEmbeddingCapability = "agentmemory_embedding_capability"
	// SecretRerankingCapability authenticates Core to the reranking sidecar.
	SecretRerankingCapability = "agentmemory_reranking_capability"
	// SecretExtractionCapability authenticates Core to the extraction sidecar.
	SecretExtractionCapability = "agentmemory_extraction_capability" // #nosec G101 -- identifier, not secret material.
	// SecretEgressAttestation is a bounded authenticated JSON control document.
	SecretEgressAttestation = "agentmemory_egress_attestation" // #nosec G101 -- identifier, not secret material.
	// SecretProviderGatewayClientCapability authenticates Core and contained
	// custom adapters to the internal-only gateway API.
	SecretProviderGatewayClientCapability = "agentmemory_provider_gateway_client_capability" // #nosec G101 -- identifier.
	// SecretProviderGatewayPermitHMACKey signs exact one-operation egress permits.
	SecretProviderGatewayPermitHMACKey = "agentmemory_provider_gateway_permit_hmac_key" // #nosec G101 -- identifier.
	// SecretProviderGatewayCredentialVault is the bounded authenticated provider
	// credential snapshot visible only inside the gateway.
	SecretProviderGatewayCredentialVault = "agentmemory_provider_gateway_credential_vault" // #nosec G101 -- identifier.
	// SecretProviderGatewayCredentialVaultKey decrypts provider credentials only
	// within the isolated gateway.
	SecretProviderGatewayCredentialVaultKey = "agentmemory_provider_gateway_credential_vault_key" // #nosec G101 -- identifier.
	// SecretProviderGatewayCredentialVaultHMACKey authenticates the vault snapshot.
	SecretProviderGatewayCredentialVaultHMACKey = "agentmemory_provider_gateway_credential_vault_hmac_key" // #nosec G101 -- identifier.
	// SecretInstallationKey is retained as a source-compatible alias. New code
	// must use SecretInstallationRootKey; the root key is never an API/HMAC key.
	SecretInstallationKey = SecretInstallationRootKey
)

var requiredDefaultSecrets = []string{
	SecretInstallationRootKey,
	SecretAPICredential,
	SecretAttestationHMACKey,
	SecretNeo4jPassword,
	SecretEmbeddingCapability,
	SecretRerankingCapability,
	SecretExtractionCapability,
	SecretEgressAttestation,
}

var requiredRemoteSecrets = []string{
	SecretProviderGatewayClientCapability,
	SecretProviderGatewayPermitHMACKey,
	SecretProviderGatewayCredentialVault,
	SecretProviderGatewayCredentialVaultKey,
	SecretProviderGatewayCredentialVaultHMACKey,
}

// Identity derives resource names only from validated installation state.
type Identity struct {
	installationID         string
	generation             string
	resourceInstallationID string
	resourceGeneration     string
}

// NewIdentity rejects project/user text and accepts only a canonical UUID
// installation identity plus a UUIDv7 data-generation identity. Docker names
// use the hyphenless forms required by ADR-017; labels retain canonical UUIDs.
func NewIdentity(installationID string, generation string) (Identity, error) {
	if !validUUID(installationID) || !validUUIDv7(generation) {
		return Identity{}, errors.New("compose installation identity is invalid")
	}
	return Identity{
		installationID:         installationID,
		generation:             generation,
		resourceInstallationID: strings.ReplaceAll(installationID, "-", ""),
		resourceGeneration:     strings.ReplaceAll(generation, "-", ""),
	}, nil
}

// InstallationID returns the validated installation UUID.
func (i Identity) InstallationID() string { return i.installationID }

// Generation returns the validated data-generation token.
func (i Identity) Generation() string { return i.generation }

// ProjectName returns the one installation-scoped Compose project name.
func (i Identity) ProjectName() string {
	return "agentmemory_" + i.resourceInstallationID
}

// VolumeName derives a generation-pinned managed volume name.
func (i Identity) VolumeName(purpose string) string {
	return fmt.Sprintf("agentmemory_%s_%s_%s", i.resourceInstallationID, purpose, i.resourceGeneration)
}

// StableVolumeName derives an installation-stable managed volume name.
func (i Identity) StableVolumeName(purpose string) string {
	return fmt.Sprintf("agentmemory_%s_%s", i.resourceInstallationID, purpose)
}

// NetworkName derives an installation-stable managed network name.
func (i Identity) NetworkName(purpose string) string {
	return fmt.Sprintf("agentmemory_%s_%s", i.resourceInstallationID, purpose)
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !isLowerHex(character) {
			return false
		}
	}
	return true
}

func isLowerHex(character rune) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')
}

func validUUIDv7(value string) bool {
	if !validUUID(value) || value[14] != '7' {
		return false
	}
	return value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b'
}

// Limits are mandatory non-zero service resource bounds.
type Limits struct {
	CPUsMilli   uint32
	MemoryBytes uint64
	PIDs        uint32
}

// Tmpfs describes one bounded in-memory scratch mount.
type Tmpfs struct {
	Target     string
	SizeBytes  uint64
	Mode       uint32
	Executable bool
}

// Port is one loopback-only core API publication.
type Port struct {
	HostIP        string
	HostPort      uint16
	ContainerPort uint16
}

// MountKind is a closed persistent/config/secret mount vocabulary.
type MountKind uint8

const (
	// MountUnknown is the invalid zero value.
	MountUnknown MountKind = iota
	// MountVolume is an installation-labelled named volume.
	MountVolume
	// MountConfig is an immutable validated configuration mount.
	MountConfig
	// MountSecret is an owner-controlled read-only secret reference mount.
	MountSecret
	// MountBind is prohibited for the persistent default profile.
	MountBind
)

// Mount describes one service mount without secret values.
type Mount struct {
	Kind     MountKind
	Source   string
	Target   string
	ReadOnly bool
}

// Dependency is one required health-gated service startup edge. The default
// offline profile permits no weak or optional dependencies.
type Dependency struct {
	Service   ServiceName
	Condition string
	Restart   bool
	Required  bool
}

// HealthcheckTiming is the complete finite health-probe schedule rendered by
// Compose. Every duration participates in signed-plan equality.
type HealthcheckTiming struct {
	Interval      time.Duration
	Timeout       time.Duration
	Retries       uint32
	StartPeriod   time.Duration
	StartInterval time.Duration
}

// Service is the policy-relevant subset of a rendered Compose service.
type Service struct {
	Name            ServiceName
	Image           string
	User            string
	ReadOnly        bool
	CapDropAll      bool
	CapAdd          []string
	NoNewPrivileges bool
	Privileged      bool
	HostNetwork     bool
	HostPID         bool
	HostIPC         bool
	NetworkDisabled bool
	Restart         string
	Networks        []NetworkName
	Healthcheck     []string
	HealthTiming    HealthcheckTiming
	StopGracePeriod time.Duration
	Command         []string
	Limits          Limits
	Tmpfs           []Tmpfs
	Ports           []Port
	Mounts          []Mount
	DependsOn       []Dependency
	Environment     map[string]string
	Labels          map[string]string
}

// Network is one rendered managed Compose network.
type Network struct {
	Name     string
	Internal bool
	Labels   map[string]string
}

// Volume is one rendered managed named volume.
type Volume struct {
	Name   string
	Labels map[string]string
}

// Secret is one signed host-file secret source. Values are never represented
// in the rendered topology or diagnostics.
type Secret struct {
	Name string
	File string
}

// Model is a fully rendered default-profile policy input.
type Model struct {
	Identity Identity
	Release  string
	Services map[ServiceName]Service
	Networks map[NetworkName]Network
	Volumes  map[string]Volume
	Secrets  map[string]Secret
}

// ViolationCode is a stable fail-closed Compose policy reason.
type ViolationCode string

const (
	// ViolationRequiredService reports a missing required service.
	ViolationRequiredService ViolationCode = "required_service"
	// ViolationImageDigest reports a mutable image reference.
	ViolationImageDigest ViolationCode = "image_digest"
	// ViolationNonRoot reports a root or missing identity.
	ViolationNonRoot ViolationCode = "non_root"
	// ViolationReadOnly reports a writable root filesystem.
	ViolationReadOnly ViolationCode = "read_only"
	// ViolationCapabilities reports missing cap_drop ALL.
	ViolationCapabilities ViolationCode = "capabilities"
	// ViolationPrivileged reports privileged execution.
	ViolationPrivileged ViolationCode = "privileged"
	// ViolationHostNamespace reports a shared host namespace.
	ViolationHostNamespace ViolationCode = "host_namespace"
	// ViolationNoNewPrivileges reports a missing escalation guard.
	ViolationNoNewPrivileges ViolationCode = "no_new_privileges"
	// ViolationResourceLimits reports missing non-zero limits.
	ViolationResourceLimits ViolationCode = "resource_limits"
	// ViolationHealthcheck reports a missing health contract.
	ViolationHealthcheck ViolationCode = "healthcheck"
	// ViolationDependencies reports a missing, weak, or unexpected startup edge.
	ViolationDependencies ViolationCode = "dependencies"
	// ViolationRestartPolicy reports a non-normative restart policy.
	ViolationRestartPolicy ViolationCode = "restart_policy"
	// ViolationPortExposure reports a non-loopback or non-core port.
	ViolationPortExposure ViolationCode = "port_exposure"
	// ViolationNetworkIsolation reports a forbidden route.
	ViolationNetworkIsolation ViolationCode = "network_isolation"
	// ViolationMountPolicy reports a forbidden or writable mount.
	ViolationMountPolicy ViolationCode = "mount_policy"
	// ViolationLabels reports incomplete ownership labels.
	ViolationLabels ViolationCode = "labels"
	// ViolationClosedInventory reports an undeclared or missing signed resource.
	ViolationClosedInventory ViolationCode = "closed_inventory"
	// ViolationEnvironment reports an unbound or secret-bearing environment.
	ViolationEnvironment ViolationCode = "environment"
)

// Violation identifies one safe policy code and resource.
type Violation struct {
	Code     ViolationCode
	Resource string
}

// Policy validates the signed default offline profile.
type Policy struct{}

// NewPolicy constructs the stateless policy.
func NewPolicy() Policy { return Policy{} }

// RequiredDefaultServices returns the required default service list.
func RequiredDefaultServices() []ServiceName {
	return []ServiceName{
		ServiceCore, ServiceNeo4j, ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor,
		ServiceMigrate, ServiceSecretProjector,
	}
}

// Validate returns deterministic violations in stable service order.
func (Policy) Validate(model Model) []Violation {
	violations := make([]Violation, 0)
	if !validReleaseIdentity(model.Release) {
		violations = append(violations, Violation{Code: ViolationLabels, Resource: "release"})
	}
	for _, required := range RequiredDefaultServices() {
		if _, exists := model.Services[required]; !exists {
			violations = append(violations, Violation{Code: ViolationRequiredService, Resource: string(required)})
		}
	}
	serviceNames := make([]string, 0, len(model.Services))
	for name := range model.Services {
		serviceNames = append(serviceNames, string(name))
	}
	sort.Strings(serviceNames)
	for _, rawName := range serviceNames {
		name := ServiceName(rawName)
		service := model.Services[name]
		if !requiredService(name) {
			violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: rawName})
			continue
		}
		violations = append(violations, validateService(model, name, service)...)
	}
	internal, exists := model.Networks[NetworkInternal]
	if !exists || !internal.Internal || internal.Name != model.Identity.NetworkName("internal") ||
		!validLabels(internal.Labels, model, "internal", model.Identity.Generation()) {
		violations = append(violations, Violation{Code: ViolationNetworkIsolation, Resource: string(NetworkInternal)})
	}
	if _, exists := model.Networks[NetworkEgress]; exists {
		violations = append(violations, Violation{Code: ViolationNetworkIsolation, Resource: string(NetworkEgress)})
	}
	for name := range model.Networks {
		if name != NetworkInternal {
			violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: string(name)})
		}
	}
	for _, required := range requiredVolumes(model.Identity) {
		if _, exists := model.Volumes[required]; !exists {
			violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: required})
		}
	}
	for _, volume := range model.Volumes {
		if !validVolume(volume, model) {
			violations = append(violations, Violation{Code: ViolationLabels, Resource: volume.Name})
		}
	}
	if len(model.Secrets) != len(requiredDefaultSecrets) {
		violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: "secrets"})
	}
	for _, name := range requiredDefaultSecrets {
		secret, exists := model.Secrets[name]
		if !exists || secret.Name != model.Identity.StableVolumeName(name) || !validSecretFile(secret.File) {
			violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: name})
		}
	}
	for name := range model.Secrets {
		if !requiredDefaultSecret(name) {
			violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: name})
		}
	}
	return violations
}

func requiredDefaultSecret(name string) bool {
	for _, required := range requiredDefaultSecrets {
		if name == required {
			return true
		}
	}
	return false
}

func requiredRemoteSecret(name string) bool {
	for _, required := range requiredRemoteSecrets {
		if name == required {
			return true
		}
	}
	return false
}

func validSecretFile(value string) bool {
	if value == "" || len(value) > 4096 || value != strings.TrimSpace(value) ||
		strings.ContainsAny(value, "\x00\r\n") || !strings.HasPrefix(value, "/") {
		return false
	}
	for index, segment := range strings.Split(value, "/") {
		if index == 0 {
			continue
		}
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func requiredService(name ServiceName) bool {
	for _, required := range RequiredDefaultServices() {
		if name == required {
			return true
		}
	}
	return false
}

func requiredVolumes(identity Identity) []string {
	purposes := requiredProjectionPurposes()
	volumes := make([]string, 0, 6+len(purposes))
	volumes = append(volumes,
		identity.VolumeName("state"),
		identity.VolumeName("artifacts"),
		identity.VolumeName("neo4j"),
		identity.StableVolumeName("journal"),
		identity.StableVolumeName("models"),
		identity.StableVolumeName("telemetry"),
	)
	for _, purpose := range purposes {
		volumes = append(volumes, identity.VolumeName(purpose))
	}
	return volumes
}

func validateService(model Model, name ServiceName, service Service) []Violation {
	violations := make([]Violation, 0)
	resource := string(name)
	if service.Name != name {
		violations = append(violations, Violation{Code: ViolationRequiredService, Resource: resource})
	}
	if !digestPinned(service.Image) {
		violations = append(violations, Violation{Code: ViolationImageDigest, Resource: resource})
	}
	if !validServiceUser(name, service.User) {
		violations = append(violations, Violation{Code: ViolationNonRoot, Resource: resource})
	}
	if !service.ReadOnly {
		violations = append(violations, Violation{Code: ViolationReadOnly, Resource: resource})
	}
	if !service.CapDropAll || !validAddedCapabilities(name, service.CapAdd) {
		violations = append(violations, Violation{Code: ViolationCapabilities, Resource: resource})
	}
	if service.Privileged {
		violations = append(violations, Violation{Code: ViolationPrivileged, Resource: resource})
	}
	if service.HostNetwork || service.HostPID || service.HostIPC {
		violations = append(violations, Violation{Code: ViolationHostNamespace, Resource: resource})
	}
	if !service.NoNewPrivileges {
		violations = append(violations, Violation{Code: ViolationNoNewPrivileges, Resource: resource})
	}
	if service.Limits.CPUsMilli == 0 || service.Limits.MemoryBytes == 0 || service.Limits.PIDs == 0 ||
		!validTmpfs(name, service.Tmpfs) {
		violations = append(violations, Violation{Code: ViolationResourceLimits, Resource: resource})
	}
	if !validServiceCommand(model, name, service.Command) {
		violations = append(violations, Violation{Code: ViolationClosedInventory, Resource: resource})
	}
	if !validServiceEnvironment(model, name, service.Environment) {
		violations = append(violations, Violation{Code: ViolationEnvironment, Resource: resource})
	}
	if !validServiceHealthcheck(name, service.Healthcheck, service.HealthTiming) {
		violations = append(violations, Violation{Code: ViolationHealthcheck, Resource: resource})
	}
	if service.StopGracePeriod <= 0 || service.StopGracePeriod > 5*time.Minute {
		violations = append(violations, Violation{Code: ViolationRestartPolicy, Resource: resource})
	}
	if !validDependencies(model, name, service.DependsOn) {
		violations = append(violations, Violation{Code: ViolationDependencies, Resource: resource})
	}
	expectedRestart := "unless-stopped"
	if name == ServiceMigrate || name == ServiceSecretProjector {
		expectedRestart = "no"
	}
	if service.Restart != expectedRestart {
		violations = append(violations, Violation{Code: ViolationRestartPolicy, Resource: resource})
	}
	if !validServiceNetworks(model, name, service.Networks, service.NetworkDisabled) {
		violations = append(violations, Violation{Code: ViolationNetworkIsolation, Resource: resource})
	}
	if !validPorts(name, service.Ports) {
		violations = append(violations, Violation{Code: ViolationPortExposure, Resource: resource})
	}
	if !validMounts(model, name, service.Mounts) {
		violations = append(violations, Violation{Code: ViolationMountPolicy, Resource: resource})
	}
	if !validLabels(service.Labels, model, resource, model.Identity.Generation()) {
		violations = append(violations, Violation{Code: ViolationLabels, Resource: resource})
	}
	return violations
}

func validServiceCommand(model Model, name ServiceName, command []string) bool {
	if name == ServiceSecretProjector && remoteTopology(model) {
		return len(command) == 1 && command[0] == "remote"
	}
	return len(command) == 0
}

func validAddedCapabilities(name ServiceName, capabilities []string) bool {
	if name != ServiceSecretProjector {
		return len(capabilities) == 0
	}
	return len(capabilities) == 2 && capabilities[0] == "CHOWN" && capabilities[1] == "DAC_READ_SEARCH"
}

func validServiceEnvironment(model Model, name ServiceName, environment map[string]string) bool {
	if len(environment) > 16 {
		return false
	}
	coreRevisions := func() (string, string, string, bool) {
		core, exists := model.Services[ServiceCore]
		if !exists {
			return "", "", "", false
		}
		embedding := core.Environment["AM_EMBEDDING_MODEL_REVISION"]
		reranking := core.Environment["AM_RERANKING_MODEL_REVISION"]
		extraction := core.Environment["AM_EXTRACTION_MODEL_REVISION"]
		return embedding, reranking, extraction,
			validRevision(embedding) && validRevision(reranking) && validRevision(extraction)
	}
	switch name {
	case ServiceSecretProjector:
		return len(environment) == 0
	case ServiceCore, ServiceMigrate:
		if len(environment) != 4 || environment["AM_NEO4J_USERNAME"] != "neo4j" ||
			!validRevision(environment["AM_EMBEDDING_MODEL_REVISION"]) ||
			!validRevision(environment["AM_RERANKING_MODEL_REVISION"]) ||
			!validRevision(environment["AM_EXTRACTION_MODEL_REVISION"]) {
			return false
		}
		if name == ServiceMigrate {
			embedding, reranking, extraction, valid := coreRevisions()
			return valid && environment["AM_EMBEDDING_MODEL_REVISION"] == embedding &&
				environment["AM_RERANKING_MODEL_REVISION"] == reranking &&
				environment["AM_EXTRACTION_MODEL_REVISION"] == extraction
		}
		return true
	case ServiceNeo4j:
		return len(environment) == 2 &&
			environment["NEO4J_client_allow__telemetry"] == "false" &&
			environment["NEO4J_server_bolt_telemetry_enabled"] == "false"
	case ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor:
		expectedRole := map[ServiceName]string{
			ServiceLocalEmbedding: "embedding",
			ServiceLocalReranker:  "reranking",
			ServiceLocalExtractor: "extraction",
		}[name]
		if len(environment) != 4 || environment["AM_PROVIDER_ROLE"] != expectedRole ||
			!validRevision(environment["AM_PROVIDER_MODEL_REVISION"]) ||
			!validSHA256(environment["AM_PROVIDER_MODEL_SHA256"]) ||
			!validModelSize(environment["AM_PROVIDER_MODEL_SIZE"]) {
			return false
		}
		embedding, reranking, extraction, valid := coreRevisions()
		if !valid {
			return false
		}
		expectedRevision := map[ServiceName]string{
			ServiceLocalEmbedding: embedding,
			ServiceLocalReranker:  reranking,
			ServiceLocalExtractor: extraction,
		}[name]
		return environment["AM_PROVIDER_MODEL_REVISION"] == expectedRevision
	case ServiceProviderGateway:
		return len(environment) == 0 && remoteTopology(model)
	default:
		return false
	}
}

func validRevision(value string) bool {
	return (len(value) == 40 || len(value) == 64) && allLowerHex(value)
}

func validSHA256(value string) bool {
	return len(value) == 64 && allLowerHex(value)
}

func allLowerHex(value string) bool {
	for _, character := range value {
		if !isLowerHex(character) {
			return false
		}
	}
	return true
}

func validModelSize(value string) bool {
	size, err := strconv.ParseUint(value, 10, 64)
	return err == nil && size > 0 && size <= 16*1024*1024*1024 && strconv.FormatUint(size, 10) == value
}

func validServiceHealthcheck(name ServiceName, command []string, timing HealthcheckTiming) bool {
	if name == ServiceMigrate || name == ServiceSecretProjector {
		return len(command) == 0 && timing == (HealthcheckTiming{})
	}
	expected := map[ServiceName][]string{
		ServiceCore:           {"CMD", "/usr/local/bin/agentmemory-healthcheck"},
		ServiceNeo4j:          {"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"},
		ServiceLocalEmbedding: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalReranker:  {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalExtractor: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceProviderGateway: {
			"CMD", "/usr/local/bin/agentmemory-provider-gateway", "healthcheck",
		},
	}[name]
	if len(command) != len(expected) {
		return false
	}
	for index := range expected {
		if command[index] != expected[index] {
			return false
		}
	}
	return validHealthcheck(command, timing)
}

func validDependencies(model Model, name ServiceName, dependencies []Dependency) bool {
	var required map[ServiceName]string
	switch name {
	case ServiceCore:
		required = map[ServiceName]string{
			ServiceNeo4j: "service_healthy", ServiceLocalEmbedding: "service_healthy",
			ServiceLocalReranker: "service_healthy", ServiceLocalExtractor: "service_healthy",
			ServiceMigrate: "service_completed_successfully",
		}
		if remoteTopology(model) {
			required[ServiceProviderGateway] = "service_healthy"
		}
	case ServiceMigrate:
		required = map[ServiceName]string{ServiceNeo4j: "service_healthy"}
	case ServiceNeo4j, ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor,
		ServiceSecretProjector, ServiceProviderGateway:
		return len(dependencies) == 0
	default:
		return len(dependencies) == 0
	}
	if len(dependencies) != len(required) {
		return false
	}
	seen := make(map[ServiceName]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		condition, exists := required[dependency.Service]
		if !exists || dependency.Condition != condition ||
			dependency.Restart || !dependency.Required {
			return false
		}
		if _, duplicate := seen[dependency.Service]; duplicate {
			return false
		}
		seen[dependency.Service] = struct{}{}
	}
	return true
}

func digestPinned(image string) bool {
	prefix, digest, found := strings.Cut(image, "@sha256:")
	if !found || prefix == "" || len(digest) != 64 || strings.Contains(prefix, "@") {
		return false
	}
	if lastSlash := strings.LastIndexByte(prefix, '/'); strings.Contains(prefix[lastSlash+1:], ":") {
		return false
	}
	for _, character := range digest {
		if !isLowerHex(character) {
			return false
		}
	}
	return true
}

func validServiceUser(name ServiceName, user string) bool {
	uidText, gidText, found := strings.Cut(user, ":")
	if !found || strings.Contains(gidText, ":") {
		return false
	}
	uid, uidError := strconv.ParseUint(uidText, 10, 32)
	gid, gidError := strconv.ParseUint(gidText, 10, 32)
	if uidError != nil || gidError != nil {
		return false
	}
	if name == ServiceNeo4j {
		return uid == 7474 && gid == 7474
	}
	if name == ServiceSecretProjector {
		return uid == 0 && gid == 0
	}
	return uid == 10_001 && gid == 10_001
}

func validTmpfs(service ServiceName, entries []Tmpfs) bool {
	if len(entries) == 0 || len(entries) > 4 {
		return false
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Target == "" || !strings.HasPrefix(entry.Target, "/") || entry.SizeBytes == 0 ||
			entry.SizeBytes > 1024*1024*1024 || entry.Mode != 0o1777 {
			return false
		}
		if entry.Executable != (service == ServiceNeo4j && entry.Target == "/tmp") {
			return false
		}
		if _, exists := seen[entry.Target]; exists {
			return false
		}
		seen[entry.Target] = struct{}{}
	}
	return true
}

func validHealthcheck(command []string, timing HealthcheckTiming) bool {
	if len(command) < 2 || len(command) > 16 || command[0] != "CMD" || !strings.HasPrefix(command[1], "/") {
		return false
	}
	if timing.Interval <= 0 || timing.Interval > 5*time.Minute || timing.Timeout <= 0 ||
		timing.Timeout > timing.Interval || timing.Retries == 0 || timing.Retries > 12 ||
		timing.StartPeriod < 0 || timing.StartPeriod > 10*time.Minute || timing.StartInterval <= 0 ||
		timing.StartInterval > timing.Interval {
		return false
	}
	for _, argument := range command[1:] {
		if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\r\n\x00") {
			return false
		}
	}
	return true
}

func validServiceNetworks(
	model Model,
	service ServiceName,
	networks []NetworkName,
	disabled bool,
) bool {
	if service == ServiceSecretProjector {
		return disabled && len(networks) == 0
	}
	if service == ServiceProviderGateway {
		return remoteTopology(model) && !disabled && len(networks) == 2 &&
			networks[0] == NetworkEgress && networks[1] == NetworkInternal
	}
	return !disabled && len(networks) == 1 && networks[0] == NetworkInternal
}

func validPorts(name ServiceName, ports []Port) bool {
	if name != ServiceCore {
		return len(ports) == 0
	}
	if len(ports) == 0 || len(ports) > 2 {
		return false
	}
	seenHosts := make(map[string]struct{}, len(ports))
	var selectedHostPort uint16
	for _, port := range ports {
		if (port.HostIP != "127.0.0.1" && port.HostIP != "::1") || port.HostPort == 0 || port.ContainerPort != 9411 {
			return false
		}
		if _, duplicate := seenHosts[port.HostIP]; duplicate {
			return false
		}
		seenHosts[port.HostIP] = struct{}{}
		if selectedHostPort != 0 && selectedHostPort != port.HostPort {
			return false
		}
		selectedHostPort = port.HostPort
	}
	return true
}

func validMounts(model Model, service ServiceName, mounts []Mount) bool {
	seenTargets := make(map[string]struct{}, len(mounts))
	seenVolumes := make(map[string]struct{}, len(mounts))
	seenSecrets := make(map[string]string, len(mounts))
	requiredSecrets := requiredSecretMounts(service)
	if service == ServiceSecretProjector && remoteTopology(model) {
		for _, name := range requiredRemoteSecrets {
			requiredSecrets[name] = "/run/inputs/" + name
		}
	}
	for _, mount := range mounts {
		if mount.Source == "" || !strings.HasPrefix(mount.Target, "/") ||
			strings.Contains(strings.ToLower(mount.Source+" "+mount.Target), "docker.sock") {
			return false
		}
		if _, duplicate := seenTargets[mount.Target]; duplicate {
			return false
		}
		seenTargets[mount.Target] = struct{}{}
		switch mount.Kind {
		case MountVolume:
			volume, exists := model.Volumes[mount.Source]
			if !exists || !validVolume(volume, model) || !allowedVolumeMount(model.Identity, service, mount) {
				return false
			}
			if _, duplicate := seenVolumes[mount.Source]; duplicate {
				return false
			}
			seenVolumes[mount.Source] = struct{}{}
		case MountConfig:
			// Config resources remain fail-closed until their top-level source,
			// uid/gid/mode, and signed-plan binding are represented end to end.
			return false
		case MountSecret:
			if _, exists := model.Secrets[mount.Source]; !exists || !mount.ReadOnly ||
				!validResourceToken(mount.Source) {
				return false
			}
			expectedTarget, allowed := requiredSecrets[mount.Source]
			if !allowed || mount.Target != expectedTarget {
				return false
			}
			if _, duplicate := seenSecrets[mount.Source]; duplicate {
				return false
			}
			seenSecrets[mount.Source] = mount.Target
		case MountUnknown, MountBind:
			return false
		}
	}
	return requiredVolumeMountsPresent(model, service, seenVolumes) &&
		exactSecretMountsPresent(requiredSecrets, seenSecrets)
}

func requiredSecretMounts(service ServiceName) map[string]string {
	secretTarget := func(name string) string { return "/run/inputs/" + name }
	switch service {
	case ServiceSecretProjector:
		return map[string]string{
			SecretInstallationRootKey:  secretTarget(SecretInstallationRootKey),
			SecretAPICredential:        secretTarget(SecretAPICredential),
			SecretAttestationHMACKey:   secretTarget(SecretAttestationHMACKey),
			SecretNeo4jPassword:        secretTarget(SecretNeo4jPassword),
			SecretEmbeddingCapability:  secretTarget(SecretEmbeddingCapability),
			SecretRerankingCapability:  secretTarget(SecretRerankingCapability),
			SecretExtractionCapability: secretTarget(SecretExtractionCapability),
			SecretEgressAttestation:    secretTarget(SecretEgressAttestation),
		}
	case ServiceCore, ServiceNeo4j, ServiceLocalEmbedding, ServiceLocalReranker,
		ServiceLocalExtractor, ServiceMigrate, ServiceProviderGateway:
		return map[string]string{}
	default:
		return map[string]string{}
	}
}

func exactSecretMountsPresent(required map[string]string, seen map[string]string) bool {
	if len(required) != len(seen) {
		return false
	}
	for source, target := range required {
		if seen[source] != target {
			return false
		}
	}
	return true
}

func requiredVolumeMountsPresent(model Model, service ServiceName, seen map[string]struct{}) bool {
	identity := model.Identity
	required := make([]string, 0, 6)
	switch service {
	case ServiceCore:
		required = append(required,
			identity.VolumeName("state"),
			identity.VolumeName("artifacts"),
			identity.StableVolumeName("journal"),
			identity.StableVolumeName("telemetry"),
			identity.VolumeName(projectionPurposeCore),
		)
		if remoteTopology(model) {
			required = append(required, identity.StableVolumeName("provider-core-egress"))
		}
	case ServiceNeo4j:
		required = append(required, identity.VolumeName("neo4j"), identity.VolumeName(projectionPurposeNeo4j))
	case ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor:
		required = append(required, identity.StableVolumeName("models"), identity.VolumeName(projectionPurposeForService(service)))
	case ServiceMigrate:
		required = append(required, identity.VolumeName("state"), identity.VolumeName(projectionPurposeMigrate))
	case ServiceSecretProjector:
		for _, purpose := range requiredProjectionPurposes() {
			required = append(required, identity.VolumeName(purpose))
		}
		if remoteTopology(model) {
			for _, purpose := range []string{
				"provider-core-egress",
				"provider-gateway-secrets",
				"provider-adapter-egress",
			} {
				required = append(required, identity.StableVolumeName(purpose))
			}
		}
	case ServiceProviderGateway:
		required = append(required,
			identity.StableVolumeName("provider-gateway-secrets"),
			identity.StableVolumeName("telemetry"),
		)
	}
	if len(seen) != len(required) {
		return false
	}
	for _, name := range required {
		if _, exists := seen[name]; !exists {
			return false
		}
	}
	return true
}

func allowedVolumeMount(identity Identity, service ServiceName, mount Mount) bool {
	projectionPurpose := projectionPurposeForService(service)
	if projectionPurpose != "" && mount.Source == identity.VolumeName(projectionPurpose) {
		return mount.ReadOnly && mount.Target == "/run/secrets"
	}
	switch service {
	case ServiceCore:
		if mount.Source == identity.StableVolumeName("provider-core-egress") {
			return mount.ReadOnly && mount.Target == "/run/provider-egress"
		}
		return !mount.ReadOnly && ((mount.Source == identity.VolumeName("state") && mount.Target == "/var/lib/agentmemory/state") ||
			(mount.Source == identity.VolumeName("artifacts") && mount.Target == "/var/lib/agentmemory/artifacts") ||
			(mount.Source == identity.StableVolumeName("journal") && mount.Target == "/var/lib/agentmemory/journal") ||
			(mount.Source == identity.StableVolumeName("telemetry") && mount.Target == "/var/lib/agentmemory/telemetry"))
	case ServiceNeo4j:
		return !mount.ReadOnly && mount.Source == identity.VolumeName("neo4j") && mount.Target == "/data"
	case ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor:
		return mount.ReadOnly && mount.Source == identity.StableVolumeName("models") && mount.Target == "/models"
	case ServiceMigrate:
		return !mount.ReadOnly && mount.Source == identity.VolumeName("state") && mount.Target == "/var/lib/agentmemory/state"
	case ServiceSecretProjector:
		for _, purpose := range requiredProjectionPurposes() {
			if mount.Source == identity.VolumeName(purpose) {
				return !mount.ReadOnly && mount.Target == "/run/outputs/"+purpose
			}
		}
		for _, purpose := range []string{
			"provider-core-egress",
			"provider-gateway-secrets",
			"provider-adapter-egress",
		} {
			if mount.Source == identity.StableVolumeName(purpose) {
				return !mount.ReadOnly && mount.Target == "/run/outputs/"+purpose
			}
		}
	case ServiceProviderGateway:
		return (mount.ReadOnly &&
			mount.Source == identity.StableVolumeName("provider-gateway-secrets") &&
			mount.Target == "/run/secrets") ||
			(!mount.ReadOnly &&
				mount.Source == identity.StableVolumeName("telemetry") &&
				mount.Target == "/var/lib/agentmemory/telemetry")
	}
	return false
}

func validVolume(volume Volume, model Model) bool {
	if volume.Name == "" || !validLabelsBase(volume.Labels, model) {
		return false
	}
	purpose := volume.Labels[LabelPurpose]
	generation := volume.Labels[LabelGeneration]
	if generation == "stable" && (purpose == "models" || purpose == "journal" ||
		purpose == "telemetry" || purpose == "provider-core-egress" ||
		purpose == "provider-gateway-secrets" || purpose == "provider-adapter-egress") {
		return volume.Name == model.Identity.StableVolumeName(purpose)
	}
	if generation != model.Identity.Generation() || !generationVolumePurpose(purpose) {
		return false
	}
	return volume.Name == model.Identity.VolumeName(purpose)
}

func remoteTopology(model Model) bool {
	_, service := model.Services[ServiceProviderGateway]
	_, network := model.Networks[NetworkEgress]
	return service && network
}

const (
	projectionPurposeCore       = "protected-core"
	projectionPurposeMigrate    = "protected-migrate"
	projectionPurposeNeo4j      = "protected-neo4j"
	projectionPurposeEmbedding  = "protected-embedding"
	projectionPurposeReranking  = "protected-reranking"
	projectionPurposeExtraction = "protected-extraction"
)

func requiredProjectionPurposes() []string {
	return []string{
		projectionPurposeCore, projectionPurposeMigrate, projectionPurposeNeo4j,
		projectionPurposeEmbedding, projectionPurposeReranking, projectionPurposeExtraction,
	}
}

func projectionPurposeForService(service ServiceName) string {
	return map[ServiceName]string{
		ServiceCore: projectionPurposeCore, ServiceMigrate: projectionPurposeMigrate,
		ServiceNeo4j: projectionPurposeNeo4j, ServiceLocalEmbedding: projectionPurposeEmbedding,
		ServiceLocalReranker: projectionPurposeReranking, ServiceLocalExtractor: projectionPurposeExtraction,
	}[service]
}

func generationVolumePurpose(purpose string) bool {
	if purpose == "state" || purpose == "artifacts" || purpose == "neo4j" {
		return true
	}
	for _, projection := range requiredProjectionPurposes() {
		if purpose == projection {
			return true
		}
	}
	return false
}

func validLabels(labels map[string]string, model Model, purpose string, generation string) bool {
	return validLabelsBase(labels, model) && labels[LabelPurpose] == purpose && labels[LabelGeneration] == generation
}

func validLabelsBase(labels map[string]string, model Model) bool {
	return len(labels) == 5 && labels[LabelInstallation] == model.Identity.InstallationID() &&
		labels[LabelRelease] == model.Release && labels[LabelManaged] == "true" &&
		labels[LabelGeneration] != "" && labels[LabelPurpose] != ""
}

func validResourceToken(value string) bool {
	if value == "" || len(value) > 64 {
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

func validReleaseIdentity(value string) bool {
	return validResourceToken(value) && len(value) <= 128
}
