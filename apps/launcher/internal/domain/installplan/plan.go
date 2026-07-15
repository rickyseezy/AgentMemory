package installplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	// SupportedSchemaMajor is the only top-level installation-plan schema this
	// launcher may interpret for side-effect authorization.
	SupportedSchemaMajor = uint16(1)
	maximumRawPlanBytes  = 32 * 1024 * 1024
	maximumJSONDepth     = 64
	maximumEvidenceBytes = 16 * 1024 * 1024
	maximumSafeJSONInt   = uint64(1<<53 - 1)
)

// CapacityInput identifies the exact adapter-owned locators whose allocation
// pools must later be live-attested. Locators are routing inputs, never pool
// identity or free-space evidence.
type CapacityInput struct {
	HostCAS          string
	HostRelease      string
	DockerEngine     string
	DockerDataVolume string
}

// ArtifactInput contains the parent-authorized acquisition descriptors. Each
// artifact is independently cross-bound to the nested signed release manifest.
type ArtifactInput struct {
	ComposeArtifactID     string
	ProxyMode             artifactacquisition.ProxyMode
	Artifacts             []artifactacquisition.ArtifactInput
	RollbackHeadroomBytes uint64
	SafetyHeadroomBytes   uint64
	Capacity              CapacityInput
}

// RuntimeCatalogInput binds the signed release resource that must be verified
// before a live runtime plan can be generated. It intentionally does not carry
// arbitrary nested plan bytes: runtimeinstall currently exposes no safe decoder.
type RuntimeCatalogInput struct {
	ResourceID string
}

// AgentConfigurationInput is the exact host mutation authorized by the plan.
type AgentConfigurationInput struct {
	AgentHost                  agentconfigdomain.AgentHost
	ConfigLocation             string
	EntryID                    string
	ExpectedManagedEntryDigest agentconfigdomain.Digest
	LauncherDigest             agentconfigdomain.Digest
	LauncherPath               string
}

func normalizedAgentHost(host agentconfigdomain.AgentHost) agentconfigdomain.AgentHost {
	if host == "" {
		return agentconfigdomain.AgentHostGeneric
	}
	return host
}

// SecretPurpose is the closed set of purpose-separated 256-bit bootstrap
// secrets consumed by the default local stack.
type SecretPurpose string

const (
	// SecretInstallationRootKey is the installation-wide root key.
	SecretInstallationRootKey SecretPurpose = "installation-root-key"
	// SecretAPICredential authenticates launcher-to-Core operations.
	SecretAPICredential SecretPurpose = "api-credential" //nolint:gosec // Purpose identifier, never a secret value.
	// SecretAttestationHMACKey authenticates local evidence.
	SecretAttestationHMACKey SecretPurpose = "attestation-hmac-key"
	// SecretNeo4jPassword authenticates the private graph service.
	SecretNeo4jPassword SecretPurpose = "neo4j-password"
	// SecretEmbeddingCapability authenticates the embedding sidecar.
	SecretEmbeddingCapability SecretPurpose = "embedding-capability" //nolint:gosec // Purpose identifier, never a secret value.
	// SecretRerankerCapability authenticates the reranking sidecar.
	SecretRerankerCapability SecretPurpose = "reranker-capability" //nolint:gosec // Purpose identifier, never a secret value.
	// SecretExtractorCapability authenticates the extraction sidecar.
	SecretExtractorCapability SecretPurpose = "extractor-capability"
)

var requiredSecretPurposes = []SecretPurpose{
	SecretAPICredential,
	SecretAttestationHMACKey,
	SecretEmbeddingCapability,
	SecretExtractorCapability,
	SecretInstallationRootKey,
	SecretNeo4jPassword,
	SecretRerankerCapability,
}

// SecretFileInput binds one purpose-separated secret to its exact protected
// host materialization path. Secret bytes are never part of the plan.
type SecretFileInput struct {
	Purpose SecretPurpose
	Path    string
}

// ProductInput contains every host path and loopback identity the product
// phases may mutate after release verification.
type ProductInput struct {
	ReleaseDirectory         string
	ConfigurationDirectory   string
	RuntimeDirectory         string
	SecretDirectory          string
	BackupDirectory          string
	ComposeProjectDirectory  string
	ComposeConfigurationPath string
	EmptyEnvironmentPath     string
	EgressAttestationPath    string
	CoreEndpoint             string
	InitialBrainID           string
	InitialBrainName         string
	OwnerPrincipalID         string
	OwnerGrantID             string
	OwnerSubjectDigest       install.Digest
	SecretFiles              []SecretFileInput
}

// Input constructs one canonical plan without accepting redundant release,
// manifest, operation, installation, generation, or Compose digest claims.
type Input struct {
	OperationID        install.OperationID
	InstallationID     string
	GenerationID       string
	RuntimeEndpoint    string
	RuntimeOwnership   install.RuntimeOwnership
	SecurityEpoch      uint64
	SignedHostPlan     hostverification.SignedPlan
	HostStorageTarget  string
	SignedRelease      releaseinventory.SignedManifest
	Product            ProductInput
	RuntimeCatalog     RuntimeCatalogInput
	Artifacts          ArtifactInput
	AgentConfiguration AgentConfigurationInput
}

// Capacity is an immutable copy of exact adapter routing inputs.
type Capacity struct {
	hostCAS          string
	hostRelease      string
	dockerEngine     string
	dockerDataVolume string
}

// HostCAS returns the exact host CAS routing locator.
func (c Capacity) HostCAS() string { return c.hostCAS }

// HostRelease returns the parent-bound immutable release-directory locator.
func (c Capacity) HostRelease() string { return c.hostRelease }

// DockerEngine returns the exact local Engine routing locator.
func (c Capacity) DockerEngine() string { return c.dockerEngine }

// DockerDataVolume returns the exact Docker data-volume routing locator.
func (c Capacity) DockerDataVolume() string { return c.dockerDataVolume }

// NetworkProjection contains only static, parent-authorized resource inputs.
type NetworkProjection struct {
	installationID  string
	generationID    string
	runtimeEndpoint string
}

// InstallationID returns the UUIDv7 resource owner.
func (p NetworkProjection) InstallationID() string { return p.installationID }

// GenerationID returns the UUIDv7 release generation.
func (p NetworkProjection) GenerationID() string { return p.generationID }

// RuntimeEndpoint returns the explicit local Docker endpoint.
func (p NetworkProjection) RuntimeEndpoint() string { return p.runtimeEndpoint }

// AgentConfigurationProjection contains the static exact host merge inputs.
type AgentConfigurationProjection struct {
	agentHost                  agentconfigdomain.AgentHost
	configLocation             string
	entryID                    string
	expectedManagedEntryDigest agentconfigdomain.Digest
	launcherDigest             agentconfigdomain.Digest
	launcherPath               string
}

// AgentHost returns the exact documented agent configuration format.
func (p AgentConfigurationProjection) AgentHost() agentconfigdomain.AgentHost { return p.agentHost }

// ConfigLocation returns the explicit owner configuration path.
func (p AgentConfigurationProjection) ConfigLocation() string { return p.configLocation }

// EntryID returns the managed entry UUIDv7.
func (p AgentConfigurationProjection) EntryID() string { return p.entryID }

// ExpectedManagedEntryDigest returns the protected prior entry digest, if any.
func (p AgentConfigurationProjection) ExpectedManagedEntryDigest() agentconfigdomain.Digest {
	return p.expectedManagedEntryDigest
}

// LauncherDigest returns the exact signed launcher digest.
func (p AgentConfigurationProjection) LauncherDigest() agentconfigdomain.Digest {
	return p.launcherDigest
}

// LauncherPath returns the exact signed launcher command path.
func (p AgentConfigurationProjection) LauncherPath() string { return p.launcherPath }

// SecretFile is an immutable path-only projection for one protected secret.
type SecretFile struct {
	purpose SecretPurpose
	path    string
}

// Purpose returns the exact key-separation purpose.
func (s SecretFile) Purpose() SecretPurpose { return s.purpose }

// Path returns the exact protected host materialization path.
func (s SecretFile) Path() string { return s.path }

// ProductProjection is the immutable host product-layout authority.
type ProductProjection struct {
	releaseDirectory         string
	configurationDirectory   string
	runtimeDirectory         string
	secretDirectory          string
	backupDirectory          string
	composeProjectDirectory  string
	composeConfigurationPath string
	emptyEnvironmentPath     string
	egressAttestationPath    string
	coreEndpoint             string
	initialBrainID           string
	initialBrainName         string
	ownerPrincipalID         string
	ownerGrantID             string
	ownerSubjectDigest       install.Digest
	secretFiles              []SecretFile
}

// ReleaseDirectory returns the exact selected generation root.
func (p ProductProjection) ReleaseDirectory() string { return p.releaseDirectory }

// ConfigurationDirectory returns the owner-controlled configuration root.
func (p ProductProjection) ConfigurationDirectory() string { return p.configurationDirectory }

// RuntimeDirectory returns the owner-controlled runtime coordination root.
func (p ProductProjection) RuntimeDirectory() string { return p.runtimeDirectory }

// SecretDirectory returns the protected Docker-secret materialization root.
func (p ProductProjection) SecretDirectory() string { return p.secretDirectory }

// BackupDirectory returns the encrypted local backup root.
func (p ProductProjection) BackupDirectory() string { return p.backupDirectory }

// ComposeProjectDirectory returns the immutable Compose project root.
func (p ProductProjection) ComposeProjectDirectory() string { return p.composeProjectDirectory }

// ComposeConfigurationPath returns the exact signed Compose configuration target.
func (p ProductProjection) ComposeConfigurationPath() string { return p.composeConfigurationPath }

// EmptyEnvironmentPath returns the exact zero-entry Compose environment file.
func (p ProductProjection) EmptyEnvironmentPath() string { return p.emptyEnvironmentPath }

// EgressAttestationPath returns the exact authenticated runtime attestation path.
func (p ProductProjection) EgressAttestationPath() string { return p.egressAttestationPath }

// CoreEndpoint returns the canonical explicit-port loopback Core endpoint.
func (p ProductProjection) CoreEndpoint() string { return p.coreEndpoint }

// InitialBrainID returns the canonical UUIDv7 selected for first bootstrap.
func (p ProductProjection) InitialBrainID() string { return p.initialBrainID }

// InitialBrainName returns the normalized first local Brain name.
func (p ProductProjection) InitialBrainName() string { return p.initialBrainName }

// OwnerPrincipalID returns the canonical local owner principal identity.
func (p ProductProjection) OwnerPrincipalID() string { return p.ownerPrincipalID }

// OwnerGrantID returns the canonical initial owner grant identity.
func (p ProductProjection) OwnerGrantID() string { return p.ownerGrantID }

// OwnerSubjectDigest returns the non-reversible protected host-owner binding.
func (p ProductProjection) OwnerSubjectDigest() install.Digest { return p.ownerSubjectDigest }

// SecretFiles returns a caller-owned purpose-sorted copy.
func (p ProductProjection) SecretFiles() []SecretFile {
	return append([]SecretFile(nil), p.secretFiles...)
}

// Plan is the immutable execution authority reconstructed only from exact
// canonical schema-v1 bytes.
type Plan struct {
	canonical          []byte
	digest             install.PlanDigest
	operationID        install.OperationID
	installationID     string
	generationID       string
	runtimeEndpoint    string
	runtimeOwnership   install.RuntimeOwnership
	securityEpoch      uint64
	signedHostPlan     hostverification.SignedPlan
	hostStorageTarget  string
	signedRelease      releaseinventory.SignedManifest
	runtimeCatalogID   string
	runtimeCatalogHash install.Digest
	acquisition        artifactacquisition.Plan
	composeArtifactID  string
	capacity           Capacity
	agentConfiguration AgentConfigurationProjection
	product            ProductProjection
}

// NewV1 validates and canonicalizes one complete plan input.
func NewV1(input Input) (Plan, error) {
	document, err := documentFromInput(input)
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	return planFromDocument(document, canonical)
}

// DecodeV1 accepts only the exact canonical encoding of one understood plan.
func DecodeV1(raw []byte) (Plan, error) {
	if len(raw) == 0 || len(raw) > maximumRawPlanBytes {
		return Plan{}, ErrMalformed
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Plan{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalPlan
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Plan{}, ErrUnknownField
		}
		return Plan{}, ErrMalformed
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Plan{}, ErrMalformed
	}
	if document.SchemaVersion != SupportedSchemaMajor {
		return Plan{}, ErrUnsupportedSchema
	}
	plan, err := planFromDocument(document, raw)
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(raw, plan.canonical) {
		return Plan{}, ErrNonCanonical
	}
	return plan, nil
}

func planFromDocument(document canonicalPlan, supplied []byte) (Plan, error) {
	if document.SchemaVersion != SupportedSchemaMajor {
		return Plan{}, ErrUnsupportedSchema
	}
	input, err := inputFromDocument(document)
	if err != nil {
		return Plan{}, err
	}
	normalized, err := documentFromInput(input)
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	if supplied != nil && !bytes.Equal(supplied, canonical) {
		return Plan{}, ErrNonCanonical
	}
	digest, err := install.BindPlan(canonical)
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	manifest := input.SignedRelease.Manifest()
	acquisition, err := acquisitionFromInput(input.Artifacts, manifest)
	if err != nil {
		return Plan{}, err
	}
	runtimeResource, exists := manifestResource(manifest, input.RuntimeCatalog.ResourceID)
	if !exists || runtimeResource.Kind() != releaseinventory.ResourceKindRuntimeCatalog {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	runtimeCatalogHash, err := install.ParseDigest(runtimeResource.Digest().Hex())
	if err != nil {
		return Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	return Plan{
		canonical:          canonical,
		digest:             digest,
		operationID:        input.OperationID,
		installationID:     input.InstallationID,
		generationID:       input.GenerationID,
		runtimeEndpoint:    input.RuntimeEndpoint,
		runtimeOwnership:   input.RuntimeOwnership,
		securityEpoch:      input.SecurityEpoch,
		signedHostPlan:     input.SignedHostPlan,
		hostStorageTarget:  input.HostStorageTarget,
		signedRelease:      input.SignedRelease,
		runtimeCatalogID:   input.RuntimeCatalog.ResourceID,
		runtimeCatalogHash: runtimeCatalogHash,
		acquisition:        acquisition,
		composeArtifactID:  input.Artifacts.ComposeArtifactID,
		capacity: Capacity{
			hostCAS:          input.Artifacts.Capacity.HostCAS,
			hostRelease:      input.Artifacts.Capacity.HostRelease,
			dockerEngine:     input.Artifacts.Capacity.DockerEngine,
			dockerDataVolume: input.Artifacts.Capacity.DockerDataVolume,
		},
		agentConfiguration: AgentConfigurationProjection{
			agentHost:                  normalizedAgentHost(input.AgentConfiguration.AgentHost),
			configLocation:             input.AgentConfiguration.ConfigLocation,
			entryID:                    input.AgentConfiguration.EntryID,
			expectedManagedEntryDigest: input.AgentConfiguration.ExpectedManagedEntryDigest,
			launcherDigest:             input.AgentConfiguration.LauncherDigest,
			launcherPath:               input.AgentConfiguration.LauncherPath,
		},
		product: productProjection(input.Product),
	}, nil
}

// CanonicalBytes returns a caller-owned copy of the exact persisted authority.
func (p Plan) CanonicalBytes() []byte { return append([]byte(nil), p.canonical...) }

// Digest returns the SHA-256 binding of CanonicalBytes.
func (p Plan) Digest() install.PlanDigest { return p.digest }

// OperationID returns the sole operation authorized by the plan.
func (p Plan) OperationID() install.OperationID { return p.operationID }

// InstallationID returns the UUIDv7 installation owner.
func (p Plan) InstallationID() string { return p.installationID }

// GenerationID returns the UUIDv7 release generation.
func (p Plan) GenerationID() string { return p.generationID }

// RuntimeEndpoint returns the explicit local runtime endpoint.
func (p Plan) RuntimeEndpoint() string { return p.runtimeEndpoint }

// RuntimeOwnership returns the parent-authorized expected ownership disposition.
func (p Plan) RuntimeOwnership() install.RuntimeOwnership { return p.runtimeOwnership }

// SecurityEpoch returns the monotonic activation security epoch.
func (p Plan) SecurityEpoch() uint64 { return p.securityEpoch }

// SignedHostPlan returns the release-signed, installation-agnostic host policy
// selected and parent-bound by these canonical installation-plan bytes.
func (p Plan) SignedHostPlan() hostverification.SignedPlan { return p.signedHostPlan }

// HostStorageTarget is the per-host owner-controlled probe root bound by the
// canonical parent plan rather than the release-wide signed compatibility policy.
func (p Plan) HostStorageTarget() string { return p.hostStorageTarget }

// SignedRelease returns the immutable unverified release envelope.
func (p Plan) SignedRelease() releaseinventory.SignedManifest { return p.signedRelease }

// RuntimeCatalogResourceID returns the signed manifest resource selected for PF-006.
func (p Plan) RuntimeCatalogResourceID() string { return p.runtimeCatalogID }

// RuntimeCatalogDigest returns the exact signed runtime-catalog content binding.
func (p Plan) RuntimeCatalogDigest() install.Digest { return p.runtimeCatalogHash }

// AcquisitionPlan returns the complete immutable non-OCI acquisition projection.
func (p Plan) AcquisitionPlan() artifactacquisition.Plan { return p.acquisition }

// ComposeArtifactID returns the exact signed Compose bundle resource ID.
func (p Plan) ComposeArtifactID() string { return p.composeArtifactID }

// Capacity returns exact adapter-routing locators for live pool attestation.
func (p Plan) Capacity() Capacity { return p.capacity }

// Network returns the immutable static managed-resource projection.
func (p Plan) Network() NetworkProjection {
	return NetworkProjection{installationID: p.installationID, generationID: p.generationID, runtimeEndpoint: p.runtimeEndpoint}
}

// AgentConfiguration returns the immutable static owner configuration projection.
func (p Plan) AgentConfiguration() AgentConfigurationProjection { return p.agentConfiguration }

// Product returns the immutable exact host product layout.
func (p Plan) Product() ProductProjection { return p.product }

func documentFromInput(input Input) (canonicalPlan, error) {
	if input.OperationID.IsZero() || !validUUIDv7(input.InstallationID) || !validUUIDv7(input.GenerationID) ||
		!validLocalEndpoint(input.RuntimeEndpoint) ||
		(input.RuntimeOwnership != install.RuntimeOwnershipUndetermined && !input.RuntimeOwnership.Resolved()) ||
		input.SecurityEpoch == 0 || input.SecurityEpoch > maximumSafeJSONInt || !input.SignedHostPlan.Valid() {
		return canonicalPlan{}, ErrIntegrity
	}
	hostPolicy := input.SignedHostPlan.Plan()
	if !hostPolicy.Valid() || input.SignedHostPlan.SigningKeyID() != hostPolicy.SigningKeyID() ||
		len(input.SignedHostPlan.Signature()) > maximumEvidenceBytes {
		return canonicalPlan{}, ErrIntegrity
	}
	storageTarget := input.HostStorageTarget
	if storageTarget == "" && hostPolicy.StorageTargetMode() == hostverification.StorageTargetExact {
		storageTarget = hostPolicy.StorageTarget()
	}
	if _, _, valid := canonicalHostPath(storageTarget); !valid ||
		hostPolicy.StorageTargetMode() == hostverification.StorageTargetExact && storageTarget != hostPolicy.StorageTarget() {
		return canonicalPlan{}, ErrIntegrity
	}
	manifest := input.SignedRelease.Manifest()
	if len(manifest.CanonicalBytes()) == 0 || manifest.SchemaVersion() != releaseinventory.SupportedManifestSchemaMajor {
		return canonicalPlan{}, ErrIntegrity
	}
	policy := manifest.TrustPolicy()
	if input.SignedRelease.TrustMode() != policy.Mode() || input.SignedRelease.TrustRootID() != policy.TrustRootID() {
		return canonicalPlan{}, ErrIntegrity
	}
	if input.SignedRelease.SignatureBundleSchemaVersion() != releaseinventory.SupportedSignatureBundleSchemaMajor ||
		len(input.SignedRelease.RevocationSet()) == 0 ||
		len(input.SignedRelease.SigstoreBundle()) > maximumEvidenceBytes ||
		len(input.SignedRelease.RevocationSet()) > maximumEvidenceBytes ||
		len(input.SignedRelease.TrustedTimeEvidence()) > maximumEvidenceBytes ||
		!releaseinventory.DigestBytes(input.SignedRelease.RevocationSet()).Equal(policy.RevocationSetDigest()) {
		return canonicalPlan{}, ErrIntegrity
	}
	if input.SignedRelease.TrustMode() == releaseinventory.SignatureTrustModeCertificateTransparency &&
		len(input.SignedRelease.SigstoreBundle()) == 0 {
		return canonicalPlan{}, ErrIntegrity
	}
	if _, exists := manifestResource(manifest, input.RuntimeCatalog.ResourceID); !exists {
		return canonicalPlan{}, ErrIntegrity
	}
	canonicalAcquisition, err := canonicalAcquisitionFromInput(input.Artifacts, manifest)
	if err != nil {
		return canonicalPlan{}, err
	}
	if !validBoundedText(input.AgentConfiguration.ConfigLocation) ||
		!validBoundedText(input.AgentConfiguration.LauncherPath) ||
		input.AgentConfiguration.LauncherDigest.IsZero() || !validUUIDv7(input.AgentConfiguration.EntryID) {
		return canonicalPlan{}, ErrIntegrity
	}
	agentHost := normalizedAgentHost(input.AgentConfiguration.AgentHost)
	if _, err := agentconfigdomain.NewTargetForAgent(agentHost, input.InstallationID, input.AgentConfiguration.EntryID,
		input.AgentConfiguration.LauncherPath, input.AgentConfiguration.LauncherDigest); err != nil {
		return canonicalPlan{}, ErrIntegrity
	}
	canonicalProduct, err := canonicalProductFromInput(input.Product)
	if err != nil {
		return canonicalPlan{}, err
	}
	if input.Artifacts.Capacity.HostRelease != input.Product.ReleaseDirectory {
		return canonicalPlan{}, ErrIntegrity
	}
	if !productMatchesHost(input.Product, hostPolicy.Platform().OperatingSystem, storageTarget, input.RuntimeEndpoint) {
		return canonicalPlan{}, ErrIntegrity
	}
	return canonicalPlan{
		AgentConfiguration: canonicalAgentConfiguration{
			AgentHost:                  agentHost,
			ConfigLocation:             input.AgentConfiguration.ConfigLocation,
			EntryID:                    input.AgentConfiguration.EntryID,
			ExpectedManagedEntryDigest: optionalAgentDigest(input.AgentConfiguration.ExpectedManagedEntryDigest),
			LauncherDigest:             input.AgentConfiguration.LauncherDigest.String(),
			LauncherPath:               input.AgentConfiguration.LauncherPath,
		},
		ArtifactAcquisition: canonicalAcquisition,
		InstallationID:      input.InstallationID,
		HostPolicy: canonicalHostPolicy{
			Plan:          base64.StdEncoding.EncodeToString(hostPolicy.CanonicalBytes()),
			Signature:     base64.StdEncoding.EncodeToString(input.SignedHostPlan.Signature()),
			SigningKeyID:  input.SignedHostPlan.SigningKeyID(),
			StorageTarget: storageTarget,
		},
		NetworkVolume:    canonicalNetworkVolume{GenerationID: input.GenerationID, RuntimeEndpoint: input.RuntimeEndpoint},
		OperationID:      input.OperationID.String(),
		Product:          canonicalProduct,
		Release:          canonicalReleaseFromSigned(input.SignedRelease),
		Runtime:          canonicalRuntime{CatalogResourceID: input.RuntimeCatalog.ResourceID},
		RuntimeOwnership: input.RuntimeOwnership.String(),
		SchemaVersion:    SupportedSchemaMajor,
		SecurityEpoch:    input.SecurityEpoch,
	}, nil
}

func inputFromDocument(document canonicalPlan) (Input, error) {
	if document.Release.SignatureBundleSchemaVersion != releaseinventory.SupportedSignatureBundleSchemaMajor {
		return Input{}, ErrUnsupportedSchema
	}
	operationID, err := install.NewOperationID(document.OperationID)
	if err != nil {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	manifestBytes, err := strictBase64(document.Release.Manifest)
	if err != nil {
		return Input{}, err
	}
	manifest, err := releaseinventory.DecodeManifestV1(manifestBytes)
	if err != nil {
		if errors.Is(err, releaseinventory.ErrManifestNonCanonical) {
			return Input{}, ErrNonCanonical
		}
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	signature, err := strictBase64(document.Release.Signature)
	if err != nil {
		return Input{}, err
	}
	sigstoreBundle, err := strictBase64(document.Release.SigstoreBundle)
	if err != nil {
		return Input{}, err
	}
	revocations, err := strictBase64(document.Release.RevocationSet)
	if err != nil {
		return Input{}, err
	}
	trustedTime, err := strictBase64(document.Release.TrustedTimeEvidence)
	if err != nil {
		return Input{}, err
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion:       document.Release.SignatureBundleSchemaVersion,
		TrustMode:           releaseinventory.SignatureTrustMode(document.Release.TrustMode),
		TrustRootID:         document.Release.TrustRootID,
		Signature:           signature,
		SigstoreBundle:      sigstoreBundle,
		RevocationSet:       revocations,
		TrustedTimeEvidence: trustedTime,
	})
	if err != nil {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	ownership, ok := parseOwnership(document.RuntimeOwnership)
	if !ok {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	agentExpected, err := parseOptionalAgentDigest(document.AgentConfiguration.ExpectedManagedEntryDigest)
	if err != nil {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	agentLauncher, err := agentconfigdomain.DigestFromHex(document.AgentConfiguration.LauncherDigest)
	if err != nil {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	artifacts, err := artifactInputFromCanonical(document.ArtifactAcquisition)
	if err != nil {
		return Input{}, err
	}
	hostPlanBytes, err := strictBase64(document.HostPolicy.Plan)
	if err != nil {
		return Input{}, err
	}
	hostPlan, err := hostverification.DecodePlan(hostPlanBytes)
	if err != nil {
		if errors.Is(err, hostverification.ErrNonCanonical) {
			return Input{}, ErrNonCanonical
		}
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	hostSignature, err := strictBase64(document.HostPolicy.Signature)
	if err != nil {
		return Input{}, err
	}
	signedHostPlan, err := hostverification.NewSignedPlan(hostPlan, document.HostPolicy.SigningKeyID, hostSignature)
	if err != nil {
		return Input{}, fmt.Errorf("%w", ErrIntegrity)
	}
	product, err := productInputFromCanonical(document.Product)
	if err != nil {
		return Input{}, err
	}
	return Input{
		OperationID:       operationID,
		InstallationID:    document.InstallationID,
		GenerationID:      document.NetworkVolume.GenerationID,
		RuntimeEndpoint:   document.NetworkVolume.RuntimeEndpoint,
		RuntimeOwnership:  ownership,
		SecurityEpoch:     document.SecurityEpoch,
		SignedHostPlan:    signedHostPlan,
		HostStorageTarget: document.HostPolicy.StorageTarget,
		SignedRelease:     signed,
		Product:           product,
		RuntimeCatalog:    RuntimeCatalogInput{ResourceID: document.Runtime.CatalogResourceID},
		Artifacts:         artifacts,
		AgentConfiguration: AgentConfigurationInput{
			AgentHost:                  document.AgentConfiguration.AgentHost,
			ConfigLocation:             document.AgentConfiguration.ConfigLocation,
			EntryID:                    document.AgentConfiguration.EntryID,
			ExpectedManagedEntryDigest: agentExpected,
			LauncherDigest:             agentLauncher,
			LauncherPath:               document.AgentConfiguration.LauncherPath,
		},
	}, nil
}

func canonicalAcquisitionFromInput(input ArtifactInput, manifest releaseinventory.Manifest) (canonicalArtifactAcquisition, error) {
	if input.ComposeArtifactID == "" || input.RollbackHeadroomBytes == 0 || input.SafetyHeadroomBytes == 0 ||
		!input.ProxyMode.Valid() ||
		!validBoundedText(input.Capacity.HostCAS) || !validBoundedText(input.Capacity.HostRelease) ||
		!validBoundedText(input.Capacity.DockerEngine) ||
		!validBoundedText(input.Capacity.DockerDataVolume) {
		return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
	}
	artifacts := append([]artifactacquisition.ArtifactInput(nil), input.Artifacts...)
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].ID < artifacts[right].ID })
	documents := make([]canonicalArtifact, 0, len(artifacts))
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if _, duplicate := seen[artifact.ID]; duplicate {
			return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
		}
		seen[artifact.ID] = struct{}{}
		resource, exists := manifestResource(manifest, artifact.ID)
		if !exists || resource.Kind() == releaseinventory.ResourceKindOCIImage ||
			resource.Kind() == releaseinventory.ResourceKindOCIIndex || artifact.Digest != resource.Digest() ||
			artifact.Size != resource.Size() {
			return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
		}
		sources := append([]string(nil), artifact.Sources...)
		sort.Strings(sources)
		if !slices.Equal(sources, resource.SourceAllowlist()) {
			return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
		}
		target, expanded := resource.ExpandedTarget()
		if expanded {
			if artifact.ExpandedBytes != target.Bytes() || !artifact.ExpandedDigest.Equal(target.Digest()) ||
				artifact.TargetKind != target.Kind() || artifact.TargetStorageID != target.StorageID() ||
				!artifact.TargetAuthorityDigest.Equal(target.AuthorityDigest()) {
				return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
			}
		} else if artifact.ExpandedBytes != 0 || !artifact.ExpandedDigest.IsZero() || artifact.TargetKind != "" ||
			artifact.TargetStorageID != "" || !artifact.TargetAuthorityDigest.IsZero() {
			return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
		}
		chunks := make([]canonicalChunk, 0, len(artifact.Chunks))
		for _, chunk := range artifact.Chunks {
			chunks = append(chunks, canonicalChunk{Digest: chunk.Digest.Hex(), Offset: chunk.Offset, Size: chunk.Size})
		}
		documents = append(documents, canonicalArtifact{
			Chunks:                chunks,
			Digest:                artifact.Digest.Hex(),
			ExpandedBytes:         artifact.ExpandedBytes,
			ExpandedDigest:        optionalReleaseDigest(artifact.ExpandedDigest),
			ID:                    artifact.ID,
			Size:                  artifact.Size,
			Sources:               sources,
			TargetAuthorityDigest: optionalReleaseDigest(artifact.TargetAuthorityDigest),
			TargetKind:            string(artifact.TargetKind), TargetStorageID: artifact.TargetStorageID,
		})
	}
	compose, exists := manifestResource(manifest, input.ComposeArtifactID)
	if !exists || compose.Kind() != releaseinventory.ResourceKindComposeBundle {
		return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
	}
	if _, included := seen[input.ComposeArtifactID]; !included {
		return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
	}
	for _, resource := range manifest.Resources() {
		if resource.Kind() == releaseinventory.ResourceKindOCIImage || resource.Kind() == releaseinventory.ResourceKindOCIIndex {
			continue
		}
		if _, included := seen[resource.ID()]; !included {
			return canonicalArtifactAcquisition{}, fmt.Errorf("%w", ErrIntegrity)
		}
	}
	document := canonicalArtifactAcquisition{
		Artifacts:                   documents,
		ComposeArtifactID:           input.ComposeArtifactID,
		ProxyMode:                   input.ProxyMode,
		DockerEngineCapacityLocator: input.Capacity.DockerEngine,
		DockerVolumeCapacityLocator: input.Capacity.DockerDataVolume,
		HostCASCapacityLocator:      input.Capacity.HostCAS,
		HostReleaseCapacityLocator:  input.Capacity.HostRelease,
		RollbackHeadroomBytes:       input.RollbackHeadroomBytes,
		SafetyHeadroomBytes:         input.SafetyHeadroomBytes,
	}
	if _, err := acquisitionFromCanonical(document); err != nil {
		return canonicalArtifactAcquisition{}, err
	}
	return document, nil
}

func acquisitionFromInput(input ArtifactInput, manifest releaseinventory.Manifest) (artifactacquisition.Plan, error) {
	document, err := canonicalAcquisitionFromInput(input, manifest)
	if err != nil {
		return artifactacquisition.Plan{}, err
	}
	return acquisitionFromCanonical(document)
}

func acquisitionFromCanonical(document canonicalArtifactAcquisition) (artifactacquisition.Plan, error) {
	canonical, err := json.Marshal(document)
	if err != nil {
		return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	inputs := make([]artifactacquisition.ArtifactInput, 0, len(document.Artifacts))
	var download uint64
	var expanded uint64
	for _, artifact := range document.Artifacts {
		digest, err := releaseinventory.ParseDigest(artifact.Digest)
		if err != nil {
			return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
		}
		expandedDigest, err := parseOptionalReleaseDigest(artifact.ExpandedDigest)
		if err != nil {
			return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
		}
		targetAuthorityDigest, err := parseOptionalReleaseDigest(artifact.TargetAuthorityDigest)
		if err != nil {
			return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
		}
		chunks := make([]artifactacquisition.ChunkInput, 0, len(artifact.Chunks))
		for _, chunk := range artifact.Chunks {
			chunkDigest, parseError := releaseinventory.ParseDigest(chunk.Digest)
			if parseError != nil {
				return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
			}
			chunks = append(chunks, artifactacquisition.ChunkInput{Offset: chunk.Offset, Size: chunk.Size, Digest: chunkDigest})
		}
		inputs = append(inputs, artifactacquisition.ArtifactInput{
			ID: artifact.ID, Digest: digest, Size: artifact.Size, ExpandedBytes: artifact.ExpandedBytes,
			ExpandedDigest: expandedDigest, TargetKind: releaseinventory.ExpandedTargetKind(artifact.TargetKind),
			TargetStorageID: artifact.TargetStorageID, TargetAuthorityDigest: targetAuthorityDigest,
			Sources: append([]string(nil), artifact.Sources...), Chunks: chunks,
		})
		var addError error
		download, addError = checkedAdd(download, artifact.Size)
		if addError == nil {
			expanded, addError = checkedAdd(expanded, artifact.ExpandedBytes)
		}
		if addError != nil {
			return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
		}
	}
	required, err := checkedAdd(download, expanded)
	if err == nil {
		required, err = checkedAdd(required, document.RollbackHeadroomBytes)
	}
	if err == nil {
		required, err = checkedAdd(required, document.SafetyHeadroomBytes)
	}
	if err != nil {
		return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes(canonical),
		ProxyMode:  document.ProxyMode,
		Artifacts:  inputs,
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: download, ExpandedBytes: expanded,
			RollbackHeadroomBytes: document.RollbackHeadroomBytes,
			SafetyHeadroomBytes:   document.SafetyHeadroomBytes, RequiredBytes: required,
		},
	})
	if err != nil {
		return artifactacquisition.Plan{}, fmt.Errorf("%w", ErrIntegrity)
	}
	return plan, nil
}

func artifactInputFromCanonical(document canonicalArtifactAcquisition) (ArtifactInput, error) {
	artifacts := make([]artifactacquisition.ArtifactInput, 0, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		digest, err := releaseinventory.ParseDigest(artifact.Digest)
		if err != nil {
			return ArtifactInput{}, fmt.Errorf("%w", ErrIntegrity)
		}
		expandedDigest, err := parseOptionalReleaseDigest(artifact.ExpandedDigest)
		if err != nil {
			return ArtifactInput{}, fmt.Errorf("%w", ErrIntegrity)
		}
		targetAuthorityDigest, err := parseOptionalReleaseDigest(artifact.TargetAuthorityDigest)
		if err != nil {
			return ArtifactInput{}, fmt.Errorf("%w", ErrIntegrity)
		}
		chunks := make([]artifactacquisition.ChunkInput, 0, len(artifact.Chunks))
		for _, chunk := range artifact.Chunks {
			chunkDigest, parseError := releaseinventory.ParseDigest(chunk.Digest)
			if parseError != nil {
				return ArtifactInput{}, fmt.Errorf("%w", ErrIntegrity)
			}
			chunks = append(chunks, artifactacquisition.ChunkInput{Offset: chunk.Offset, Size: chunk.Size, Digest: chunkDigest})
		}
		artifacts = append(artifacts, artifactacquisition.ArtifactInput{
			ID: artifact.ID, Digest: digest, Size: artifact.Size, ExpandedBytes: artifact.ExpandedBytes,
			ExpandedDigest: expandedDigest, TargetKind: releaseinventory.ExpandedTargetKind(artifact.TargetKind),
			TargetStorageID: artifact.TargetStorageID, TargetAuthorityDigest: targetAuthorityDigest,
			Sources: append([]string(nil), artifact.Sources...), Chunks: chunks,
		})
	}
	return ArtifactInput{
		ComposeArtifactID:     document.ComposeArtifactID,
		ProxyMode:             document.ProxyMode,
		Artifacts:             artifacts,
		RollbackHeadroomBytes: document.RollbackHeadroomBytes,
		SafetyHeadroomBytes:   document.SafetyHeadroomBytes,
		Capacity: CapacityInput{
			HostCAS:          document.HostCASCapacityLocator,
			HostRelease:      document.HostReleaseCapacityLocator,
			DockerEngine:     document.DockerEngineCapacityLocator,
			DockerDataVolume: document.DockerVolumeCapacityLocator,
		},
	}, nil
}

func canonicalProductFromInput(input ProductInput) (canonicalProduct, error) {
	directories := []string{
		input.ReleaseDirectory,
		input.ConfigurationDirectory,
		input.RuntimeDirectory,
		input.SecretDirectory,
		input.BackupDirectory,
		input.ComposeProjectDirectory,
	}
	seenDirectories := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if _, _, ok := canonicalHostPath(directory); !ok {
			return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
		}
		if _, duplicate := seenDirectories[directory]; duplicate {
			return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
		}
		seenDirectories[directory] = struct{}{}
	}
	if !strictHostPathChild(input.ReleaseDirectory, input.ComposeProjectDirectory) ||
		!strictHostPathChild(input.ComposeProjectDirectory, input.ComposeConfigurationPath) ||
		!strictHostPathChild(input.ComposeProjectDirectory, input.EmptyEnvironmentPath) ||
		input.ComposeConfigurationPath == input.EmptyEnvironmentPath ||
		!strictHostPathChild(input.RuntimeDirectory, input.EgressAttestationPath) ||
		!validLoopbackCoreEndpoint(input.CoreEndpoint) || !validUUIDv7(input.InitialBrainID) ||
		!validBrainName(input.InitialBrainName) || !validUUIDv7(input.OwnerPrincipalID) ||
		!validUUIDv7(input.OwnerGrantID) || input.OwnerSubjectDigest.IsZero() {
		return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
	}

	files := append([]SecretFileInput(nil), input.SecretFiles...)
	sort.Slice(files, func(left, right int) bool { return files[left].Purpose < files[right].Purpose })
	if len(files) != len(requiredSecretPurposes) {
		return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
	}
	seenPaths := make(map[string]struct{}, len(files))
	canonicalFiles := make([]canonicalSecretFile, 0, len(files))
	for index, required := range requiredSecretPurposes {
		if files[index].Purpose != required || !strictHostPathChild(input.SecretDirectory, files[index].Path) {
			return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
		}
		if _, duplicate := seenPaths[files[index].Path]; duplicate {
			return canonicalProduct{}, fmt.Errorf("%w", ErrIntegrity)
		}
		seenPaths[files[index].Path] = struct{}{}
		canonicalFiles = append(canonicalFiles, canonicalSecretFile{Purpose: required, Path: files[index].Path})
	}
	return canonicalProduct{
		BackupDirectory: input.BackupDirectory, ComposeConfigurationPath: input.ComposeConfigurationPath,
		ComposeProjectDirectory: input.ComposeProjectDirectory, ConfigurationDirectory: input.ConfigurationDirectory,
		CoreEndpoint: input.CoreEndpoint, EgressAttestationPath: input.EgressAttestationPath,
		EmptyEnvironmentPath: input.EmptyEnvironmentPath, InitialBrainID: input.InitialBrainID,
		InitialBrainName: input.InitialBrainName, OwnerPrincipalID: input.OwnerPrincipalID,
		OwnerGrantID: input.OwnerGrantID, OwnerSubjectDigest: input.OwnerSubjectDigest.String(),
		ReleaseDirectory: input.ReleaseDirectory, RuntimeDirectory: input.RuntimeDirectory,
		SecretDirectory: input.SecretDirectory, SecretFiles: canonicalFiles,
	}, nil
}

func productInputFromCanonical(document canonicalProduct) (ProductInput, error) {
	files := make([]SecretFileInput, 0, len(document.SecretFiles))
	for _, file := range document.SecretFiles {
		files = append(files, SecretFileInput{Purpose: file.Purpose, Path: file.Path})
	}
	input := ProductInput{
		ReleaseDirectory: document.ReleaseDirectory, ConfigurationDirectory: document.ConfigurationDirectory,
		RuntimeDirectory: document.RuntimeDirectory, SecretDirectory: document.SecretDirectory,
		BackupDirectory: document.BackupDirectory, ComposeProjectDirectory: document.ComposeProjectDirectory,
		ComposeConfigurationPath: document.ComposeConfigurationPath, EmptyEnvironmentPath: document.EmptyEnvironmentPath,
		EgressAttestationPath: document.EgressAttestationPath, CoreEndpoint: document.CoreEndpoint,
		InitialBrainID: document.InitialBrainID, InitialBrainName: document.InitialBrainName,
		OwnerPrincipalID: document.OwnerPrincipalID, OwnerGrantID: document.OwnerGrantID,
		SecretFiles: files,
	}
	ownerDigest, err := install.ParseDigest(document.OwnerSubjectDigest)
	if err != nil {
		return ProductInput{}, fmt.Errorf("%w", ErrIntegrity)
	}
	input.OwnerSubjectDigest = ownerDigest
	if _, err := canonicalProductFromInput(input); err != nil {
		return ProductInput{}, err
	}
	return input, nil
}

func productProjection(input ProductInput) ProductProjection {
	files := append([]SecretFileInput(nil), input.SecretFiles...)
	sort.Slice(files, func(left, right int) bool { return files[left].Purpose < files[right].Purpose })
	projected := make([]SecretFile, 0, len(files))
	for _, file := range files {
		projected = append(projected, SecretFile{purpose: file.Purpose, path: file.Path})
	}
	return ProductProjection{
		releaseDirectory: input.ReleaseDirectory, configurationDirectory: input.ConfigurationDirectory,
		runtimeDirectory: input.RuntimeDirectory, secretDirectory: input.SecretDirectory,
		backupDirectory: input.BackupDirectory, composeProjectDirectory: input.ComposeProjectDirectory,
		composeConfigurationPath: input.ComposeConfigurationPath, emptyEnvironmentPath: input.EmptyEnvironmentPath,
		egressAttestationPath: input.EgressAttestationPath, coreEndpoint: input.CoreEndpoint,
		initialBrainID: input.InitialBrainID, initialBrainName: input.InitialBrainName,
		ownerPrincipalID: input.OwnerPrincipalID, ownerGrantID: input.OwnerGrantID,
		ownerSubjectDigest: input.OwnerSubjectDigest, secretFiles: projected,
	}
}

func productMatchesHost(
	input ProductInput,
	operatingSystem hostverification.OperatingSystem,
	storageTarget string,
	runtimeEndpoint string,
) bool {
	wantUnix := operatingSystem == hostverification.OperatingSystemLinux ||
		operatingSystem == hostverification.OperatingSystemMacOS
	if !wantUnix && operatingSystem != hostverification.OperatingSystemWindows {
		return false
	}
	if wantUnix != strings.HasPrefix(runtimeEndpoint, "unix:///") {
		return false
	}
	if !wantUnix && !strings.HasPrefix(runtimeEndpoint, "npipe:////./pipe/") {
		return false
	}
	paths := []string{
		input.ReleaseDirectory, input.ConfigurationDirectory, input.RuntimeDirectory,
		input.SecretDirectory, input.BackupDirectory, input.ComposeProjectDirectory,
		input.ComposeConfigurationPath, input.EmptyEnvironmentPath, input.EgressAttestationPath,
	}
	for _, secret := range input.SecretFiles {
		paths = append(paths, secret.Path)
	}
	for _, path := range paths {
		_, isUnix, valid := canonicalHostPath(path)
		if !valid || isUnix != wantUnix || !strictHostPathChild(storageTarget, path) {
			return false
		}
	}
	return true
}

type hostPathIdentity struct {
	root       string
	components []string
}

func canonicalHostPath(value string) (hostPathIdentity, bool, bool) {
	if value == "" || len(value) > 4096 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n") {
		return hostPathIdentity{}, false, false
	}
	if strings.HasPrefix(value, "/") {
		if value == "/" || strings.HasPrefix(value, "//") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
			return hostPathIdentity{}, false, false
		}
		components := strings.Split(strings.TrimPrefix(value, "/"), "/")
		if !safeHostPathComponents(components) {
			return hostPathIdentity{}, false, false
		}
		return hostPathIdentity{root: "/", components: components}, true, true
	}
	if len(value) < 4 || value[0] < 'A' || value[0] > 'Z' || value[1] != ':' || value[2] != '\\' ||
		strings.Contains(value, "/") || strings.Contains(value[3:], "\\\\") || strings.HasSuffix(value, "\\") {
		return hostPathIdentity{}, false, false
	}
	components := strings.Split(value[3:], "\\")
	if !safeHostPathComponents(components) {
		return hostPathIdentity{}, false, false
	}
	for _, component := range components {
		if strings.ContainsAny(component, `<>:"|?*`) || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return hostPathIdentity{}, false, false
		}
	}
	return hostPathIdentity{root: value[:3], components: components}, false, true
}

func safeHostPathComponents(components []string) bool {
	if len(components) == 0 || len(components) > 128 {
		return false
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return false
		}
	}
	return true
}

func strictHostPathChild(parent, child string) bool {
	parentIdentity, _, parentOK := canonicalHostPath(parent)
	childIdentity, _, childOK := canonicalHostPath(child)
	if !parentOK || !childOK || parentIdentity.root != childIdentity.root ||
		len(childIdentity.components) <= len(parentIdentity.components) {
		return false
	}
	return slices.Equal(parentIdentity.components, childIdentity.components[:len(parentIdentity.components)])
}

func validLoopbackCoreEndpoint(value string) bool {
	portText := ""
	switch {
	case strings.HasPrefix(value, "http://127.0.0.1:"):
		portText = strings.TrimPrefix(value, "http://127.0.0.1:")
	case strings.HasPrefix(value, "http://[::1]:"):
		portText = strings.TrimPrefix(value, "http://[::1]:")
	default:
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == portText
}

func validBrainName(value string) bool {
	if len(value) == 0 || len(value) > 63 ||
		(value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func canonicalReleaseFromSigned(signed releaseinventory.SignedManifest) canonicalRelease {
	return canonicalRelease{
		Manifest:                     base64.StdEncoding.EncodeToString(signed.Manifest().CanonicalBytes()),
		RevocationSet:                base64.StdEncoding.EncodeToString(signed.RevocationSet()),
		Signature:                    base64.StdEncoding.EncodeToString(signed.Signature()),
		SignatureBundleSchemaVersion: signed.SignatureBundleSchemaVersion(),
		SigstoreBundle:               base64.StdEncoding.EncodeToString(signed.SigstoreBundle()),
		TrustMode:                    string(signed.TrustMode()),
		TrustRootID:                  signed.TrustRootID(),
		TrustedTimeEvidence:          base64.StdEncoding.EncodeToString(signed.TrustedTimeEvidence()),
	}
}

func strictBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximumEvidenceBytes || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%w", ErrIntegrity)
	}
	return decoded, nil
}

func manifestResource(manifest releaseinventory.Manifest, id string) (releaseinventory.Resource, bool) {
	if id == "" {
		return releaseinventory.Resource{}, false
	}
	for _, resource := range manifest.Resources() {
		if resource.ID() == id {
			return resource, true
		}
	}
	return releaseinventory.Resource{}, false
}

func parseOwnership(value string) (install.RuntimeOwnership, bool) {
	switch value {
	case install.RuntimeOwnershipUndetermined.String():
		return install.RuntimeOwnershipUndetermined, true
	case install.RuntimeOwnershipReusedExternal.String():
		return install.RuntimeOwnershipReusedExternal, true
	case install.RuntimeOwnershipProvisionedByAgentMemory.String():
		return install.RuntimeOwnershipProvisionedByAgentMemory, true
	default:
		return install.RuntimeOwnershipUnknown, false
	}
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validLocalEndpoint(value string) bool {
	if !validBoundedText(value) {
		return false
	}
	if strings.HasPrefix(value, "unix:///") {
		path := strings.TrimPrefix(value, "unix://")
		if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			return false
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || segment == ".." {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(value, "npipe:////./pipe/") {
		name := strings.TrimPrefix(value, "npipe:////./pipe/")
		return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`)
	}
	return false
}

func validBoundedText(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func optionalAgentDigest(digest agentconfigdomain.Digest) string {
	if digest.IsZero() {
		return ""
	}
	return digest.String()
}

func parseOptionalAgentDigest(value string) (agentconfigdomain.Digest, error) {
	if value == "" {
		return agentconfigdomain.Digest{}, nil
	}
	return agentconfigdomain.DigestFromHex(value)
}

func optionalReleaseDigest(digest releaseinventory.Digest) string {
	if digest.IsZero() {
		return ""
	}
	return digest.Hex()
}

func parseOptionalReleaseDigest(value string) (releaseinventory.Digest, error) {
	if value == "" {
		return releaseinventory.Digest{}, nil
	}
	return releaseinventory.ParseDigest(value)
}

func checkedAdd(left, right uint64) (uint64, error) {
	if left > maximumSafeJSONInt || right > maximumSafeJSONInt || right > maximumSafeJSONInt-left {
		return 0, ErrIntegrity
	}
	return left + right, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ErrMalformed
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumJSONDepth {
		return ErrMalformed
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrMalformed
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return ErrMalformed
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrMalformed
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrDuplicateKey
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return ErrMalformed
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return ErrMalformed
		}
	default:
		return ErrMalformed
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrMalformed
}

type canonicalPlan struct {
	AgentConfiguration  canonicalAgentConfiguration  `json:"agent_configuration"`
	ArtifactAcquisition canonicalArtifactAcquisition `json:"artifact_acquisition"`
	HostPolicy          canonicalHostPolicy          `json:"host_policy"`
	InstallationID      string                       `json:"installation_id"`
	NetworkVolume       canonicalNetworkVolume       `json:"network_volume"`
	OperationID         string                       `json:"operation_id"`
	Product             canonicalProduct             `json:"product"`
	Release             canonicalRelease             `json:"release"`
	Runtime             canonicalRuntime             `json:"runtime"`
	RuntimeOwnership    string                       `json:"runtime_ownership"`
	SchemaVersion       uint16                       `json:"schema_version"`
	SecurityEpoch       uint64                       `json:"security_epoch"`
}

type canonicalHostPolicy struct {
	Plan          string `json:"plan"`
	Signature     string `json:"signature"`
	SigningKeyID  string `json:"signing_key_id"`
	StorageTarget string `json:"storage_target"`
}

type canonicalProduct struct {
	BackupDirectory          string                `json:"backup_directory"`
	ComposeConfigurationPath string                `json:"compose_configuration_path"`
	ComposeProjectDirectory  string                `json:"compose_project_directory"`
	ConfigurationDirectory   string                `json:"configuration_directory"`
	CoreEndpoint             string                `json:"core_endpoint"`
	EgressAttestationPath    string                `json:"egress_attestation_path"`
	EmptyEnvironmentPath     string                `json:"empty_environment_path"`
	InitialBrainID           string                `json:"initial_brain_id"`
	InitialBrainName         string                `json:"initial_brain_name"`
	OwnerGrantID             string                `json:"owner_grant_id"`
	OwnerPrincipalID         string                `json:"owner_principal_id"`
	OwnerSubjectDigest       string                `json:"owner_subject_digest"`
	ReleaseDirectory         string                `json:"release_directory"`
	RuntimeDirectory         string                `json:"runtime_directory"`
	SecretDirectory          string                `json:"secret_directory"`
	SecretFiles              []canonicalSecretFile `json:"secret_files"`
}

type canonicalSecretFile struct {
	Path    string        `json:"path"`
	Purpose SecretPurpose `json:"purpose"`
}

type canonicalAgentConfiguration struct {
	AgentHost                  agentconfigdomain.AgentHost `json:"agent_host"`
	ConfigLocation             string                      `json:"config_location"`
	EntryID                    string                      `json:"entry_id"`
	ExpectedManagedEntryDigest string                      `json:"expected_managed_entry_digest"`
	LauncherDigest             string                      `json:"launcher_digest"`
	LauncherPath               string                      `json:"launcher_path"`
}

type canonicalArtifactAcquisition struct {
	Artifacts                   []canonicalArtifact           `json:"artifacts"`
	ComposeArtifactID           string                        `json:"compose_artifact_id"`
	DockerEngineCapacityLocator string                        `json:"docker_engine_capacity_locator"`
	DockerVolumeCapacityLocator string                        `json:"docker_volume_capacity_locator"`
	HostCASCapacityLocator      string                        `json:"host_cas_capacity_locator"`
	HostReleaseCapacityLocator  string                        `json:"host_release_capacity_locator"`
	ProxyMode                   artifactacquisition.ProxyMode `json:"proxy_mode"`
	RollbackHeadroomBytes       uint64                        `json:"rollback_headroom_bytes"`
	SafetyHeadroomBytes         uint64                        `json:"safety_headroom_bytes"`
}

type canonicalArtifact struct {
	Chunks                []canonicalChunk `json:"chunks"`
	Digest                string           `json:"digest"`
	ExpandedBytes         uint64           `json:"expanded_bytes"`
	ExpandedDigest        string           `json:"expanded_digest"`
	ID                    string           `json:"id"`
	Size                  uint64           `json:"size"`
	Sources               []string         `json:"sources"`
	TargetAuthorityDigest string           `json:"target_authority_digest"`
	TargetKind            string           `json:"target_kind"`
	TargetStorageID       string           `json:"target_storage_id"`
}

type canonicalChunk struct {
	Digest string `json:"digest"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

type canonicalNetworkVolume struct {
	GenerationID    string `json:"generation_id"`
	RuntimeEndpoint string `json:"runtime_endpoint"`
}

type canonicalRelease struct {
	Manifest                     string `json:"manifest"`
	RevocationSet                string `json:"revocation_set"`
	Signature                    string `json:"signature"`
	SignatureBundleSchemaVersion uint16 `json:"signature_bundle_schema_version"`
	SigstoreBundle               string `json:"sigstore_bundle"`
	TrustMode                    string `json:"trust_mode"`
	TrustRootID                  string `json:"trust_root_id"`
	TrustedTimeEvidence          string `json:"trusted_time_evidence"`
}

type canonicalRuntime struct {
	CatalogResourceID string `json:"catalog_resource_id"`
}
