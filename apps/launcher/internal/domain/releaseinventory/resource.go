package releaseinventory

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// ResourceKind is the closed release-resource vocabulary understood by the
// launcher. Unknown kinds require a manifest-major change before execution.
type ResourceKind string

// Supported resource kinds in manifest schema v1.
const (
	ResourceKindLauncher            ResourceKind = "launcher"
	ResourceKindHelper              ResourceKind = "helper"
	ResourceKindComposeBundle       ResourceKind = "compose_bundle"
	ResourceKindOCIImage            ResourceKind = "oci_image"
	ResourceKindOCIIndex            ResourceKind = "oci_index"
	ResourceKindSchema              ResourceKind = "schema"
	ResourceKindMigration           ResourceKind = "migration"
	ResourceKindSetupUI             ResourceKind = "setup_ui"
	ResourceKindVerifier            ResourceKind = "verifier"
	ResourceKindModel               ResourceKind = "model"
	ResourceKindTokenizer           ResourceKind = "tokenizer"
	ResourceKindTemplate            ResourceKind = "template"
	ResourceKindInstallPlanTemplate ResourceKind = "install_plan_template"
	ResourceKindOfflineComponent    ResourceKind = "offline_bundle_component"
	ResourceKindRuntimeCatalog      ResourceKind = "runtime_catalog"
	ResourceKindCycloneDXSBOM       ResourceKind = "cyclonedx_sbom"
	ResourceKindSPDXSBOM            ResourceKind = "spdx_sbom"
	ResourceKindProvenance          ResourceKind = "provenance"
	ResourceKindLicense             ResourceKind = "license"
	ResourceKindVulnerabilityReport ResourceKind = "vulnerability_report"
)

// ResourcePurpose is the closed execution purpose declared independently of
// a resource's transport and filename.
type ResourcePurpose string

// Supported execution and evidence purposes in manifest schema v1.
const (
	ResourcePurposeNativeLauncher      ResourcePurpose = "native_launcher"
	ResourcePurposeNativeHelper        ResourcePurpose = "native_helper"
	ResourcePurposeComposeLock         ResourcePurpose = "compose_lock"
	ResourcePurposeOCIPlatformManifest ResourcePurpose = "oci_platform_manifest"
	ResourcePurposeOCIIndex            ResourcePurpose = "oci_multiarch_index"
	ResourcePurposeContractBundle      ResourcePurpose = "contract_bundle"
	ResourcePurposeMigrationSet        ResourcePurpose = "migration_set"
	ResourcePurposeSetupUI             ResourcePurpose = "setup_ui"
	ResourcePurposeOfflineVerifier     ResourcePurpose = "offline_verifier"
	ResourcePurposeModelWeights        ResourcePurpose = "model_weights"
	ResourcePurposeTokenizer           ResourcePurpose = "tokenizer"
	ResourcePurposePromptTemplate      ResourcePurpose = "prompt_template"
	ResourcePurposeInstallPlanTemplate ResourcePurpose = "install_plan_template"
	ResourcePurposeOfflineComponent    ResourcePurpose = "offline_bundle_component"
	ResourcePurposeRuntimeCatalog      ResourcePurpose = "runtime_catalog"
	ResourcePurposeCycloneDXSBOM       ResourcePurpose = "cyclonedx_sbom"
	ResourcePurposeSPDXSBOM            ResourcePurpose = "spdx_sbom"
	ResourcePurposeSLSAProvenance      ResourcePurpose = "slsa_provenance"
	ResourcePurposeLicenseEvaluation   ResourcePurpose = "license_evaluation"
	ResourcePurposeVulnerabilityReport ResourcePurpose = "vulnerability_evaluation"
)

// QualificationResult is the closed release qualification result vocabulary.
type QualificationResult string

// QualificationResultPassed is the only result that can authorize installation.
const QualificationResultPassed QualificationResult = "passed"

// LocalProviderRole is the closed mandatory local provider vocabulary.
type LocalProviderRole string

// Mandatory local provider roles in PF-001.
const (
	LocalProviderRoleEmbedding  LocalProviderRole = "embedding"
	LocalProviderRoleReranking  LocalProviderRole = "reranking"
	LocalProviderRoleExtraction LocalProviderRole = "extraction"
)

// Valid reports whether the local provider role is understood by schema v1.
func (r LocalProviderRole) Valid() bool {
	return r == LocalProviderRoleEmbedding || r == LocalProviderRoleReranking ||
		r == LocalProviderRoleExtraction
}

// Canonical media types understood by manifest schema v1.
const (
	MediaTypeNativeExecutable        = "application/vnd.agentmemory.native-executable"
	MediaTypeComposeLock             = "application/vnd.docker.compose.project+yaml"
	MediaTypeOCIManifest             = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex                = "application/vnd.oci.image.index.v1+json"
	MediaTypeContractBundle          = "application/vnd.agentmemory.contract-bundle+tar"
	MediaTypeMigrationSet            = "application/vnd.agentmemory.migration-set+tar"
	MediaTypeSetupUI                 = "application/vnd.agentmemory.setup-ui+tar"
	MediaTypeModelWeights            = "application/vnd.agentmemory.model-weights"
	MediaTypeTokenizer               = "application/vnd.agentmemory.tokenizer+json"
	MediaTypePromptTemplate          = "text/vnd.agentmemory.prompt-template"
	MediaTypeInstallPlanTemplate     = "application/vnd.agentmemory.install-plan-template+json"
	MediaTypeOfflineComponent        = "application/vnd.agentmemory.offline-component"
	MediaTypeRuntimeCatalog          = "application/vnd.agentmemory.runtime-catalog+json"
	MediaTypeCycloneDX               = "application/vnd.cyclonedx+json"
	MediaTypeSPDX                    = "application/spdx+json"
	MediaTypeSLSAProvenance          = "application/vnd.in-toto+json"
	MediaTypeLicenseEvaluation       = "application/vnd.agentmemory.license-evaluation+json"
	MediaTypeVulnerabilityEvaluation = "application/vnd.agentmemory.vulnerability-evaluation+json"
)

// ResourceInput is copied and validated by NewResource.
type ResourceInput struct {
	ID                      string
	Kind                    ResourceKind
	Purpose                 ResourcePurpose
	MediaType               string
	ProviderRole            LocalProviderRole
	Platform                Platform
	Digest                  Digest
	OCIIndexDigest          Digest
	OCIIndexResourceID      string
	Size                    uint64
	SourceRef               string
	SourceAllowlist         []string
	CycloneDXSBOMResourceID string
	SPDXSBOMResourceID      string
	ProvenanceResourceID    string
	LicenseResourceID       string
	VulnerabilityResourceID string
	NativePublisherIdentity string
	NativePublisherPolicyID string
	SubjectResourceID       string
	SubjectDigest           Digest
	PolicySnapshotDigest    Digest
	QualificationResult     QualificationResult
	QualificationExpiresAt  time.Time
	ExpandedTarget          ReleaseExpandedTargetInput
}

// Resource is one immutable, content-addressed release subject or evidence
// document. SourceRef is acquisition metadata, never proof of identity.
type Resource struct {
	id                      string
	kind                    ResourceKind
	purpose                 ResourcePurpose
	mediaType               string
	providerRole            LocalProviderRole
	platform                Platform
	digest                  Digest
	ociIndexDigest          Digest
	ociIndexResourceID      string
	size                    uint64
	sourceRef               string
	sourceAllowlist         []string
	cycloneDXSBOMResourceID string
	spdxSBOMResourceID      string
	provenanceResourceID    string
	licenseResourceID       string
	vulnerabilityResourceID string
	nativePublisherIdentity string
	nativePublisherPolicyID string
	subjectResourceID       string
	subjectDigest           Digest
	policySnapshotDigest    Digest
	qualificationResult     QualificationResult
	qualificationExpiresAt  int64
	expandedTarget          ReleaseExpandedTarget
}

// NewResource constructs a closed, digest-pinned resource descriptor.
func NewResource(input ResourceInput) (Resource, error) {
	if !validIdentifier(input.ID) || !input.Kind.Valid() || !input.Platform.Valid() {
		return Resource{}, errors.New("release resource identity is invalid")
	}
	if input.Purpose != expectedPurpose(input.Kind) || input.MediaType != expectedMediaType(input.Kind) {
		return Resource{}, errors.New("release resource purpose or media type is invalid")
	}
	if input.Kind == ResourceKindModel || input.Kind == ResourceKindTokenizer || input.Kind == ResourceKindTemplate {
		if !input.ProviderRole.Valid() {
			return Resource{}, errors.New("local provider resource role is invalid")
		}
	} else if input.ProviderRole != "" {
		return Resource{}, errors.New("non-provider resource cannot declare a provider role")
	}
	if input.Digest.IsZero() || checkedSafeJSONInteger(input.Size, "resource size") != nil {
		return Resource{}, errors.New("release resource content binding is invalid")
	}
	sourceAllowlist, err := validateSourceAllowlist(input.SourceAllowlist, input.Kind, input.Digest)
	if err != nil || !containsExact(sourceAllowlist, input.SourceRef) {
		return Resource{}, errors.New("release resource source reference is invalid")
	}

	switch {
	case input.Kind.IsEvidence():
		if input.CycloneDXSBOMResourceID != "" || input.SPDXSBOMResourceID != "" ||
			input.ProvenanceResourceID != "" || input.LicenseResourceID != "" ||
			input.VulnerabilityResourceID != "" {
			return Resource{}, errors.New("release evidence resource cannot reference attestations")
		}
		if !validIdentifier(input.SubjectResourceID) || input.SubjectDigest.IsZero() {
			return Resource{}, errors.New("release evidence subject binding is invalid")
		}
	case !validIdentifier(input.CycloneDXSBOMResourceID) ||
		!validIdentifier(input.SPDXSBOMResourceID) ||
		!validIdentifier(input.ProvenanceResourceID) ||
		!validIdentifier(input.LicenseResourceID) ||
		!validIdentifier(input.VulnerabilityResourceID):
		return Resource{}, errors.New("release subject is missing verification evidence")
	case input.SubjectResourceID != "" || !input.SubjectDigest.IsZero() ||
		!input.PolicySnapshotDigest.IsZero() || input.QualificationResult != "" ||
		!input.QualificationExpiresAt.IsZero():
		return Resource{}, errors.New("release subject cannot declare evidence qualification fields")
	}

	if input.Kind == ResourceKindOCIImage {
		if input.OCIIndexDigest.IsZero() || !validIdentifier(input.OCIIndexResourceID) {
			return Resource{}, errors.New("OCI image index digest is required")
		}
		digestSuffix := "@sha256:" + input.Digest.Hex()
		if strings.Count(input.SourceRef, "@") != 1 || !strings.HasSuffix(input.SourceRef, digestSuffix) {
			return Resource{}, errors.New("OCI image source must use its exact platform digest")
		}
	}
	if input.Kind != ResourceKindOCIImage && (!input.OCIIndexDigest.IsZero() || input.OCIIndexResourceID != "") {
		return Resource{}, errors.New("non-OCI resource cannot declare an OCI index")
	}
	if input.Kind == ResourceKindLauncher || input.Kind == ResourceKindVerifier || input.Kind == ResourceKindHelper {
		if input.Platform.IsAny() || !validIdentifier(input.NativePublisherIdentity) ||
			!validIdentifier(input.NativePublisherPolicyID) {
			return Resource{}, errors.New("native release resource publisher policy is invalid")
		}
	} else if input.NativePublisherIdentity != "" || input.NativePublisherPolicyID != "" {
		return Resource{}, errors.New("non-native resource cannot declare native publisher policy")
	}
	if input.Kind == ResourceKindOCIImage && input.Platform.IsAny() {
		return Resource{}, errors.New("OCI platform manifest requires an exact platform")
	}
	if input.Kind == ResourceKindOCIIndex && !input.Platform.IsAny() {
		return Resource{}, errors.New("OCI multi-architecture index must be platform independent")
	}
	qualificationExpiresAt, err := validateQualification(input)
	if err != nil {
		return Resource{}, err
	}
	expandedTarget := ReleaseExpandedTarget{}
	if input.Kind == ResourceKindComposeBundle {
		expandedTarget, err = NewReleaseExpandedTarget(input.Digest, input.Size, input.ExpandedTarget)
		if err != nil {
			return Resource{}, err
		}
	} else if input.ExpandedTarget != (ReleaseExpandedTargetInput{}) {
		return Resource{}, ErrExpandedTargetInvalid
	}

	return Resource{
		id:                      input.ID,
		kind:                    input.Kind,
		purpose:                 input.Purpose,
		mediaType:               input.MediaType,
		providerRole:            input.ProviderRole,
		platform:                input.Platform,
		digest:                  input.Digest,
		ociIndexDigest:          input.OCIIndexDigest,
		ociIndexResourceID:      input.OCIIndexResourceID,
		size:                    input.Size,
		sourceRef:               input.SourceRef,
		sourceAllowlist:         sourceAllowlist,
		cycloneDXSBOMResourceID: input.CycloneDXSBOMResourceID,
		spdxSBOMResourceID:      input.SPDXSBOMResourceID,
		provenanceResourceID:    input.ProvenanceResourceID,
		licenseResourceID:       input.LicenseResourceID,
		vulnerabilityResourceID: input.VulnerabilityResourceID,
		nativePublisherIdentity: input.NativePublisherIdentity,
		nativePublisherPolicyID: input.NativePublisherPolicyID,
		subjectResourceID:       input.SubjectResourceID,
		subjectDigest:           input.SubjectDigest,
		policySnapshotDigest:    input.PolicySnapshotDigest,
		qualificationResult:     input.QualificationResult,
		qualificationExpiresAt:  qualificationExpiresAt,
		expandedTarget:          expandedTarget,
	}, nil
}

func expectedPurpose(kind ResourceKind) ResourcePurpose {
	switch kind {
	case ResourceKindLauncher:
		return ResourcePurposeNativeLauncher
	case ResourceKindHelper:
		return ResourcePurposeNativeHelper
	case ResourceKindComposeBundle:
		return ResourcePurposeComposeLock
	case ResourceKindOCIImage:
		return ResourcePurposeOCIPlatformManifest
	case ResourceKindOCIIndex:
		return ResourcePurposeOCIIndex
	case ResourceKindSchema:
		return ResourcePurposeContractBundle
	case ResourceKindMigration:
		return ResourcePurposeMigrationSet
	case ResourceKindSetupUI:
		return ResourcePurposeSetupUI
	case ResourceKindVerifier:
		return ResourcePurposeOfflineVerifier
	case ResourceKindModel:
		return ResourcePurposeModelWeights
	case ResourceKindTokenizer:
		return ResourcePurposeTokenizer
	case ResourceKindTemplate:
		return ResourcePurposePromptTemplate
	case ResourceKindInstallPlanTemplate:
		return ResourcePurposeInstallPlanTemplate
	case ResourceKindOfflineComponent:
		return ResourcePurposeOfflineComponent
	case ResourceKindRuntimeCatalog:
		return ResourcePurposeRuntimeCatalog
	case ResourceKindCycloneDXSBOM:
		return ResourcePurposeCycloneDXSBOM
	case ResourceKindSPDXSBOM:
		return ResourcePurposeSPDXSBOM
	case ResourceKindProvenance:
		return ResourcePurposeSLSAProvenance
	case ResourceKindLicense:
		return ResourcePurposeLicenseEvaluation
	case ResourceKindVulnerabilityReport:
		return ResourcePurposeVulnerabilityReport
	}
	return ""
}

func expectedMediaType(kind ResourceKind) string {
	switch kind {
	case ResourceKindLauncher, ResourceKindHelper, ResourceKindVerifier:
		return MediaTypeNativeExecutable
	case ResourceKindComposeBundle:
		return MediaTypeComposeLock
	case ResourceKindOCIImage:
		return MediaTypeOCIManifest
	case ResourceKindOCIIndex:
		return MediaTypeOCIIndex
	case ResourceKindSchema:
		return MediaTypeContractBundle
	case ResourceKindMigration:
		return MediaTypeMigrationSet
	case ResourceKindSetupUI:
		return MediaTypeSetupUI
	case ResourceKindModel:
		return MediaTypeModelWeights
	case ResourceKindTokenizer:
		return MediaTypeTokenizer
	case ResourceKindTemplate:
		return MediaTypePromptTemplate
	case ResourceKindInstallPlanTemplate:
		return MediaTypeInstallPlanTemplate
	case ResourceKindOfflineComponent:
		return MediaTypeOfflineComponent
	case ResourceKindRuntimeCatalog:
		return MediaTypeRuntimeCatalog
	case ResourceKindCycloneDXSBOM:
		return MediaTypeCycloneDX
	case ResourceKindSPDXSBOM:
		return MediaTypeSPDX
	case ResourceKindProvenance:
		return MediaTypeSLSAProvenance
	case ResourceKindLicense:
		return MediaTypeLicenseEvaluation
	case ResourceKindVulnerabilityReport:
		return MediaTypeVulnerabilityEvaluation
	}
	return ""
}

func validateSourceAllowlist(values []string, kind ResourceKind, digest Digest) ([]string, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, errors.New("release source allowlist size is invalid")
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if index > 0 && result[index-1] == value || !validImmutableSource(value, kind, digest) {
			return nil, errors.New("release source allowlist contains an invalid entry")
		}
	}
	return result, nil
}

func validImmutableSource(value string, kind ResourceKind, digest Digest) bool {
	if !validSafeText(value, 2048) {
		return false
	}
	if kind == ResourceKindOCIImage || kind == ResourceKindOCIIndex {
		return validOCIReference(value, digest)
	}
	if strings.ContainsAny(value, "%?#@") {
		return false
	}
	if strings.HasPrefix(value, "bundle://") {
		path := strings.TrimPrefix(value, "bundle://")
		return path != "" && !strings.Contains(path, "..") && !strings.Contains(path, "//") &&
			validSourcePath(path)
	}
	if !strings.HasPrefix(value, "https://") {
		return false
	}
	remainder := strings.TrimPrefix(value, "https://")
	slash := strings.IndexByte(remainder, '/')
	if slash <= 0 || slash == len(remainder)-1 {
		return false
	}
	host, path := remainder[:slash], remainder[slash+1:]
	return validSourceHost(host) && !strings.Contains(path, "..") &&
		!strings.Contains(path, "//") && validSourcePath(path)
}

func validSourceHost(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validSourcePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '-' ||
			character == '_' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func validOCIReference(value string, digest Digest) bool {
	suffix := "@sha256:" + digest.Hex()
	if strings.Count(value, "@") != 1 || !strings.HasSuffix(value, suffix) {
		return false
	}
	repository := strings.TrimSuffix(value, suffix)
	if repository == "" || strings.Contains(repository, ":") || !strings.Contains(repository, "/") ||
		strings.Contains(repository, "//") || strings.Contains(repository, "..") ||
		strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") {
		return false
	}
	for _, character := range repository {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '-' || character == '_' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func validateQualification(input ResourceInput) (int64, error) {
	//nolint:exhaustive // All non-policy kinds intentionally share the default prohibition.
	switch input.Kind {
	case ResourceKindLicense:
		if input.PolicySnapshotDigest.IsZero() || input.QualificationResult != QualificationResultPassed ||
			!input.QualificationExpiresAt.IsZero() {
			return 0, errors.New("license qualification binding is invalid")
		}
		return 0, nil
	case ResourceKindVulnerabilityReport:
		if input.PolicySnapshotDigest.IsZero() || input.QualificationResult != QualificationResultPassed ||
			input.QualificationExpiresAt.IsZero() {
			return 0, errors.New("vulnerability qualification binding is invalid")
		}
		expiresAt := input.QualificationExpiresAt.UTC().UnixMicro()
		if expiresAt <= 0 || uint64(expiresAt) > maxSafeJSONInteger {
			return 0, errors.New("vulnerability qualification expiry is invalid")
		}
		return expiresAt, nil
	default:
		if !input.PolicySnapshotDigest.IsZero() || input.QualificationResult != "" ||
			!input.QualificationExpiresAt.IsZero() {
			return 0, errors.New("non-policy evidence cannot declare qualification fields")
		}
		return 0, nil
	}
}

func containsExact(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

// Valid reports whether the kind is understood by manifest schema v1.
func (k ResourceKind) Valid() bool {
	switch k {
	case ResourceKindLauncher,
		ResourceKindHelper,
		ResourceKindComposeBundle,
		ResourceKindOCIImage,
		ResourceKindOCIIndex,
		ResourceKindSchema,
		ResourceKindMigration,
		ResourceKindSetupUI,
		ResourceKindVerifier,
		ResourceKindModel,
		ResourceKindTokenizer,
		ResourceKindTemplate,
		ResourceKindInstallPlanTemplate,
		ResourceKindOfflineComponent,
		ResourceKindRuntimeCatalog,
		ResourceKindCycloneDXSBOM,
		ResourceKindSPDXSBOM,
		ResourceKindProvenance,
		ResourceKindLicense,
		ResourceKindVulnerabilityReport:
		return true
	}
	return false
}

// IsEvidence reports whether this resource verifies another subject.
func (k ResourceKind) IsEvidence() bool {
	return k == ResourceKindCycloneDXSBOM || k == ResourceKindSPDXSBOM ||
		k == ResourceKindProvenance || k == ResourceKindLicense ||
		k == ResourceKindVulnerabilityReport
}

// ID returns the stable logical inventory identifier.
func (r Resource) ID() string { return r.id }

// Kind returns the closed resource kind.
func (r Resource) Kind() ResourceKind { return r.kind }

// Purpose returns the closed signed execution purpose.
func (r Resource) Purpose() ResourcePurpose { return r.purpose }

// MediaType returns the exact signed artifact media type.
func (r Resource) MediaType() string { return r.mediaType }

// ProviderRole returns the mandatory local-provider role for model resources.
func (r Resource) ProviderRole() LocalProviderRole { return r.providerRole }

// Platform returns the exact target or the platform-independent zero value.
func (r Resource) Platform() Platform { return r.platform }

// Digest returns the expected resource SHA-256 digest.
func (r Resource) Digest() Digest { return r.digest }

// OCIIndexDigest returns the multi-architecture index digest for OCI images.
func (r Resource) OCIIndexDigest() Digest { return r.ociIndexDigest }

// OCIIndexResourceID returns the exact associated multi-architecture index resource.
func (r Resource) OCIIndexResourceID() string { return r.ociIndexResourceID }

// Size returns the expected exact byte length.
func (r Resource) Size() uint64 { return r.size }

// SourceRef returns signed acquisition metadata, not identity proof.
func (r Resource) SourceRef() string { return r.sourceRef }

// SourceAllowlist returns a copy of exact authorized acquisition locations.
func (r Resource) SourceAllowlist() []string {
	return append([]string(nil), r.sourceAllowlist...)
}

// CycloneDXSBOMResourceID returns the linked CycloneDX evidence resource.
func (r Resource) CycloneDXSBOMResourceID() string { return r.cycloneDXSBOMResourceID }

// SPDXSBOMResourceID returns the linked SPDX evidence resource.
func (r Resource) SPDXSBOMResourceID() string { return r.spdxSBOMResourceID }

// ProvenanceResourceID returns the linked SLSA evidence resource.
func (r Resource) ProvenanceResourceID() string { return r.provenanceResourceID }

// LicenseResourceID returns the linked license-policy evidence resource.
func (r Resource) LicenseResourceID() string { return r.licenseResourceID }

// VulnerabilityResourceID returns the linked vulnerability evidence resource.
func (r Resource) VulnerabilityResourceID() string { return r.vulnerabilityResourceID }

// NativePublisherIdentity returns the expected platform-native publisher.
func (r Resource) NativePublisherIdentity() string { return r.nativePublisherIdentity }

// NativePublisherPolicyID returns the signed native publisher policy binding.
func (r Resource) NativePublisherPolicyID() string { return r.nativePublisherPolicyID }

// SubjectResourceID returns the exact subject bound by an evidence resource.
func (r Resource) SubjectResourceID() string { return r.subjectResourceID }

// SubjectDigest returns the exact subject digest bound by an evidence resource.
func (r Resource) SubjectDigest() Digest { return r.subjectDigest }

// PolicySnapshotDigest returns the license or vulnerability policy snapshot digest.
func (r Resource) PolicySnapshotDigest() Digest { return r.policySnapshotDigest }

// QualificationResult returns the signed release qualification result.
func (r Resource) QualificationResult() QualificationResult { return r.qualificationResult }

// QualificationExpiresAt returns the vulnerability qualification expiry, if applicable.
func (r Resource) QualificationExpiresAt() time.Time {
	if r.qualificationExpiresAt == 0 {
		return time.Time{}
	}
	return time.UnixMicro(r.qualificationExpiresAt).UTC()
}

// ExpandedTarget returns publisher-signed materialization authority when the
// resource has an expanded local representation.
func (r Resource) ExpandedTarget() (ReleaseExpandedTarget, bool) {
	return r.expandedTarget, r.expandedTarget.Valid()
}

func (r Resource) appliesTo(platform Platform) bool {
	return r.platform.IsAny() || r.platform == platform
}
