package releaseinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	// SupportedManifestSchemaMajor is the only manifest major this package may
	// interpret for execution decisions.
	SupportedManifestSchemaMajor uint16 = 1
	// ManifestSignatureSize is the exact detached Ed25519 signature length used
	// by explicit key-ID trust mode. Certificate modes are verified by another
	// adapter and are not constrained to this length.
	ManifestSignatureSize = 64
)

var (
	// ErrTargetUnsupported means the signed inventory has no subjects for the
	// requested certified platform.
	ErrTargetUnsupported = errors.New("release target platform is unsupported")
	// ErrTargetInventoryIncomplete means a platform is declared but its closed
	// PF-001 resource/evidence set is incomplete or cross-bound.
	ErrTargetInventoryIncomplete = errors.New("release target inventory is incomplete")
)

// ManifestInput is copied into an immutable ReleaseManifest.
type ManifestInput struct {
	SchemaVersion             uint16
	ReleaseID                 string
	Version                   string
	BuildID                   string
	SourceCommit              string
	BuildTimestamp            time.Time
	Channel                   ReleaseChannel
	Sequence                  uint64
	DataGeneration            uint64
	ValidFrom                 time.Time
	ValidUntil                time.Time
	Protocol                  ProtocolRange
	Compatibility             Compatibility
	TrustPolicy               TrustPolicy
	ReleaseHistory            ReleaseHistory
	LicensePolicyDigest       Digest
	VulnerabilityPolicyDigest Digest
	DockerTopology            DockerTopology
	Resources                 []Resource
}

// Manifest is the understood release-manifest v1 security projection. The
// canonical encoding is RFC 8785-compatible for this schema: object keys are
// declared in lexical order, arrays are deterministically sorted, strings are
// restricted to safe ASCII, and all numbers are safe integers.
type Manifest struct {
	schemaVersion             uint16
	releaseID                 string
	version                   string
	buildID                   string
	sourceCommit              string
	buildTimestamp            int64
	channel                   ReleaseChannel
	sequence                  uint64
	dataGeneration            uint64
	validFrom                 int64
	validUntil                int64
	protocol                  ProtocolRange
	compatibility             Compatibility
	trustPolicy               TrustPolicy
	releaseHistory            ReleaseHistory
	licensePolicyDigest       Digest
	vulnerabilityPolicyDigest Digest
	dockerTopology            DockerTopology
	resources                 []Resource
	canonical                 []byte
}

// NewManifest validates associations, closes the understood schema, and
// calculates deterministic canonical JSON.
func NewManifest(input ManifestInput) (Manifest, error) {
	if input.SchemaVersion != SupportedManifestSchemaMajor {
		return Manifest{}, errors.New("release manifest schema major is unsupported")
	}
	if !validIdentifier(input.ReleaseID) || !validIdentifier(input.BuildID) ||
		!validSourceCommit(input.SourceCommit) || !input.Channel.Valid() {
		return Manifest{}, errors.New("release manifest identity is invalid")
	}
	if _, err := parseStableSemanticVersion(input.Version); err != nil {
		return Manifest{}, errors.New("release product version is invalid")
	}
	if checkedSafeJSONInteger(input.Sequence, "release sequence") != nil ||
		checkedSafeJSONInteger(input.DataGeneration, "data generation") != nil ||
		!input.Protocol.Valid() || !input.Compatibility.Valid() || !input.TrustPolicy.Valid() ||
		input.LicensePolicyDigest.IsZero() || input.VulnerabilityPolicyDigest.IsZero() ||
		!input.DockerTopology.Valid() {
		return Manifest{}, errors.New("release manifest policy is invalid")
	}
	validFrom, validUntil, err := canonicalValidity(input.ValidFrom, input.ValidUntil)
	if err != nil {
		return Manifest{}, err
	}
	buildTimestamp, err := canonicalBuildTimestamp(input.BuildTimestamp, validFrom)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateReleaseHistory(input.ReleaseID, input.ReleaseHistory); err != nil {
		return Manifest{}, err
	}
	if len(input.Resources) == 0 || len(input.Resources) > 4096 {
		return Manifest{}, errors.New("release resource inventory size is invalid")
	}

	resources := append([]Resource(nil), input.Resources...)
	sort.Slice(resources, func(left int, right int) bool { return resources[left].ID() < resources[right].ID() })
	byID := make(map[string]Resource, len(resources))
	evidenceUseCount := make(map[string]int)
	for _, resource := range resources {
		if resource.ID() == "" || !resource.Kind().Valid() || resource.Digest().IsZero() {
			return Manifest{}, errors.New("release inventory contains an invalid resource")
		}
		if _, duplicate := byID[resource.ID()]; duplicate {
			return Manifest{}, errors.New("release inventory contains a duplicate resource")
		}
		byID[resource.ID()] = resource
	}
	for _, resource := range resources {
		if resource.Kind().IsEvidence() {
			if resource.Kind() == ResourceKindLicense &&
				!resource.PolicySnapshotDigest().Equal(input.LicensePolicyDigest) {
				return Manifest{}, errors.New("release license policy snapshot binding is invalid")
			}
			if resource.Kind() == ResourceKindVulnerabilityReport &&
				(!resource.PolicySnapshotDigest().Equal(input.VulnerabilityPolicyDigest) ||
					resource.qualificationExpiresAt < validUntil) {
				return Manifest{}, errors.New("release vulnerability policy snapshot binding is invalid")
			}
			continue
		}
		if !associationBindsSubject(byID, resource.CycloneDXSBOMResourceID(), ResourceKindCycloneDXSBOM, resource) ||
			!associationBindsSubject(byID, resource.SPDXSBOMResourceID(), ResourceKindSPDXSBOM, resource) ||
			!associationBindsSubject(byID, resource.ProvenanceResourceID(), ResourceKindProvenance, resource) ||
			!associationBindsSubject(byID, resource.LicenseResourceID(), ResourceKindLicense, resource) ||
			!associationBindsSubject(byID, resource.VulnerabilityResourceID(), ResourceKindVulnerabilityReport, resource) {
			return Manifest{}, errors.New("release inventory evidence association is invalid")
		}
		for _, evidenceID := range []string{
			resource.CycloneDXSBOMResourceID(),
			resource.SPDXSBOMResourceID(),
			resource.ProvenanceResourceID(),
			resource.LicenseResourceID(),
			resource.VulnerabilityResourceID(),
		} {
			evidenceUseCount[evidenceID]++
		}
		if resource.Kind() == ResourceKindOCIImage &&
			!associationBindsOCIIndex(byID, resource) {
			return Manifest{}, errors.New("release OCI index association is invalid")
		}
	}
	for _, resource := range resources {
		if resource.Kind().IsEvidence() && evidenceUseCount[resource.ID()] != 1 {
			return Manifest{}, errors.New("release inventory contains orphaned or reused evidence")
		}
	}
	if err := validateDockerTopologyResources(input.DockerTopology, resources, byID); err != nil {
		return Manifest{}, err
	}

	manifest := Manifest{
		schemaVersion:             input.SchemaVersion,
		releaseID:                 input.ReleaseID,
		version:                   input.Version,
		buildID:                   input.BuildID,
		sourceCommit:              input.SourceCommit,
		buildTimestamp:            buildTimestamp,
		channel:                   input.Channel,
		sequence:                  input.Sequence,
		dataGeneration:            input.DataGeneration,
		validFrom:                 validFrom,
		validUntil:                validUntil,
		protocol:                  input.Protocol,
		compatibility:             input.Compatibility,
		trustPolicy:               input.TrustPolicy,
		releaseHistory:            input.ReleaseHistory,
		licensePolicyDigest:       input.LicensePolicyDigest,
		vulnerabilityPolicyDigest: input.VulnerabilityPolicyDigest,
		dockerTopology:            input.DockerTopology,
		resources:                 resources,
	}
	canonical, err := manifest.encodeCanonical()
	if err != nil {
		return Manifest{}, errors.New("release manifest canonical encoding failed")
	}
	manifest.canonical = canonical
	return manifest, nil
}

func canonicalValidity(validFrom time.Time, validUntil time.Time) (int64, int64, error) {
	if validFrom.IsZero() || validUntil.IsZero() {
		return 0, 0, errors.New("release validity window is required")
	}
	from := validFrom.UTC().UnixMicro()
	until := validUntil.UTC().UnixMicro()
	if from <= 0 || until <= from || uint64(until) > maxSafeJSONInteger {
		return 0, 0, errors.New("release validity window is invalid")
	}
	return from, until, nil
}

func canonicalBuildTimestamp(buildTimestamp time.Time, validFrom int64) (int64, error) {
	if buildTimestamp.IsZero() {
		return 0, errors.New("release build timestamp is required")
	}
	microseconds := buildTimestamp.UTC().UnixMicro()
	if microseconds <= 0 || microseconds > validFrom || uint64(microseconds) > maxSafeJSONInteger {
		return 0, errors.New("release build timestamp is invalid")
	}
	return microseconds, nil
}

func validSourceCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return strings.Trim(value, "0") != ""
}

func validateReleaseHistory(releaseID string, history ReleaseHistory) error {
	priorInputs := make([]PriorReleaseInput, 0, len(history.prior))
	for _, prior := range history.prior {
		if prior.releaseID == releaseID {
			return errors.New("current release cannot be its own compatibility source")
		}
		priorInputs = append(priorInputs, PriorReleaseInput{
			ReleaseID: prior.releaseID, ManifestDigest: prior.manifestDigest,
			MinimumDataGeneration: prior.minimumDataGeneration,
			MaximumDataGeneration: prior.maximumDataGeneration,
		})
	}
	rollbackInputs := make([]RollbackReleaseInput, 0, len(history.rollback))
	for _, rollback := range history.rollback {
		rollbackInputs = append(rollbackInputs, RollbackReleaseInput{
			ReleaseID: rollback.releaseID, ManifestDigest: rollback.manifestDigest,
			DataGeneration: rollback.dataGeneration,
		})
	}
	_, err := NewReleaseHistory(priorInputs, rollbackInputs)
	return err
}

func associationBindsSubject(
	resources map[string]Resource,
	id string,
	kind ResourceKind,
	subject Resource,
) bool {
	evidence, exists := resources[id]
	return exists && evidence.Kind() == kind && evidence.SubjectResourceID() == subject.ID() &&
		evidence.SubjectDigest().Equal(subject.Digest())
}

func associationBindsOCIIndex(resources map[string]Resource, image Resource) bool {
	index, exists := resources[image.OCIIndexResourceID()]
	return exists && index.Kind() == ResourceKindOCIIndex && index.Platform().IsAny() &&
		index.Digest().Equal(image.OCIIndexDigest())
}

func validateDockerTopologyResources(
	topology DockerTopology,
	resources []Resource,
	byID map[string]Resource,
) error {
	referencedImages := make(map[string]struct{})
	for _, service := range topology.services {
		platforms := make(map[Platform]struct{})
		for _, imageID := range service.imageResourceIDs {
			image, exists := byID[imageID]
			if !exists || image.Kind() != ResourceKindOCIImage || image.Platform().IsAny() {
				return errors.New("docker service image resource is invalid")
			}
			if _, duplicate := platforms[image.Platform()]; duplicate {
				return errors.New("docker service has ambiguous images for a platform")
			}
			platforms[image.Platform()] = struct{}{}
			referencedImages[imageID] = struct{}{}
		}
	}
	referencedIndexes := make(map[string]struct{})
	for _, resource := range resources {
		if resource.Kind() == ResourceKindOCIImage {
			if _, referenced := referencedImages[resource.ID()]; !referenced {
				return errors.New("release inventory contains an unrendered OCI image")
			}
			referencedIndexes[resource.OCIIndexResourceID()] = struct{}{}
		}
	}
	for _, resource := range resources {
		if resource.Kind() == ResourceKindOCIIndex {
			if _, referenced := referencedIndexes[resource.ID()]; !referenced {
				return errors.New("release inventory contains an unbound OCI index")
			}
		}
	}
	return nil
}

func (m Manifest) encodeCanonical() ([]byte, error) {
	resources := make([]canonicalResource, 0, len(m.resources))
	for _, resource := range m.resources {
		resources = append(resources, canonicalResource{
			CycloneDXSBOMResourceID: resource.CycloneDXSBOMResourceID(),
			Digest:                  resource.Digest().Hex(),
			ID:                      resource.ID(),
			Kind:                    string(resource.Kind()),
			LicenseResourceID:       resource.LicenseResourceID(),
			MediaType:               resource.MediaType(),
			NativePublisherIdentity: resource.NativePublisherIdentity(),
			NativePublisherPolicyID: resource.NativePublisherPolicyID(),
			OCIIndexDigest:          emptyDigestHex(resource.OCIIndexDigest()),
			OCIIndexResourceID:      resource.OCIIndexResourceID(),
			Platform: canonicalPlatform{
				Architecture: resource.Platform().Architecture(),
				OS:           resource.Platform().OS(),
			},
			PolicySnapshotDigest:    emptyDigestHex(resource.PolicySnapshotDigest()),
			ProvenanceResourceID:    resource.ProvenanceResourceID(),
			ProviderRole:            string(resource.ProviderRole()),
			Purpose:                 string(resource.Purpose()),
			QualificationExpiresAt:  resource.qualificationExpiresAt,
			QualificationResult:     string(resource.QualificationResult()),
			Size:                    resource.Size(),
			SourceAllowlist:         resource.SourceAllowlist(),
			SourceRef:               resource.SourceRef(),
			SPDXSBOMResourceID:      resource.SPDXSBOMResourceID(),
			SubjectDigest:           emptyDigestHex(resource.SubjectDigest()),
			SubjectResourceID:       resource.SubjectResourceID(),
			VulnerabilityResourceID: resource.VulnerabilityResourceID(),
			ExpandedTarget:          canonicalExpandedTargetFrom(resource),
		})
	}
	document := canonicalManifest{
		BuildID:             m.buildID,
		BuildTimestamp:      m.buildTimestamp,
		Channel:             string(m.channel),
		Compatibility:       canonicalCompatibilityFrom(m.compatibility),
		DataGeneration:      m.dataGeneration,
		DockerTopology:      canonicalDockerTopologyFrom(m.dockerTopology),
		LicensePolicyDigest: m.licensePolicyDigest.Hex(),
		PriorReleases:       canonicalPriorReleasesFrom(m.releaseHistory),
		Protocol:            canonicalProtocol{Maximum: m.protocol.Maximum(), Minimum: m.protocol.Minimum()},
		ReleaseID:           m.releaseID,
		Resources:           resources,
		RollbackReleases:    canonicalRollbackReleasesFrom(m.releaseHistory),
		SchemaVersion:       m.schemaVersion,
		Sequence:            m.sequence,
		SourceCommit:        m.sourceCommit,
		TrustPolicy: canonicalTrustPolicy{
			Mode:                string(m.trustPolicy.Mode()),
			RevocationSetDigest: m.trustPolicy.RevocationSetDigest().Hex(),
			RuntimeTrustRootID:  m.trustPolicy.RuntimeTrustRootID(),
			TransparencyLogID:   m.trustPolicy.TransparencyLogID(),
			TrustRootID:         m.trustPolicy.TrustRootID(),
		},
		ValidFrom:                 m.validFrom,
		ValidUntil:                m.validUntil,
		Version:                   m.version,
		VulnerabilityPolicyDigest: m.vulnerabilityPolicyDigest.Hex(),
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

// CanonicalBytes returns a copy of the RFC 8785-compatible signed bytes.
func (m Manifest) CanonicalBytes() []byte { return append([]byte(nil), m.canonical...) }

// Digest returns the SHA-256 digest of the canonical manifest.
func (m Manifest) Digest() Digest { return DigestBytes(m.canonical) }

// SchemaVersion returns the understood manifest major.
func (m Manifest) SchemaVersion() uint16 { return m.schemaVersion }

// ReleaseID returns the immutable build identity.
func (m Manifest) ReleaseID() string { return m.releaseID }

// Version returns the product semantic version text.
func (m Manifest) Version() string { return m.version }

// BuildID returns the immutable qualified build identity.
func (m Manifest) BuildID() string { return m.buildID }

// SourceCommit returns the exact lowercase source commit.
func (m Manifest) SourceCommit() string { return m.sourceCommit }

// BuildTimestamp returns the UTC qualified build time.
func (m Manifest) BuildTimestamp() time.Time { return time.UnixMicro(m.buildTimestamp).UTC() }

// Channel returns the signed promotion and anti-rollback namespace.
func (m Manifest) Channel() ReleaseChannel { return m.channel }

// Sequence returns the channel anti-rollback sequence.
func (m Manifest) Sequence() uint64 { return m.sequence }

// DataGeneration returns the release's canonical data-generation version.
func (m Manifest) DataGeneration() uint64 { return m.dataGeneration }

// ValidFrom returns the beginning of the signed installation window.
func (m Manifest) ValidFrom() time.Time { return time.UnixMicro(m.validFrom).UTC() }

// ValidUntil returns the exclusive signed support expiry.
func (m Manifest) ValidUntil() time.Time { return time.UnixMicro(m.validUntil).UTC() }

// Protocol returns the signed launcher protocol window.
func (m Manifest) Protocol() ProtocolRange { return m.protocol }

// Compatibility returns the complete signed execution compatibility matrix.
func (m Manifest) Compatibility() Compatibility { return m.compatibility }

// TrustPolicy returns the signed offline signature policy.
func (m Manifest) TrustPolicy() TrustPolicy { return m.trustPolicy }

// ReleaseHistory returns immutable prior-release and exact rollback bindings.
func (m Manifest) ReleaseHistory() ReleaseHistory {
	return ReleaseHistory{
		prior:    append([]PriorRelease(nil), m.releaseHistory.prior...),
		rollback: append([]RollbackRelease(nil), m.releaseHistory.rollback...),
	}
}

// LicensePolicyDigest returns the signed license policy snapshot digest.
func (m Manifest) LicensePolicyDigest() Digest { return m.licensePolicyDigest }

// VulnerabilityPolicyDigest returns the signed vulnerability policy snapshot digest.
func (m Manifest) VulnerabilityPolicyDigest() Digest { return m.vulnerabilityPolicyDigest }

// DockerTopology returns the closed signed Docker execution inventory.
func (m Manifest) DockerTopology() DockerTopology { return cloneDockerTopology(m.dockerTopology) }

// Resources returns a copy of the closed resource inventory.
func (m Manifest) Resources() []Resource { return append([]Resource(nil), m.resources...) }

// ValidAt enforces the signed support window as [valid_from, valid_until).
func (m Manifest) ValidAt(now time.Time) bool {
	if now.IsZero() {
		return false
	}
	microseconds := now.UTC().UnixMicro()
	return microseconds >= m.validFrom && microseconds < m.validUntil
}

// ResourcesFor selects only target-independent and exact-target resources,
// adds their linked evidence, and proves the complete PF-001 subject kinds are
// present before any artifact is acquired or executed.
func (m Manifest) ResourcesFor(platform Platform) ([]Resource, error) {
	if platform.IsAny() || !platform.Valid() {
		return nil, ErrTargetUnsupported
	}
	byID := make(map[string]Resource, len(m.resources))
	selected := make(map[string]Resource, len(m.resources))
	presentKinds := make(map[ResourceKind]bool)
	subjects := make([]Resource, 0, len(m.resources))
	hasExactTarget := false
	for _, resource := range m.resources {
		byID[resource.ID()] = resource
		if resource.Kind().IsEvidence() || !resource.appliesTo(platform) {
			continue
		}
		selected[resource.ID()] = resource
		subjects = append(subjects, resource)
		presentKinds[resource.Kind()] = true
		if resource.Platform() == platform {
			hasExactTarget = true
		}
	}
	for _, required := range requiredSubjectKinds() {
		if !presentKinds[required] {
			if !hasExactTarget {
				return nil, ErrTargetUnsupported
			}
			return nil, ErrTargetInventoryIncomplete
		}
	}
	if !hasCompleteProviderMatrix(subjects) || !hasUnambiguousSingletonSubjects(subjects) ||
		!m.hasServiceImagesFor(platform) {
		return nil, ErrTargetInventoryIncomplete
	}
	for _, subject := range subjects {
		for _, evidenceID := range []string{
			subject.CycloneDXSBOMResourceID(),
			subject.SPDXSBOMResourceID(),
			subject.ProvenanceResourceID(),
			subject.LicenseResourceID(),
			subject.VulnerabilityResourceID(),
		} {
			evidence := byID[evidenceID]
			if !evidence.appliesTo(platform) {
				return nil, ErrTargetInventoryIncomplete
			}
			selected[evidenceID] = evidence
		}
	}
	result := make([]Resource, 0, len(selected))
	for _, resource := range selected {
		result = append(result, resource)
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].ID() < result[right].ID() })
	return result, nil
}

func requiredSubjectKinds() []ResourceKind {
	return []ResourceKind{
		ResourceKindLauncher,
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
		ResourceKindRuntimeCatalog,
	}
}

func hasCompleteProviderMatrix(subjects []Resource) bool {
	present := make(map[LocalProviderRole]map[ResourceKind]int)
	for _, subject := range subjects {
		if subject.ProviderRole() == "" {
			continue
		}
		if present[subject.ProviderRole()] == nil {
			present[subject.ProviderRole()] = make(map[ResourceKind]int)
		}
		present[subject.ProviderRole()][subject.Kind()]++
	}
	for _, role := range []LocalProviderRole{
		LocalProviderRoleEmbedding,
		LocalProviderRoleReranking,
		LocalProviderRoleExtraction,
	} {
		for _, kind := range []ResourceKind{ResourceKindModel, ResourceKindTokenizer, ResourceKindTemplate} {
			if present[role][kind] != 1 {
				return false
			}
		}
	}
	return true
}

func hasUnambiguousSingletonSubjects(subjects []Resource) bool {
	counts := make(map[ResourceKind]int)
	for _, subject := range subjects {
		counts[subject.Kind()]++
	}
	for _, kind := range []ResourceKind{
		ResourceKindLauncher,
		ResourceKindHelper,
		ResourceKindComposeBundle,
		ResourceKindSchema,
		ResourceKindMigration,
		ResourceKindSetupUI,
		ResourceKindVerifier,
		ResourceKindRuntimeCatalog,
	} {
		if counts[kind] != 1 {
			return false
		}
	}
	return true
}

func (m Manifest) hasServiceImagesFor(platform Platform) bool {
	byID := make(map[string]Resource, len(m.resources))
	for _, resource := range m.resources {
		byID[resource.ID()] = resource
	}
	for _, service := range m.dockerTopology.services {
		matches := 0
		for _, imageID := range service.imageResourceIDs {
			image := byID[imageID]
			if image.Kind() == ResourceKindOCIImage && image.Platform() == platform {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

// SignatureBundleInput contains offline evidence. Presence is intentionally
// checked by the application so each missing security proof receives a stable
// typed blocker instead of being collapsed into input validation.
type SignatureBundleInput struct {
	SchemaVersion       uint16
	TrustMode           SignatureTrustMode
	TrustRootID         string
	Signature           []byte
	SigstoreBundle      []byte
	RevocationSet       []byte
	TrustedTimeEvidence []byte
}

// SupportedSignatureBundleSchemaMajor is the only signature-envelope schema
// whose evidence semantics this launcher understands. Version 2 replaces the
// ambiguous split certificate/Rekor fields with one official Sigstore bundle.
const SupportedSignatureBundleSchemaMajor = uint16(2)

// SignatureBundle is immutable offline signature and trust evidence.
type SignatureBundle struct {
	schemaVersion       uint16
	trustMode           SignatureTrustMode
	trustRootID         string
	signature           []byte
	sigstoreBundle      []byte
	revocationSet       []byte
	trustedTimeEvidence []byte
}

// SignedManifest binds an immutable manifest to its offline signature bundle.
type SignedManifest struct {
	manifest Manifest
	bundle   SignatureBundle
}

// NewSignedManifest validates cryptographic envelope shape without claiming
// trust. Trust evidence and signature validity are application decisions.
func NewSignedManifest(manifest Manifest, input SignatureBundleInput) (SignedManifest, error) {
	if len(manifest.canonical) == 0 || !validIdentifier(input.TrustRootID) {
		return SignedManifest{}, errors.New("signed release manifest identity is invalid")
	}
	if input.SchemaVersion != SupportedSignatureBundleSchemaMajor {
		return SignedManifest{}, errors.New("signed release signature bundle schema is unsupported")
	}
	if input.TrustMode != SignatureTrustModeKeyID &&
		input.TrustMode != SignatureTrustModeCertificateTransparency {
		return SignedManifest{}, errors.New("signed release manifest trust mode is invalid")
	}
	if input.TrustMode == SignatureTrustModeKeyID &&
		(len(input.Signature) != ManifestSignatureSize || len(input.SigstoreBundle) != 0) {
		return SignedManifest{}, errors.New("key-ID release signature length is invalid")
	}
	if input.TrustMode == SignatureTrustModeCertificateTransparency && len(input.Signature) != 0 {
		return SignedManifest{}, errors.New("certificate-transparency signatures must use an official Sigstore bundle")
	}
	bundle := SignatureBundle{
		schemaVersion:       input.SchemaVersion,
		trustMode:           input.TrustMode,
		trustRootID:         input.TrustRootID,
		signature:           append([]byte(nil), input.Signature...),
		sigstoreBundle:      append([]byte(nil), input.SigstoreBundle...),
		revocationSet:       append([]byte(nil), input.RevocationSet...),
		trustedTimeEvidence: append([]byte(nil), input.TrustedTimeEvidence...),
	}
	return SignedManifest{manifest: manifest, bundle: bundle}, nil
}

// Manifest returns the immutable signed manifest.
func (s SignedManifest) Manifest() Manifest { return s.manifest }

// SignatureBundleSchemaVersion returns the understood nested envelope schema.
func (s SignedManifest) SignatureBundleSchemaVersion() uint16 { return s.bundle.schemaVersion }

// TrustMode returns the bundle's offline trust mode.
func (s SignedManifest) TrustMode() SignatureTrustMode { return s.bundle.trustMode }

// TrustRootID returns the exact bundle trust-root identifier.
func (s SignedManifest) TrustRootID() string { return s.bundle.trustRootID }

// Signature returns a copy of the detached signature bytes.
func (s SignedManifest) Signature() []byte { return append([]byte(nil), s.bundle.signature...) }

// SigstoreBundle returns a copy of the official offline Sigstore bundle JSON.
func (s SignedManifest) SigstoreBundle() []byte {
	return append([]byte(nil), s.bundle.sigstoreBundle...)
}

// RevocationSet returns a copy of the offline signed revocation evidence.
func (s SignedManifest) RevocationSet() []byte { return append([]byte(nil), s.bundle.revocationSet...) }

// TrustedTimeEvidence returns a copy of the offline trusted-time evidence.
func (s SignedManifest) TrustedTimeEvidence() []byte {
	return append([]byte(nil), s.bundle.trustedTimeEvidence...)
}

// SignaturePayload returns the exact RFC 8785 canonical manifest bytes required by ADR-016.
func (s SignedManifest) SignaturePayload() []byte {
	return s.manifest.CanonicalBytes()
}

type canonicalManifest struct {
	BuildID                   string                     `json:"build_id"`
	BuildTimestamp            int64                      `json:"build_timestamp"`
	Channel                   string                     `json:"channel"`
	Compatibility             canonicalCompatibility     `json:"compatibility"`
	DataGeneration            uint64                     `json:"data_generation"`
	DockerTopology            canonicalDockerTopology    `json:"docker_topology"`
	LicensePolicyDigest       string                     `json:"license_policy_digest"`
	PriorReleases             []canonicalPriorRelease    `json:"prior_releases"`
	Protocol                  canonicalProtocol          `json:"protocol"`
	ReleaseID                 string                     `json:"release_id"`
	Resources                 []canonicalResource        `json:"resources"`
	RollbackReleases          []canonicalRollbackRelease `json:"rollback_releases"`
	SchemaVersion             uint16                     `json:"schema_version"`
	Sequence                  uint64                     `json:"sequence"`
	SourceCommit              string                     `json:"source_commit"`
	TrustPolicy               canonicalTrustPolicy       `json:"trust_policy"`
	ValidFrom                 int64                      `json:"valid_from"`
	ValidUntil                int64                      `json:"valid_until"`
	Version                   string                     `json:"version"`
	VulnerabilityPolicyDigest string                     `json:"vulnerability_policy_digest"`
}

type canonicalProtocol struct {
	Maximum uint32 `json:"maximum"`
	Minimum uint32 `json:"minimum"`
}

type canonicalTrustPolicy struct {
	Mode                string `json:"mode"`
	RevocationSetDigest string `json:"revocation_set_digest"`
	RuntimeTrustRootID  string `json:"runtime_trust_root_id"`
	TransparencyLogID   string `json:"transparency_log_id"`
	TrustRootID         string `json:"trust_root_id"`
}

type canonicalResource struct {
	CycloneDXSBOMResourceID string                  `json:"cyclonedx_sbom_resource_id"`
	Digest                  string                  `json:"digest"`
	ExpandedTarget          canonicalExpandedTarget `json:"expanded_target"`
	ID                      string                  `json:"id"`
	Kind                    string                  `json:"kind"`
	LicenseResourceID       string                  `json:"license_resource_id"`
	MediaType               string                  `json:"media_type"`
	NativePublisherIdentity string                  `json:"native_publisher_identity"`
	NativePublisherPolicyID string                  `json:"native_publisher_policy_id"`
	OCIIndexDigest          string                  `json:"oci_index_digest"`
	OCIIndexResourceID      string                  `json:"oci_index_resource_id"`
	Platform                canonicalPlatform       `json:"platform"`
	PolicySnapshotDigest    string                  `json:"policy_snapshot_digest"`
	ProvenanceResourceID    string                  `json:"provenance_resource_id"`
	ProviderRole            string                  `json:"provider_role"`
	Purpose                 string                  `json:"purpose"`
	QualificationExpiresAt  int64                   `json:"qualification_expires_at"`
	QualificationResult     string                  `json:"qualification_result"`
	Size                    uint64                  `json:"size"`
	SourceAllowlist         []string                `json:"source_allowlist"`
	SourceRef               string                  `json:"source_ref"`
	SPDXSBOMResourceID      string                  `json:"spdx_sbom_resource_id"`
	SubjectDigest           string                  `json:"subject_digest"`
	SubjectResourceID       string                  `json:"subject_resource_id"`
	VulnerabilityResourceID string                  `json:"vulnerability_resource_id"`
}

type canonicalExpandedTarget struct {
	Bytes     uint64 `json:"bytes"`
	Digest    string `json:"digest"`
	Kind      string `json:"kind"`
	StorageID string `json:"storage_id"`
}

func canonicalExpandedTargetFrom(resource Resource) canonicalExpandedTarget {
	target, exists := resource.ExpandedTarget()
	if !exists {
		return canonicalExpandedTarget{}
	}
	return canonicalExpandedTarget{
		Bytes: target.Bytes(), Digest: target.Digest().Hex(), Kind: string(target.Kind()), StorageID: target.StorageID(),
	}
}

func emptyDigestHex(digest Digest) string {
	if digest.IsZero() {
		return ""
	}
	return digest.Hex()
}

type canonicalPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}
