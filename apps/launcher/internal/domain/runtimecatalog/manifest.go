package runtimecatalog

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"
)

// ManifestInput is the complete trusted-construction input for one certified platform cell.
type ManifestInput struct {
	SchemaVersion    uint32
	CatalogID        string
	CatalogSequence  uint64
	SigningKeyID     string
	SupportExpiresAt time.Time
	Platform         PlatformPolicyInput
	Runtime          RuntimePolicyInput
	Artifact         ArtifactPolicyInput
	Install          InstallerPolicyInput
	LinuxExecution   LinuxExecutionPolicyInput
	Prerequisites    []PrerequisiteInput
	CapabilityProbes []CapabilityProbe
	Terms            TermsPolicyInput
}

// Manifest is one immutable signed runtime prerequisite catalog cell.
type Manifest struct {
	schemaVersion    uint32
	catalogID        string
	sequence         uint64
	signingKeyID     string
	supportExpiresAt time.Time
	platform         PlatformPolicy
	runtime          RuntimePolicy
	artifact         ArtifactPolicy
	install          InstallerPolicy
	linuxExecution   *LinuxExecutionPolicy
	prerequisites    []Prerequisite
	capabilityProbes []CapabilityProbe
	terms            TermsPolicy
	canonical        []byte
	digest           Digest
}

// NewManifest validates all execution, trust, source, terms, support, and rollback boundaries.
func NewManifest(input ManifestInput) (Manifest, error) {
	if input.SchemaVersion != SupportedSchemaVersion || !validIdentifier(input.CatalogID) ||
		input.CatalogSequence == 0 || input.CatalogSequence > maximumSafeJSONInteger || !validIdentifier(input.SigningKeyID) ||
		input.SupportExpiresAt.IsZero() || input.SupportExpiresAt.UnixMicro() <= 0 ||
		uint64(input.SupportExpiresAt.UnixMicro()) > maximumSafeJSONInteger {
		return Manifest{}, ErrManifestIntegrity
	}
	platform, err := newPlatformPolicy(input.Platform)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	runtimePolicy, err := newRuntimePolicy(input.Runtime, platform.operatingSystem)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	artifact, err := newArtifactPolicy(input.Artifact, platform.operatingSystem)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	install, err := newInstallerPolicy(input.Install, platform.operatingSystem)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	var linuxExecution *LinuxExecutionPolicy
	if platform.operatingSystem == OSKindLinux {
		policy, policyError := newLinuxExecutionPolicy(input.LinuxExecution, artifact)
		if policyError != nil || input.LinuxExecution.MinimumAvailableMemory > platform.minimumMemoryBytes {
			return Manifest{}, ErrManifestIntegrity
		}
		linuxExecution = &policy
	} else if !linuxExecutionInputZero(input.LinuxExecution) {
		return Manifest{}, ErrManifestIntegrity
	}
	prerequisites, err := buildPrerequisites(input.Prerequisites)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	capabilities, err := buildCapabilities(input.CapabilityProbes, platform.operatingSystem)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	terms, err := newTermsPolicy(input.Terms)
	if err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	if !linuxManifestBindingsValid(
		linuxExecution, platform, artifact, install, prerequisites, capabilities, terms,
	) {
		return Manifest{}, ErrManifestIntegrity
	}
	manifest := Manifest{
		schemaVersion: input.SchemaVersion, catalogID: input.CatalogID, sequence: input.CatalogSequence,
		signingKeyID: input.SigningKeyID, supportExpiresAt: input.SupportExpiresAt.UTC(),
		platform: platform, runtime: runtimePolicy, artifact: artifact, install: install,
		linuxExecution: linuxExecution, prerequisites: prerequisites,
		capabilityProbes: capabilities, terms: terms,
	}
	canonical, err := marshalCanonical(manifest)
	if err != nil || len(canonical) == 0 || len(canonical) > maximumRawManifestBytes {
		return Manifest{}, ErrManifestIntegrity
	}
	manifest.canonical = canonical
	manifest.digest = DigestBytes(canonical)
	return manifest, nil
}

func buildPrerequisites(inputs []PrerequisiteInput) ([]Prerequisite, error) {
	if len(inputs) == 0 || len(inputs) > 32 {
		return nil, ErrManifestIntegrity
	}
	result := make([]Prerequisite, 0, len(inputs))
	previous := PrerequisiteOperation("")
	for _, input := range inputs {
		prerequisite, err := newPrerequisite(input)
		if err != nil || previous != "" && previous >= prerequisite.operation {
			return nil, ErrManifestIntegrity
		}
		previous = prerequisite.operation
		result = append(result, prerequisite)
	}
	return result, nil
}

func buildCapabilities(inputs []CapabilityProbe, platform OSKind) ([]CapabilityProbe, error) {
	if len(inputs) == 0 || len(inputs) > 16 || !sort.SliceIsSorted(inputs, func(left int, right int) bool {
		return inputs[left] < inputs[right]
	}) {
		return nil, ErrManifestIntegrity
	}
	seen := make(map[CapabilityProbe]struct{}, len(inputs))
	for _, probe := range inputs {
		if !probe.valid() {
			return nil, ErrManifestIntegrity
		}
		if _, duplicate := seen[probe]; duplicate {
			return nil, ErrManifestIntegrity
		}
		seen[probe] = struct{}{}
	}
	for _, required := range []CapabilityProbe{
		CapabilityBindReadOnly, CapabilityComposeVersion, CapabilityEngineAPI,
		CapabilityLinuxContainers, CapabilityLocalEndpoint, CapabilityNetworkIsolation,
		CapabilityNoTCPListener, CapabilitySecurityMode, CapabilityVolumePersistence,
	} {
		if _, present := seen[required]; !present {
			return nil, ErrManifestIntegrity
		}
	}
	if platform == OSKindLinux {
		if _, present := seen[CapabilityRootless]; !present {
			return nil, ErrManifestIntegrity
		}
	}
	return append([]CapabilityProbe(nil), inputs...), nil
}

func marshalCanonical(manifest Manifest) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(canonicalFromManifest(manifest)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

// SchemaVersion returns the wire schema major.
func (m Manifest) SchemaVersion() uint32 { return m.schemaVersion }

// CatalogID returns the catalog cell identity.
func (m Manifest) CatalogID() string { return m.catalogID }

// CatalogSequence returns the monotonic catalog anti-rollback sequence.
func (m Manifest) CatalogSequence() uint64 { return m.sequence }

// SigningKeyID returns the detached-signature trust-key identity.
func (m Manifest) SigningKeyID() string { return m.signingKeyID }

// SupportExpiresAt returns the exclusive UTC support expiry.
func (m Manifest) SupportExpiresAt() time.Time { return m.supportExpiresAt }

// Platform returns the exact certified platform range.
func (m Manifest) Platform() PlatformPolicy { return m.platform }

// Runtime returns the exact runtime and Compose versions.
func (m Manifest) Runtime() RuntimePolicy { return m.runtime }

// Artifact returns the exact artifact/source/publisher policy.
func (m Manifest) Artifact() ArtifactPolicy { return m.artifact }

// Install returns the closed installer policy.
func (m Manifest) Install() InstallerPolicy { return m.install }

// LinuxExecution returns the complete signed Linux execution projection when
// this is a Linux catalog cell. Other platforms return false.
func (m Manifest) LinuxExecution() (LinuxExecutionPolicy, bool) {
	if m.linuxExecution == nil {
		return LinuxExecutionPolicy{}, false
	}
	return *m.linuxExecution, true
}

// Prerequisites returns a defensive copy of typed privilege operations.
func (m Manifest) Prerequisites() []Prerequisite {
	return append([]Prerequisite(nil), m.prerequisites...)
}

// CapabilityProbes returns a defensive copy of required post-install proofs.
func (m Manifest) CapabilityProbes() []CapabilityProbe {
	return append([]CapabilityProbe(nil), m.capabilityProbes...)
}

// Terms returns the exact third-party terms binding.
func (m Manifest) Terms() TermsPolicy { return m.terms }

// CanonicalBytes returns a defensive copy of the signed canonical document.
func (m Manifest) CanonicalBytes() []byte { return append([]byte(nil), m.canonical...) }

// Digest returns SHA-256 over the exact canonical bytes.
func (m Manifest) Digest() Digest { return m.digest }

// Valid reports whether every immutable projection still reconstructs the signed identity.
func (m Manifest) Valid() bool {
	if m.schemaVersion != SupportedSchemaVersion || !m.platform.valid() ||
		!m.runtime.valid(m.platform.operatingSystem) || !m.artifact.valid(m.platform.operatingSystem) ||
		!m.terms.valid() || !m.install.valid(m.platform.operatingSystem) ||
		!linuxManifestBindingsValid(
			m.linuxExecution, m.platform, m.artifact, m.install, m.prerequisites, m.capabilityProbes, m.terms,
		) || !prerequisitesValid(m.prerequisites) ||
		!capabilitiesValid(m.capabilityProbes, m.platform.operatingSystem) ||
		len(m.canonical) == 0 || m.digest.IsZero() {
		return false
	}
	canonical, err := marshalCanonical(m)
	return err == nil && bytes.Equal(canonical, m.canonical) && DigestBytes(canonical).Equal(m.digest)
}

func prerequisitesValid(prerequisites []Prerequisite) bool {
	inputs := make([]PrerequisiteInput, 0, len(prerequisites))
	for _, prerequisite := range prerequisites {
		inputs = append(inputs, PrerequisiteInput{
			Operation: prerequisite.operation, FeatureID: prerequisite.featureID,
			PackageIDs:   append([]string(nil), prerequisite.packageIDs...),
			RepositoryID: prerequisite.repositoryID, ServiceID: prerequisite.serviceID,
			SubordinateIDCount: prerequisite.subordinateIDCount,
		})
	}
	validated, err := buildPrerequisites(inputs)
	return err == nil && len(validated) == len(prerequisites)
}

func capabilitiesValid(capabilities []CapabilityProbe, platform OSKind) bool {
	validated, err := buildCapabilities(capabilities, platform)
	return err == nil && len(validated) == len(capabilities)
}

// AuthorizeSource enforces online allowlisting and signed offline redistribution policy.
func (m Manifest) AuthorizeSource(mode SourceMode, requested *SourceLocation) error {
	if !m.Valid() {
		return ErrSourceDenied
	}
	switch mode {
	case SourceModeOnline:
		if requested == nil {
			return ErrSourceDenied
		}
		for _, official := range m.artifact.sources {
			if official.authorizes(*requested) {
				return nil
			}
		}
	case SourceModeOfflineBundle:
		if requested == nil && m.artifact.offlinePolicy == OfflinePolicyBundled &&
			m.artifact.redistributionPermitted {
			return nil
		}
	case SourceModeOfflineUserSelected:
		if requested == nil && m.artifact.offlinePolicy == OfflinePolicyUserSelectedOfficial &&
			!m.artifact.redistributionPermitted {
			return nil
		}
	case SourceModeUnknown:
	}
	return ErrSourceDenied
}

// SupportedAt reports whether the catalog cell remains supported at trusted UTC policy time.
func (m Manifest) SupportedAt(now time.Time) bool {
	return m.Valid() && !now.IsZero() && now.UTC().Before(m.supportExpiresAt)
}
