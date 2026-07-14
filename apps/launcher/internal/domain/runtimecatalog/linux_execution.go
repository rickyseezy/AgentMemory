package runtimecatalog

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// LinuxPackageManager is the closed native transaction backend certified by
// one Linux runtime catalog cell.
type LinuxPackageManager string

const (
	// LinuxPackageManagerAPT selects an exact Debian-family package transaction.
	LinuxPackageManagerAPT LinuxPackageManager = "apt"
	// LinuxPackageManagerDNF selects an exact RPM-family package transaction.
	LinuxPackageManagerDNF LinuxPackageManager = "dnf"
)

func (m LinuxPackageManager) valid() bool {
	return m == LinuxPackageManagerAPT || m == LinuxPackageManagerDNF
}

// LinuxPackagePurpose prevents a prerequisite from being substituted for a
// Docker runtime component even when a native package name overlaps.
type LinuxPackagePurpose string

const (
	// LinuxPackagePurposePrerequisite identifies the rootless identity prerequisite.
	LinuxPackagePurposePrerequisite LinuxPackagePurpose = "rootless_prerequisite"
	// LinuxPackagePurposeRuntime identifies one Docker runtime component.
	LinuxPackagePurposeRuntime LinuxPackagePurpose = "runtime_component"
)

func (p LinuxPackagePurpose) valid() bool {
	return p == LinuxPackagePurposePrerequisite || p == LinuxPackagePurposeRuntime
}

// LinuxRepositoryInput binds the exact official repository state consumed by
// the unprivileged acquisition adapter and later installed by the helper.
type LinuxRepositoryInput struct {
	ID                    string
	URL                   OfficialSourceInput
	Suite                 string
	Component             string
	SigningKeyFingerprint string
	SigningKeyDigest      Digest
	ConfigurationDigest   Digest
	MetadataDigest        Digest
}

// LinuxRepository is immutable signed repository authority.
type LinuxRepository struct {
	id                    string
	url                   SourceLocation
	suite                 string
	component             string
	signingKeyFingerprint string
	signingKeyDigest      Digest
	configurationDigest   Digest
	metadataDigest        Digest
}

func newLinuxRepository(input LinuxRepositoryInput, codename string) (LinuxRepository, error) {
	url, err := NewSourceLocation(input.URL)
	if err != nil || !strings.HasSuffix(input.URL.PathPrefix, "/") || !validIdentifier(input.ID) ||
		!validIdentifier(input.Suite) || input.Suite != codename || input.Component != "stable" ||
		!validUpperHexFingerprint(input.SigningKeyFingerprint) || input.SigningKeyDigest.IsZero() ||
		input.ConfigurationDigest.IsZero() || input.MetadataDigest.IsZero() {
		return LinuxRepository{}, ErrManifestIntegrity
	}
	return LinuxRepository{
		id: input.ID, url: url, suite: input.Suite, component: input.Component,
		signingKeyFingerprint: input.SigningKeyFingerprint,
		signingKeyDigest:      input.SigningKeyDigest, configurationDigest: input.ConfigurationDigest,
		metadataDigest: input.MetadataDigest,
	}, nil
}

// ID returns the signed repository identity.
func (r LinuxRepository) ID() string { return r.id }

// URL returns the structured official repository base URL.
func (r LinuxRepository) URL() SourceLocation { return r.url }

// Suite returns the exact distribution codename.
func (r LinuxRepository) Suite() string { return r.suite }

// Component returns the immutable stable repository component.
func (r LinuxRepository) Component() string { return r.component }

// SigningKeyFingerprint returns the exact uppercase OpenPGP fingerprint.
func (r LinuxRepository) SigningKeyFingerprint() string { return r.signingKeyFingerprint }

// SigningKeyDigest returns the exact repository-key artifact digest.
func (r LinuxRepository) SigningKeyDigest() Digest { return r.signingKeyDigest }

// ConfigurationDigest returns the canonical native repository configuration digest.
func (r LinuxRepository) ConfigurationDigest() Digest { return r.configurationDigest }

// MetadataDigest returns the pinned authenticated metadata-set digest.
func (r LinuxRepository) MetadataDigest() Digest { return r.metadataDigest }

// LinuxPackageInput is one exact retained native package. Source is a complete
// official file location, never a mutable repository query or package name.
type LinuxPackageInput struct {
	Name                string
	Version             string
	Purpose             LinuxPackagePurpose
	DownloadBytes       uint64
	SHA256              Digest
	NativeReceiptDigest Digest
	Source              OfficialSourceInput
}

// LinuxPackage is immutable acquisition and native publisher authority.
type LinuxPackage struct {
	name                string
	version             string
	purpose             LinuxPackagePurpose
	downloadBytes       uint64
	sha256              Digest
	nativeReceiptDigest Digest
	source              SourceLocation
}

// Name returns the exact native package identity.
func (p LinuxPackage) Name() string { return p.name }

// Version returns the complete native package version.
func (p LinuxPackage) Version() string { return p.version }

// Purpose returns the closed semantic package role.
func (p LinuxPackage) Purpose() LinuxPackagePurpose { return p.purpose }

// DownloadBytes returns the exact package artifact size.
func (p LinuxPackage) DownloadBytes() uint64 { return p.downloadBytes }

// SHA256 returns the exact package artifact digest.
func (p LinuxPackage) SHA256() Digest { return p.sha256 }

// NativeReceiptDigest returns the expected authenticated metadata receipt.
func (p LinuxPackage) NativeReceiptDigest() Digest { return p.nativeReceiptDigest }

// Source returns the exact official package artifact URL.
func (p LinuxPackage) Source() SourceLocation { return p.source }

// LinuxExecutionPolicyInput is the complete signed Linux-only execution
// projection. Host identity and observations are deliberately supplied later
// by a native probe and cannot be declared by the catalog.
type LinuxExecutionPolicyInput struct {
	PackageManager            LinuxPackageManager
	PackageManagerVersion     string
	Codename                  string
	MinimumKernel             string
	MinimumAvailableMemory    uint64
	Repository                LinuxRepositoryInput
	Packages                  []LinuxPackageInput
	PackageSetDigest          Digest
	SubordinateIDCount        uint32
	SELinuxEnforcingSupported bool
	ServiceID                 string
	ServiceUnitDigest         Digest
	RootlessToolPath          string
	RootlessToolDigest        Digest
	ProbeImage                string
	ProbeImageDigest          Digest
	ProbeContractVersion      string
	CapabilityPolicyDigest    Digest
}

// LinuxExecutionPolicy is present only in a Linux catalog cell.
type LinuxExecutionPolicy struct {
	packageManager            LinuxPackageManager
	packageManagerVersion     string
	codename                  string
	minimumKernel             string
	minimumAvailableMemory    uint64
	repository                LinuxRepository
	packages                  []LinuxPackage
	packageSetDigest          Digest
	subordinateIDCount        uint32
	selinuxEnforcingSupported bool
	serviceID                 string
	serviceUnitDigest         Digest
	rootlessToolPath          string
	rootlessToolDigest        Digest
	probeImage                string
	probeImageDigest          Digest
	probeContractVersion      string
	capabilityPolicyDigest    Digest
}

func newLinuxExecutionPolicy(
	input LinuxExecutionPolicyInput,
	artifact ArtifactPolicy,
) (LinuxExecutionPolicy, error) {
	if !input.PackageManager.valid() || !validLinuxPackageVersion(input.PackageManagerVersion) ||
		!validIdentifier(input.Codename) || !validLinuxPackageVersion(input.MinimumKernel) ||
		input.MinimumAvailableMemory == 0 || input.MinimumAvailableMemory > maximumSafeJSONInteger ||
		input.PackageSetDigest.IsZero() || input.SubordinateIDCount < 65536 ||
		input.ServiceID != "docker.service" || input.ServiceUnitDigest.IsZero() ||
		input.RootlessToolPath != "/usr/bin/dockerd-rootless-setuptool.sh" || input.RootlessToolDigest.IsZero() ||
		input.ProbeContractVersion != "1" || input.CapabilityPolicyDigest.IsZero() ||
		!validLinuxProbeImage(input.ProbeImage, input.ProbeImageDigest) {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	repository, err := newLinuxRepository(input.Repository, input.Codename)
	if err != nil || !repositoryMatchesManager(repository, input.PackageManager) {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	packages, err := newLinuxPackages(input.PackageManager, input.Packages, artifact)
	if err != nil || !LinuxPackageSetDigest(input.Packages).Equal(input.PackageSetDigest) ||
		!input.PackageSetDigest.Equal(artifact.sha256) || packageDownloadBytes(packages) != artifact.downloadBytes {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	return LinuxExecutionPolicy{
		packageManager: input.PackageManager, packageManagerVersion: input.PackageManagerVersion,
		codename: input.Codename, minimumKernel: input.MinimumKernel,
		minimumAvailableMemory: input.MinimumAvailableMemory, repository: repository,
		packages: packages, packageSetDigest: input.PackageSetDigest,
		subordinateIDCount:        input.SubordinateIDCount,
		selinuxEnforcingSupported: input.SELinuxEnforcingSupported,
		serviceID:                 input.ServiceID, serviceUnitDigest: input.ServiceUnitDigest,
		rootlessToolPath: input.RootlessToolPath, rootlessToolDigest: input.RootlessToolDigest,
		probeImage: input.ProbeImage, probeImageDigest: input.ProbeImageDigest,
		probeContractVersion:   input.ProbeContractVersion,
		capabilityPolicyDigest: input.CapabilityPolicyDigest,
	}, nil
}

func newLinuxPackages(
	manager LinuxPackageManager,
	inputs []LinuxPackageInput,
	artifact ArtifactPolicy,
) ([]LinuxPackage, error) {
	if len(inputs) != 7 || !sort.SliceIsSorted(inputs, func(left, right int) bool {
		return inputs[left].Name < inputs[right].Name
	}) {
		return nil, ErrManifestIntegrity
	}
	wanted := map[string]LinuxPackagePurpose{
		"containerd.io": LinuxPackagePurposeRuntime, "docker-buildx-plugin": LinuxPackagePurposeRuntime,
		"docker-ce": LinuxPackagePurposeRuntime, "docker-ce-cli": LinuxPackagePurposeRuntime,
		"docker-ce-rootless-extras": LinuxPackagePurposeRuntime,
		"docker-compose-plugin":     LinuxPackagePurposeRuntime,
	}
	if manager == LinuxPackageManagerAPT {
		wanted["uidmap"] = LinuxPackagePurposePrerequisite
	} else {
		wanted["shadow-utils"] = LinuxPackagePurposePrerequisite
	}
	result := make([]LinuxPackage, 0, len(inputs))
	for index, input := range inputs {
		purpose, present := wanted[input.Name]
		source, sourceError := NewSourceLocation(input.Source)
		if !present || purpose != input.Purpose || !input.Purpose.valid() ||
			!validLinuxPackageVersion(input.Version) || input.DownloadBytes == 0 ||
			input.DownloadBytes > maximumSafeJSONInteger || input.SHA256.IsZero() ||
			input.NativeReceiptDigest.IsZero() || sourceError != nil ||
			strings.HasSuffix(input.Source.PathPrefix, "/") || !artifactAuthorizesSource(artifact, source) ||
			index > 0 && inputs[index-1].Name == input.Name {
			return nil, ErrManifestIntegrity
		}
		delete(wanted, input.Name)
		result = append(result, LinuxPackage{
			name: input.Name, version: input.Version, purpose: input.Purpose,
			downloadBytes: input.DownloadBytes, sha256: input.SHA256,
			nativeReceiptDigest: input.NativeReceiptDigest, source: source,
		})
	}
	if len(wanted) != 0 {
		return nil, ErrManifestIntegrity
	}
	return result, nil
}

func artifactAuthorizesSource(artifact ArtifactPolicy, requested SourceLocation) bool {
	for _, source := range artifact.sources {
		if source.authorizes(requested) {
			return true
		}
	}
	return false
}

func repositoryMatchesManager(repository LinuxRepository, manager LinuxPackageManager) bool {
	path := repository.url.PathPrefix()
	return repository.url.Host() == "download.docker.com" &&
		(manager == LinuxPackageManagerAPT && (strings.HasPrefix(path, "/linux/ubuntu/") ||
			strings.HasPrefix(path, "/linux/debian/")) ||
			manager == LinuxPackageManagerDNF && (strings.HasPrefix(path, "/linux/fedora/") ||
				strings.HasPrefix(path, "/linux/centos/")))
}

func validLinuxPackageVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(strings.ToLower(value), "latest") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:+~-", character) {
			continue
		}
		return false
	}
	return true
}

func validUpperHexFingerprint(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'A' && character <= 'F' {
			continue
		}
		return false
	}
	return true
}

func validLinuxProbeImage(value string, digest Digest) bool {
	if digest.IsZero() || len(value) > 512 || strings.Count(value, "@sha256:") != 1 ||
		strings.ContainsAny(value, "\x00\r\n *?$`\\") {
		return false
	}
	name, encoded, present := strings.Cut(value, "@sha256:")
	if !present || name == "" || encoded != digest.Hex() || strings.Contains(name, "..") || strings.Contains(name, "//") {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			strings.ContainsRune("./:_-", character) {
			continue
		}
		return false
	}
	return true
}

// LinuxPackageSetDigest returns the signed aggregate identity over the exact,
// sorted retained package projection. Invalid or unsorted inputs return zero.
func LinuxPackageSetDigest(inputs []LinuxPackageInput) Digest {
	if len(inputs) == 0 || !sort.SliceIsSorted(inputs, func(left, right int) bool {
		return inputs[left].Name < inputs[right].Name
	}) {
		return Digest{}
	}
	type canonicalPackage struct {
		DownloadBytes uint64              `json:"download_bytes"`
		Name          string              `json:"name"`
		Purpose       LinuxPackagePurpose `json:"purpose"`
		Receipt       string              `json:"receipt_digest"`
		SHA256        string              `json:"sha256"`
		Source        canonicalSource     `json:"source"`
		Version       string              `json:"version"`
	}
	document := make([]canonicalPackage, 0, len(inputs))
	for _, input := range inputs {
		document = append(document, canonicalPackage{
			DownloadBytes: input.DownloadBytes, Name: input.Name, Purpose: input.Purpose,
			Receipt: input.NativeReceiptDigest.Hex(), SHA256: input.SHA256.Hex(),
			Source:  canonicalSource{Scheme: input.Source.Scheme, Host: input.Source.Host, PathPrefix: input.Source.PathPrefix},
			Version: input.Version,
		})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return Digest{}
	}
	return DigestBytes(bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}))
}

func packageDownloadBytes(packages []LinuxPackage) uint64 {
	var total uint64
	for _, pkg := range packages {
		if total > maximumSafeJSONInteger-pkg.downloadBytes {
			return maximumSafeJSONInteger
		}
		total += pkg.downloadBytes
	}
	return total
}

func linuxExecutionInputZero(input LinuxExecutionPolicyInput) bool {
	return input.PackageManager == "" && input.PackageManagerVersion == "" && input.Codename == "" &&
		input.MinimumKernel == "" && input.MinimumAvailableMemory == 0 && input.Repository == (LinuxRepositoryInput{}) &&
		len(input.Packages) == 0 && input.PackageSetDigest.IsZero() && input.SubordinateIDCount == 0 &&
		!input.SELinuxEnforcingSupported && input.ServiceID == "" && input.ServiceUnitDigest.IsZero() &&
		input.RootlessToolPath == "" && input.RootlessToolDigest.IsZero() && input.ProbeImage == "" &&
		input.ProbeImageDigest.IsZero() && input.ProbeContractVersion == "" && input.CapabilityPolicyDigest.IsZero()
}

func linuxExecutionValid(policy *LinuxExecutionPolicy, platform PlatformPolicy, artifact ArtifactPolicy) bool {
	if platform.operatingSystem != OSKindLinux {
		return policy == nil
	}
	return policy != nil && policy.minimumAvailableMemory <= platform.minimumMemoryBytes && policy.ValidFor(artifact)
}

func linuxManifestBindingsValid(
	policy *LinuxExecutionPolicy,
	platform PlatformPolicy,
	artifact ArtifactPolicy,
	install InstallerPolicy,
	prerequisites []Prerequisite,
	capabilities []CapabilityProbe,
	terms TermsPolicy,
) bool {
	if platform.operatingSystem != OSKindLinux {
		return policy == nil
	}
	if policy == nil || !linuxExecutionValid(policy, platform, artifact) ||
		!managerMatchesDistribution(policy.packageManager, platform.distribution) ||
		policy.repository.url.PathPrefix() != "/linux/"+platform.distribution+"/" ||
		artifact.publisher.verification != NativeVerificationPackageSignature ||
		artifact.publisher.packageIdentity != "docker-engine-package-set" ||
		install.executable != InstallerExecutableRootlessSetup ||
		install.serviceIdentity != policy.serviceID ||
		terms.presentation != TermsPresentationAgentMemory ||
		!LinuxCapabilityPolicyDigest(capabilities).Equal(policy.capabilityPolicyDigest) {
		return false
	}
	packageIDs := make([]string, 0, len(policy.packages))
	for _, pkg := range policy.packages {
		packageIDs = append(packageIDs, pkg.name)
	}
	wanted := []PrerequisiteInput{
		{Operation: PrerequisiteConfigureOfficialRepository, RepositoryID: policy.repository.id},
		{Operation: PrerequisiteConfigureSubordinateIDs, SubordinateIDCount: policy.subordinateIDCount},
		{Operation: PrerequisiteEnableUserService, ServiceID: policy.serviceID},
		{Operation: PrerequisiteInstallVerifiedPackage, PackageIDs: packageIDs},
	}
	if len(prerequisites) != len(wanted) {
		return false
	}
	for index, expected := range wanted {
		actual := prerequisites[index]
		if actual.operation != expected.Operation || actual.featureID != expected.FeatureID ||
			actual.repositoryID != expected.RepositoryID || actual.serviceID != expected.ServiceID ||
			actual.subordinateIDCount != expected.SubordinateIDCount ||
			!slicesEqualStrings(actual.packageIDs, expected.PackageIDs) {
			return false
		}
	}
	return true
}

func managerMatchesDistribution(manager LinuxPackageManager, distribution string) bool {
	return manager == LinuxPackageManagerAPT && (distribution == "ubuntu" || distribution == "debian") ||
		manager == LinuxPackageManagerDNF && (distribution == "fedora" || distribution == "centos")
}

func slicesEqualStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// LinuxCapabilityPolicyDigest binds the sorted active-probe contract consumed
// by the Linux authority resolver. Invalid or unsorted probes return zero.
func LinuxCapabilityPolicyDigest(capabilities []CapabilityProbe) Digest {
	if len(capabilities) == 0 || !sort.SliceIsSorted(capabilities, func(left, right int) bool {
		return capabilities[left] < capabilities[right]
	}) {
		return Digest{}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(capabilities); err != nil {
		return Digest{}
	}
	return DigestBytes(bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}))
}

// PackageManager returns the closed native transaction backend.
func (p LinuxExecutionPolicy) PackageManager() LinuxPackageManager { return p.packageManager }

// PackageManagerVersion returns the exact certified native backend version.
func (p LinuxExecutionPolicy) PackageManagerVersion() string { return p.packageManagerVersion }

// Codename returns the exact distribution suite.
func (p LinuxExecutionPolicy) Codename() string { return p.codename }

// MinimumKernel returns the signed kernel floor.
func (p LinuxExecutionPolicy) MinimumKernel() string { return p.minimumKernel }

// MinimumAvailableMemory returns the signed available-memory floor.
func (p LinuxExecutionPolicy) MinimumAvailableMemory() uint64 { return p.minimumAvailableMemory }

// Repository returns immutable official repository authority.
func (p LinuxExecutionPolicy) Repository() LinuxRepository { return p.repository }

// Packages returns a defensive copy of the full retained package set.
func (p LinuxExecutionPolicy) Packages() []LinuxPackage {
	return append([]LinuxPackage(nil), p.packages...)
}

// PackageSetDigest returns the aggregate retained-set identity.
func (p LinuxExecutionPolicy) PackageSetDigest() Digest { return p.packageSetDigest }

// SubordinateIDCount returns the required rootless UID/GID allocation.
func (p LinuxExecutionPolicy) SubordinateIDCount() uint32 { return p.subordinateIDCount }

// SELinuxEnforcingSupported reports signed enforcing-mode support.
func (p LinuxExecutionPolicy) SELinuxEnforcingSupported() bool { return p.selinuxEnforcingSupported }

// ServiceID returns the only authorized per-user service.
func (p LinuxExecutionPolicy) ServiceID() string { return p.serviceID }

// ServiceUnitDigest returns the expected packaged user-unit digest.
func (p LinuxExecutionPolicy) ServiceUnitDigest() Digest { return p.serviceUnitDigest }

// RootlessToolPath returns the fixed packaged setup-tool path.
func (p LinuxExecutionPolicy) RootlessToolPath() string { return p.rootlessToolPath }

// RootlessToolDigest returns the exact setup-tool receipt binding.
func (p LinuxExecutionPolicy) RootlessToolDigest() Digest { return p.rootlessToolDigest }

// ProbeImage returns the immutable active-probe OCI reference.
func (p LinuxExecutionPolicy) ProbeImage() string { return p.probeImage }

// ProbeImageDigest returns the exact active-probe OCI manifest digest.
func (p LinuxExecutionPolicy) ProbeImageDigest() Digest { return p.probeImageDigest }

// ProbeContractVersion returns the closed active-probe entrypoint contract.
func (p LinuxExecutionPolicy) ProbeContractVersion() string { return p.probeContractVersion }

// CapabilityPolicyDigest returns the complete active-probe policy binding.
func (p LinuxExecutionPolicy) CapabilityPolicyDigest() Digest { return p.capabilityPolicyDigest }

// ValidFor reconstructs the complete Linux execution projection against the
// catalog's aggregate artifact policy.
func (p LinuxExecutionPolicy) ValidFor(artifact ArtifactPolicy) bool {
	inputs := make([]LinuxPackageInput, 0, len(p.packages))
	for _, pkg := range p.packages {
		inputs = append(inputs, LinuxPackageInput{
			Name: pkg.name, Version: pkg.version, Purpose: pkg.purpose,
			DownloadBytes: pkg.downloadBytes, SHA256: pkg.sha256,
			NativeReceiptDigest: pkg.nativeReceiptDigest,
			Source:              OfficialSourceInput{Scheme: pkg.source.scheme, Host: pkg.source.host, PathPrefix: pkg.source.pathPrefix},
		})
	}
	validated, err := newLinuxExecutionPolicy(LinuxExecutionPolicyInput{
		PackageManager: p.packageManager, PackageManagerVersion: p.packageManagerVersion,
		Codename: p.codename, MinimumKernel: p.minimumKernel,
		MinimumAvailableMemory: p.minimumAvailableMemory,
		Repository: LinuxRepositoryInput{
			ID:    p.repository.id,
			URL:   OfficialSourceInput{Scheme: p.repository.url.scheme, Host: p.repository.url.host, PathPrefix: p.repository.url.pathPrefix},
			Suite: p.repository.suite, Component: p.repository.component,
			SigningKeyFingerprint: p.repository.signingKeyFingerprint,
			SigningKeyDigest:      p.repository.signingKeyDigest,
			ConfigurationDigest:   p.repository.configurationDigest,
			MetadataDigest:        p.repository.metadataDigest,
		},
		Packages: inputs, PackageSetDigest: p.packageSetDigest,
		SubordinateIDCount:        p.subordinateIDCount,
		SELinuxEnforcingSupported: p.selinuxEnforcingSupported,
		ServiceID:                 p.serviceID, ServiceUnitDigest: p.serviceUnitDigest,
		RootlessToolPath: p.rootlessToolPath, RootlessToolDigest: p.rootlessToolDigest,
		ProbeImage: p.probeImage, ProbeImageDigest: p.probeImageDigest,
		ProbeContractVersion:   p.probeContractVersion,
		CapabilityPolicyDigest: p.capabilityPolicyDigest,
	}, artifact)
	return err == nil && len(validated.packages) == len(p.packages)
}
