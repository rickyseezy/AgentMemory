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

// LinuxRepositoryArtifactRole identifies one exact native trust-chain input.
type LinuxRepositoryArtifactRole string

const (
	// LinuxRepositoryArtifactSigningKey identifies the pinned repository signing key.
	LinuxRepositoryArtifactSigningKey LinuxRepositoryArtifactRole = "signing_key"
	// LinuxRepositoryArtifactSignedMetadata identifies inline- or detached-signed repository metadata.
	LinuxRepositoryArtifactSignedMetadata LinuxRepositoryArtifactRole = "signed_metadata"
	// LinuxRepositoryArtifactMetadataSignature identifies a detached repository-metadata signature.
	LinuxRepositoryArtifactMetadataSignature LinuxRepositoryArtifactRole = "metadata_signature"
	// LinuxRepositoryArtifactPackageIndex identifies the package index authenticated by repository metadata.
	LinuxRepositoryArtifactPackageIndex LinuxRepositoryArtifactRole = "package_index"
)

// LinuxRepositoryMetadataAuthentication is the closed publisher-authentication
// mode for native repository metadata. Package signatures remain mandatory for
// every DNF package regardless of this mode.
type LinuxRepositoryMetadataAuthentication string

const (
	// LinuxRepositoryMetadataAuthenticationInline identifies APT InRelease
	// metadata whose OpenPGP signature is carried in the metadata object.
	LinuxRepositoryMetadataAuthenticationInline LinuxRepositoryMetadataAuthentication = "inline"
	// LinuxRepositoryMetadataAuthenticationDetached identifies DNF repomd.xml
	// metadata with a separately retained publisher signature.
	LinuxRepositoryMetadataAuthenticationDetached LinuxRepositoryMetadataAuthentication = "detached"
	// LinuxRepositoryMetadataAuthenticationPackageSignatures identifies a DNF
	// repository that does not publish signed metadata. Its metadata is pinned by
	// the signed AgentMemory catalog and every selected RPM must authenticate to
	// the repository's exact publisher key.
	LinuxRepositoryMetadataAuthenticationPackageSignatures LinuxRepositoryMetadataAuthentication = "package_signatures"
)

func (m LinuxRepositoryMetadataAuthentication) validFor(manager LinuxPackageManager) bool {
	if manager == LinuxPackageManagerAPT {
		return m == LinuxRepositoryMetadataAuthenticationInline
	}
	return manager == LinuxPackageManagerDNF &&
		(m == LinuxRepositoryMetadataAuthenticationDetached ||
			m == LinuxRepositoryMetadataAuthenticationPackageSignatures)
}

// LinuxRepositoryArtifactInput is one exact official trust-chain resource.
type LinuxRepositoryArtifactInput struct {
	Role          LinuxRepositoryArtifactRole
	DownloadBytes uint64
	SHA256        Digest
	Source        OfficialSourceInput
}

// LinuxRepositoryArtifact is an immutable retained trust-chain resource.
type LinuxRepositoryArtifact struct {
	role          LinuxRepositoryArtifactRole
	downloadBytes uint64
	sha256        Digest
	source        SourceLocation
}

// Role returns the resource's fixed trust-chain role.
func (a LinuxRepositoryArtifact) Role() LinuxRepositoryArtifactRole { return a.role }

// DownloadBytes returns the exact retained resource size.
func (a LinuxRepositoryArtifact) DownloadBytes() uint64 { return a.downloadBytes }

// SHA256 returns the signed expected resource digest.
func (a LinuxRepositoryArtifact) SHA256() Digest { return a.sha256 }

// Source returns the exact official resource location.
func (a LinuxRepositoryArtifact) Source() SourceLocation { return a.source }

// LinuxRepositoryInput binds the exact official repository state consumed by
// the unprivileged acquisition adapter and later installed by the helper.
type LinuxRepositoryInput struct {
	ID                     string
	URL                    OfficialSourceInput
	Suite                  string
	Component              string
	SigningKeyFingerprint  string
	SigningKeyDigest       Digest
	ConfigurationDigest    Digest
	MetadataDigest         Digest
	MetadataAuthentication LinuxRepositoryMetadataAuthentication
	VerificationArtifacts  []LinuxRepositoryArtifactInput
}

// LinuxRepository is immutable signed repository authority.
type LinuxRepository struct {
	id                     string
	url                    SourceLocation
	suite                  string
	component              string
	signingKeyFingerprint  string
	signingKeyDigest       Digest
	configurationDigest    Digest
	metadataDigest         Digest
	metadataAuthentication LinuxRepositoryMetadataAuthentication
	verification           []LinuxRepositoryArtifact
}

func newLinuxRepository(
	input LinuxRepositoryInput,
	codename string,
	manager LinuxPackageManager,
	primary bool,
) (LinuxRepository, error) {
	url, err := NewSourceLocation(input.URL)
	if err != nil || !strings.HasSuffix(input.URL.PathPrefix, "/") || !validIdentifier(input.ID) ||
		!validIdentifier(input.Suite) || !validIdentifier(input.Component) ||
		(primary && (input.Suite != codename || input.Component != "stable")) ||
		(!primary && input.Suite != codename && !strings.HasPrefix(input.Suite, codename+"-")) ||
		!validUpperHexFingerprint(input.SigningKeyFingerprint) || input.SigningKeyDigest.IsZero() ||
		!input.MetadataAuthentication.validFor(manager) ||
		input.ConfigurationDigest.IsZero() || input.MetadataDigest.IsZero() {
		return LinuxRepository{}, ErrManifestIntegrity
	}
	verification, err := newLinuxRepositoryArtifacts(
		input.VerificationArtifacts, manager, input.MetadataAuthentication, url, input.Suite, input.Component,
	)
	if err != nil || len(verification) == 0 || !verification[0].sha256.Equal(input.SigningKeyDigest) ||
		!LinuxRepositoryMetadataDigest(input.VerificationArtifacts).Equal(input.MetadataDigest) {
		return LinuxRepository{}, ErrManifestIntegrity
	}
	return LinuxRepository{
		id: input.ID, url: url, suite: input.Suite, component: input.Component,
		signingKeyFingerprint: input.SigningKeyFingerprint,
		signingKeyDigest:      input.SigningKeyDigest, configurationDigest: input.ConfigurationDigest,
		metadataDigest: input.MetadataDigest, metadataAuthentication: input.MetadataAuthentication,
		verification: verification,
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

// MetadataAuthentication returns the exact signed repository-metadata policy.
func (r LinuxRepository) MetadataAuthentication() LinuxRepositoryMetadataAuthentication {
	return r.metadataAuthentication
}

// VerificationArtifacts returns the fixed-order native trust-chain inputs.
func (r LinuxRepository) VerificationArtifacts() []LinuxRepositoryArtifact {
	return append([]LinuxRepositoryArtifact(nil), r.verification...)
}

func newLinuxRepositoryArtifacts(
	inputs []LinuxRepositoryArtifactInput,
	manager LinuxPackageManager,
	metadataAuthentication LinuxRepositoryMetadataAuthentication,
	repository SourceLocation,
	codename string,
	component string,
) ([]LinuxRepositoryArtifact, error) {
	expected := []LinuxRepositoryArtifactRole{
		LinuxRepositoryArtifactSigningKey,
		LinuxRepositoryArtifactSignedMetadata,
		LinuxRepositoryArtifactPackageIndex,
	}
	if manager == LinuxPackageManagerDNF &&
		metadataAuthentication == LinuxRepositoryMetadataAuthenticationDetached {
		expected = []LinuxRepositoryArtifactRole{
			LinuxRepositoryArtifactSigningKey,
			LinuxRepositoryArtifactSignedMetadata,
			LinuxRepositoryArtifactMetadataSignature,
			LinuxRepositoryArtifactPackageIndex,
		}
	}
	if len(inputs) != len(expected) {
		return nil, ErrManifestIntegrity
	}
	result := make([]LinuxRepositoryArtifact, 0, len(inputs))
	for index, input := range inputs {
		source, err := NewSourceLocation(input.Source)
		if err != nil || input.Role != expected[index] || input.DownloadBytes == 0 ||
			input.DownloadBytes > maximumLinuxRepositoryArtifactBytes(input.Role) || input.SHA256.IsZero() ||
			source.Scheme() != repository.Scheme() ||
			(input.Role != LinuxRepositoryArtifactSigningKey && source.Host() != repository.Host()) ||
			!linuxRepositoryArtifactPathValid(manager, input.Role, source.PathPrefix(), repository.PathPrefix(), codename, component) {
			return nil, ErrManifestIntegrity
		}
		result = append(result, LinuxRepositoryArtifact{
			role: input.Role, downloadBytes: input.DownloadBytes, sha256: input.SHA256, source: source,
		})
	}
	if manager == LinuxPackageManagerDNF && len(result) == 4 &&
		result[2].source.PathPrefix() != result[1].source.PathPrefix()+".asc" {
		return nil, ErrManifestIntegrity
	}
	return result, nil
}

func maximumLinuxRepositoryArtifactBytes(role LinuxRepositoryArtifactRole) uint64 {
	if role == LinuxRepositoryArtifactSigningKey || role == LinuxRepositoryArtifactMetadataSignature {
		return 1 << 20
	}
	return 64 << 20
}

func linuxRepositoryArtifactPathValid(
	manager LinuxPackageManager,
	role LinuxRepositoryArtifactRole,
	path string,
	repositoryPath string,
	codename string,
	component string,
) bool {
	base := strings.TrimSuffix(repositoryPath, "/")
	if role == LinuxRepositoryArtifactSigningKey {
		return strings.HasSuffix(path, "/gpg") || strings.HasSuffix(path, ".gpg")
	}
	if manager == LinuxPackageManagerAPT {
		switch role {
		case LinuxRepositoryArtifactSignedMetadata:
			return path == base+"/dists/"+codename+"/InRelease"
		case LinuxRepositoryArtifactPackageIndex:
			prefix := base + "/dists/" + codename + "/" + component + "/binary-"
			return strings.HasPrefix(path, prefix) &&
				(strings.HasSuffix(path, "/Packages") || strings.HasSuffix(path, "/Packages.gz") ||
					strings.HasSuffix(path, "/Packages.xz"))
		case LinuxRepositoryArtifactSigningKey, LinuxRepositoryArtifactMetadataSignature:
			return false
		}
	}
	if manager != LinuxPackageManagerDNF || !strings.HasPrefix(path, base+"/") {
		return false
	}
	switch role {
	case LinuxRepositoryArtifactSignedMetadata:
		return path == base+"/repodata/repomd.xml"
	case LinuxRepositoryArtifactMetadataSignature:
		return path == base+"/repodata/repomd.xml.asc"
	case LinuxRepositoryArtifactPackageIndex:
		return strings.HasPrefix(path, base+"/repodata/") && strings.HasSuffix(path, "-primary.xml.gz")
	case LinuxRepositoryArtifactSigningKey:
		return false
	}
	return false
}

// LinuxRepositoryMetadataDigest binds every native metadata/signature/index
// artifact in fixed verification order. The signing key has its own digest.
func LinuxRepositoryMetadataDigest(inputs []LinuxRepositoryArtifactInput) Digest {
	if len(inputs) < 3 || inputs[0].Role != LinuxRepositoryArtifactSigningKey {
		return Digest{}
	}
	type canonicalRepositoryArtifact struct {
		DownloadBytes uint64                      `json:"download_bytes"`
		Role          LinuxRepositoryArtifactRole `json:"role"`
		SHA256        string                      `json:"sha256"`
		Source        canonicalSource             `json:"source"`
	}
	document := make([]canonicalRepositoryArtifact, 0, len(inputs)-1)
	for _, input := range inputs[1:] {
		if input.DownloadBytes == 0 || input.SHA256.IsZero() {
			return Digest{}
		}
		document = append(document, canonicalRepositoryArtifact{
			DownloadBytes: input.DownloadBytes, Role: input.Role, SHA256: input.SHA256.Hex(),
			Source: canonicalSource{
				Scheme: input.Source.Scheme, Host: input.Source.Host, PathPrefix: input.Source.PathPrefix,
			},
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return Digest{}
	}
	return DigestBytes(encoded)
}

// LinuxPackageInput is one exact retained native package. Source is a complete
// official file location, never a mutable repository query or package name.
type LinuxPackageInput struct {
	Name                string
	Version             string
	Purpose             LinuxPackagePurpose
	RepositoryID        string
	DownloadBytes       uint64
	SHA256              Digest
	NativeReceiptDigest Digest
	Source              OfficialSourceInput
}

// LinuxNativePackageReceiptDigest binds the exact package-index fields that a
// native repository verifier must authenticate before the package is eligible
// for a privileged transaction. Catalog producers must use this canonical
// receipt; arbitrary opaque receipt digests are rejected.
func LinuxNativePackageReceiptDigest(manager LinuxPackageManager, input LinuxPackageInput) Digest {
	if !manager.valid() || input.Name == "" || input.Version == "" || input.RepositoryID == "" || input.DownloadBytes == 0 ||
		input.SHA256.IsZero() || input.Source.Scheme == "" || input.Source.Host == "" ||
		input.Source.PathPrefix == "" {
		return Digest{}
	}
	document := struct {
		DownloadBytes uint64              `json:"download_bytes"`
		Manager       LinuxPackageManager `json:"manager"`
		Name          string              `json:"name"`
		RepositoryID  string              `json:"repository_id"`
		SHA256        string              `json:"sha256"`
		Source        canonicalSource     `json:"source"`
		Version       string              `json:"version"`
	}{
		DownloadBytes: input.DownloadBytes, Manager: manager, Name: input.Name, RepositoryID: input.RepositoryID,
		SHA256: input.SHA256.Hex(), Version: input.Version,
		Source: canonicalSource{
			Scheme: input.Source.Scheme, Host: input.Source.Host, PathPrefix: input.Source.PathPrefix,
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return Digest{}
	}
	return DigestBytes(encoded)
}

// LinuxPackage is immutable acquisition and native publisher authority.
type LinuxPackage struct {
	name                string
	version             string
	purpose             LinuxPackagePurpose
	repositoryID        string
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

// RepositoryID returns the signed repository that authenticates this package.
func (p LinuxPackage) RepositoryID() string { return p.repositoryID }

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
	PackageManager                    LinuxPackageManager
	PackageManagerVersion             string
	Codename                          string
	MinimumKernel                     string
	MinimumAvailableMemory            uint64
	Repository                        LinuxRepositoryInput
	VerificationRepositories          []LinuxRepositoryInput
	Packages                          []LinuxPackageInput
	PackageSetDigest                  Digest
	RollbackHeadroomBytes             uint64
	AcquisitionSafetyBytes            uint64
	SubordinateIDCount                uint32
	SELinuxEnforcingSupported         bool
	ServiceID                         string
	ServiceUnitDigest                 Digest
	DockerCLIPath                     string
	DockerCLISHA256                   Digest
	ComposePluginPath                 string
	ComposePluginSHA256               Digest
	RPMKeysPath                       string
	RPMKeysSHA256                     Digest
	RPMKeysPackageVersion             string
	RPMKeysPackageReceiptDigest       Digest
	PrivilegeToolPath                 string
	PrivilegeToolSHA256               Digest
	PrivilegeToolPackage              string
	PrivilegeToolPackageVersion       string
	PrivilegeToolPackageReceiptDigest Digest
	RootlessToolPath                  string
	RootlessToolDigest                Digest
	ProbeImage                        string
	ProbeImageDigest                  Digest
	ProbeContractVersion              string
	CapabilityPolicyDigest            Digest
}

// LinuxExecutionPolicy is present only in a Linux catalog cell.
type LinuxExecutionPolicy struct {
	packageManager                    LinuxPackageManager
	packageManagerVersion             string
	codename                          string
	minimumKernel                     string
	minimumAvailableMemory            uint64
	repository                        LinuxRepository
	verificationRepositories          []LinuxRepository
	packages                          []LinuxPackage
	packageSetDigest                  Digest
	rollbackHeadroomBytes             uint64
	acquisitionSafetyBytes            uint64
	subordinateIDCount                uint32
	selinuxEnforcingSupported         bool
	serviceID                         string
	serviceUnitDigest                 Digest
	dockerCLIPath                     string
	dockerCLISHA256                   Digest
	composePluginPath                 string
	composePluginSHA256               Digest
	rpmKeysPath                       string
	rpmKeysSHA256                     Digest
	rpmKeysPackageVersion             string
	rpmKeysPackageReceiptDigest       Digest
	privilegeToolPath                 string
	privilegeToolSHA256               Digest
	privilegeToolPackage              string
	privilegeToolPackageVersion       string
	privilegeToolPackageReceiptDigest Digest
	rootlessToolPath                  string
	rootlessToolDigest                Digest
	probeImage                        string
	probeImageDigest                  Digest
	probeContractVersion              string
	capabilityPolicyDigest            Digest
}

func newLinuxExecutionPolicy(
	input LinuxExecutionPolicyInput,
	artifact ArtifactPolicy,
) (LinuxExecutionPolicy, error) {
	if !input.PackageManager.valid() || !validLinuxPackageVersion(input.PackageManagerVersion) ||
		!validIdentifier(input.Codename) || !validLinuxPackageVersion(input.MinimumKernel) ||
		input.MinimumAvailableMemory == 0 || input.MinimumAvailableMemory > maximumSafeJSONInteger ||
		input.PackageSetDigest.IsZero() || input.RollbackHeadroomBytes == 0 ||
		input.AcquisitionSafetyBytes == 0 || input.SubordinateIDCount < 65536 ||
		input.ServiceID != "docker.service" || input.ServiceUnitDigest.IsZero() ||
		!validLinuxExecutableAuthority(input) ||
		input.RootlessToolPath != "/usr/bin/dockerd-rootless-setuptool.sh" || input.RootlessToolDigest.IsZero() ||
		input.ProbeContractVersion != "1" || input.CapabilityPolicyDigest.IsZero() ||
		!validLinuxProbeImage(input.ProbeImage, input.ProbeImageDigest) {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	repository, err := newLinuxRepository(input.Repository, input.Codename, input.PackageManager, true)
	if err != nil || !repositoryMatchesManager(repository, input.PackageManager) ||
		!repositoryArtifactsAuthorized(repository.verification, artifact) {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	verificationRepositories, err := newLinuxVerificationRepositories(
		input.VerificationRepositories, input.Codename, input.PackageManager, repository, artifact,
	)
	if err != nil {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	repositories := make(map[string]LinuxRepository, len(verificationRepositories)+1)
	repositories[repository.id] = repository
	for _, verificationRepository := range verificationRepositories {
		repositories[verificationRepository.id] = verificationRepository
	}
	packages, err := newLinuxPackages(input.PackageManager, input.Packages, artifact, repositories, repository.id)
	reserved, reserveOverflow := checkedLinuxBytes(
		artifact.downloadBytes, input.RollbackHeadroomBytes, input.AcquisitionSafetyBytes,
	)
	trustBytes, trustOverflow := linuxRepositorySetDownloadBytes(repository, verificationRepositories)
	packageAndTrustBytes, packageAndTrustOverflow := checkedLinuxBytes(packageDownloadBytes(packages), trustBytes)
	if err != nil || !LinuxPackageSetDigest(input.Packages).Equal(input.PackageSetDigest) ||
		!input.PackageSetDigest.Equal(artifact.sha256) || trustOverflow || packageAndTrustOverflow ||
		packageAndTrustBytes != artifact.downloadBytes ||
		reserveOverflow || reserved != artifact.reserveBytes {
		return LinuxExecutionPolicy{}, ErrManifestIntegrity
	}
	return LinuxExecutionPolicy{
		packageManager: input.PackageManager, packageManagerVersion: input.PackageManagerVersion,
		codename: input.Codename, minimumKernel: input.MinimumKernel,
		minimumAvailableMemory: input.MinimumAvailableMemory, repository: repository,
		verificationRepositories: verificationRepositories,
		packages:                 packages, packageSetDigest: input.PackageSetDigest,
		rollbackHeadroomBytes:     input.RollbackHeadroomBytes,
		acquisitionSafetyBytes:    input.AcquisitionSafetyBytes,
		subordinateIDCount:        input.SubordinateIDCount,
		selinuxEnforcingSupported: input.SELinuxEnforcingSupported,
		serviceID:                 input.ServiceID, serviceUnitDigest: input.ServiceUnitDigest,
		dockerCLIPath: input.DockerCLIPath, dockerCLISHA256: input.DockerCLISHA256,
		composePluginPath: input.ComposePluginPath, composePluginSHA256: input.ComposePluginSHA256,
		rpmKeysPath: input.RPMKeysPath, rpmKeysSHA256: input.RPMKeysSHA256,
		rpmKeysPackageVersion:             input.RPMKeysPackageVersion,
		rpmKeysPackageReceiptDigest:       input.RPMKeysPackageReceiptDigest,
		privilegeToolPath:                 input.PrivilegeToolPath,
		privilegeToolSHA256:               input.PrivilegeToolSHA256,
		privilegeToolPackage:              input.PrivilegeToolPackage,
		privilegeToolPackageVersion:       input.PrivilegeToolPackageVersion,
		privilegeToolPackageReceiptDigest: input.PrivilegeToolPackageReceiptDigest,
		rootlessToolPath:                  input.RootlessToolPath, rootlessToolDigest: input.RootlessToolDigest,
		probeImage: input.ProbeImage, probeImageDigest: input.ProbeImageDigest,
		probeContractVersion:   input.ProbeContractVersion,
		capabilityPolicyDigest: input.CapabilityPolicyDigest,
	}, nil
}

func validLinuxExecutableAuthority(input LinuxExecutionPolicyInput) bool {
	if input.DockerCLIPath != "/usr/bin/docker" || input.DockerCLISHA256.IsZero() ||
		input.ComposePluginPath != "/usr/libexec/docker/cli-plugins/docker-compose" ||
		input.ComposePluginSHA256.IsZero() || input.PrivilegeToolPath != "/usr/bin/pkexec" ||
		input.PrivilegeToolSHA256.IsZero() || !validLinuxPackageVersion(input.PrivilegeToolPackageVersion) ||
		input.PrivilegeToolPackageReceiptDigest.IsZero() {
		return false
	}
	if input.PackageManager == LinuxPackageManagerAPT {
		return input.PrivilegeToolPackage == "pkexec" &&
			input.RPMKeysPath == "" && input.RPMKeysSHA256.IsZero() &&
			input.RPMKeysPackageVersion == "" && input.RPMKeysPackageReceiptDigest.IsZero()
	}
	return input.PackageManager == LinuxPackageManagerDNF && input.PrivilegeToolPackage == "polkit" &&
		input.RPMKeysPath == "/usr/bin/rpmkeys" &&
		!input.RPMKeysSHA256.IsZero() && validLinuxPackageVersion(input.RPMKeysPackageVersion) &&
		!input.RPMKeysPackageReceiptDigest.IsZero()
}

func newLinuxVerificationRepositories(
	inputs []LinuxRepositoryInput,
	codename string,
	manager LinuxPackageManager,
	primary LinuxRepository,
	artifact ArtifactPolicy,
) ([]LinuxRepository, error) {
	if len(inputs) != 1 || !sort.SliceIsSorted(inputs, func(left, right int) bool {
		return inputs[left].ID < inputs[right].ID
	}) {
		return nil, ErrManifestIntegrity
	}
	result := make([]LinuxRepository, 0, len(inputs))
	for index, input := range inputs {
		repository, err := newLinuxRepository(input, codename, manager, false)
		if err != nil || repository.id == primary.id ||
			index > 0 && inputs[index-1].ID == input.ID ||
			!verificationRepositoryMatchesManager(repository, manager) ||
			!repositoryArtifactsAuthorized(repository.verification, artifact) {
			return nil, ErrManifestIntegrity
		}
		result = append(result, repository)
	}
	return result, nil
}

func linuxRepositorySetDownloadBytes(
	primary LinuxRepository,
	verification []LinuxRepository,
) (uint64, bool) {
	total := repositoryArtifactDownloadBytes(primary.verification)
	for _, repository := range verification {
		var overflow bool
		total, overflow = checkedLinuxBytes(total, repositoryArtifactDownloadBytes(repository.verification))
		if overflow {
			return 0, true
		}
	}
	return total, false
}

func repositoryArtifactsAuthorized(
	resources []LinuxRepositoryArtifact,
	artifact ArtifactPolicy,
) bool {
	if len(resources) == 0 {
		return false
	}
	for _, resource := range resources {
		if !artifactAuthorizesSource(artifact, resource.source) {
			return false
		}
	}
	return true
}

func checkedLinuxBytes(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if value > maximumSafeJSONInteger || total > maximumSafeJSONInteger-value {
			return 0, true
		}
		total += value
	}
	return total, false
}

func newLinuxPackages(
	manager LinuxPackageManager,
	inputs []LinuxPackageInput,
	artifact ArtifactPolicy,
	repositories map[string]LinuxRepository,
	primaryRepositoryID string,
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
		repository, repositoryPresent := repositories[input.RepositoryID]
		source, sourceError := NewSourceLocation(input.Source)
		if !present || purpose != input.Purpose || !input.Purpose.valid() ||
			!repositoryPresent || !validIdentifier(input.RepositoryID) ||
			(input.Purpose == LinuxPackagePurposeRuntime && input.RepositoryID != primaryRepositoryID) ||
			(input.Purpose == LinuxPackagePurposePrerequisite && input.RepositoryID == primaryRepositoryID) ||
			!validLinuxPackageVersion(input.Version) || input.DownloadBytes == 0 ||
			input.DownloadBytes > maximumSafeJSONInteger || input.SHA256.IsZero() ||
			input.NativeReceiptDigest.IsZero() ||
			!LinuxNativePackageReceiptDigest(manager, input).Equal(input.NativeReceiptDigest) || sourceError != nil ||
			strings.HasSuffix(input.Source.PathPrefix, "/") || !artifactAuthorizesSource(artifact, source) ||
			!repository.url.authorizes(source) ||
			index > 0 && inputs[index-1].Name == input.Name {
			return nil, ErrManifestIntegrity
		}
		delete(wanted, input.Name)
		result = append(result, LinuxPackage{
			name: input.Name, version: input.Version, purpose: input.Purpose, repositoryID: input.RepositoryID,
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

func verificationRepositoryMatchesManager(repository LinuxRepository, manager LinuxPackageManager) bool {
	host := repository.url.Host()
	path := repository.url.PathPrefix()
	if manager == LinuxPackageManagerAPT {
		switch host {
		case "archive.ubuntu.com", "ports.ubuntu.com", "security.ubuntu.com":
			return strings.HasPrefix(path, "/ubuntu/")
		case "deb.debian.org":
			return strings.HasPrefix(path, "/debian/")
		case "security.debian.org":
			return strings.HasPrefix(path, "/debian-security/")
		default:
			return false
		}
	}
	if manager != LinuxPackageManagerDNF {
		return false
	}
	switch host {
	case "download.fedoraproject.org", "dl.fedoraproject.org":
		return strings.HasPrefix(path, "/pub/fedora/linux/")
	case "mirror.stream.centos.org":
		return strings.HasPrefix(path, "/")
	default:
		return false
	}
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
		RepositoryID  string              `json:"repository_id"`
		SHA256        string              `json:"sha256"`
		Source        canonicalSource     `json:"source"`
		Version       string              `json:"version"`
	}
	document := make([]canonicalPackage, 0, len(inputs))
	for _, input := range inputs {
		document = append(document, canonicalPackage{
			DownloadBytes: input.DownloadBytes, Name: input.Name, Purpose: input.Purpose,
			Receipt: input.NativeReceiptDigest.Hex(), RepositoryID: input.RepositoryID, SHA256: input.SHA256.Hex(),
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

func repositoryArtifactDownloadBytes(artifacts []LinuxRepositoryArtifact) uint64 {
	var total uint64
	for _, artifact := range artifacts {
		if total > maximumSafeJSONInteger-artifact.downloadBytes {
			return maximumSafeJSONInteger
		}
		total += artifact.downloadBytes
	}
	return total
}

func linuxExecutionInputZero(input LinuxExecutionPolicyInput) bool {
	return input.PackageManager == "" && input.PackageManagerVersion == "" && input.Codename == "" &&
		input.MinimumKernel == "" && input.MinimumAvailableMemory == 0 && linuxRepositoryInputZero(input.Repository) &&
		len(input.VerificationRepositories) == 0 && len(input.Packages) == 0 &&
		input.PackageSetDigest.IsZero() && input.SubordinateIDCount == 0 &&
		input.RollbackHeadroomBytes == 0 && input.AcquisitionSafetyBytes == 0 &&
		!input.SELinuxEnforcingSupported && input.ServiceID == "" && input.ServiceUnitDigest.IsZero() &&
		input.RootlessToolPath == "" && input.RootlessToolDigest.IsZero() && input.ProbeImage == "" &&
		input.ProbeImageDigest.IsZero() && input.ProbeContractVersion == "" && input.CapabilityPolicyDigest.IsZero()
}

func linuxRepositoryInputZero(input LinuxRepositoryInput) bool {
	return input.ID == "" && input.URL == (OfficialSourceInput{}) && input.Suite == "" && input.Component == "" &&
		input.SigningKeyFingerprint == "" && input.SigningKeyDigest.IsZero() && input.ConfigurationDigest.IsZero() &&
		input.MetadataDigest.IsZero() && len(input.VerificationArtifacts) == 0
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

// VerificationRepositories returns the additional signed repositories needed
// to authenticate distribution-owned prerequisite packages.
func (p LinuxExecutionPolicy) VerificationRepositories() []LinuxRepository {
	return append([]LinuxRepository(nil), p.verificationRepositories...)
}

// Packages returns a defensive copy of the full retained package set.
func (p LinuxExecutionPolicy) Packages() []LinuxPackage {
	return append([]LinuxPackage(nil), p.packages...)
}

// PackageSetDigest returns the aggregate retained-set identity.
func (p LinuxExecutionPolicy) PackageSetDigest() Digest { return p.packageSetDigest }

// RollbackHeadroomBytes returns acquisition capacity retained for recovery.
func (p LinuxExecutionPolicy) RollbackHeadroomBytes() uint64 { return p.rollbackHeadroomBytes }

// AcquisitionSafetyBytes returns the post-download free-space safety floor.
func (p LinuxExecutionPolicy) AcquisitionSafetyBytes() uint64 { return p.acquisitionSafetyBytes }

// SubordinateIDCount returns the required rootless UID/GID allocation.
func (p LinuxExecutionPolicy) SubordinateIDCount() uint32 { return p.subordinateIDCount }

// SELinuxEnforcingSupported reports signed enforcing-mode support.
func (p LinuxExecutionPolicy) SELinuxEnforcingSupported() bool { return p.selinuxEnforcingSupported }

// ServiceID returns the only authorized per-user service.
func (p LinuxExecutionPolicy) ServiceID() string { return p.serviceID }

// ServiceUnitDigest returns the expected packaged user-unit digest.
func (p LinuxExecutionPolicy) ServiceUnitDigest() Digest { return p.serviceUnitDigest }

// DockerCLIPath returns the fixed package-owned Docker client path.
func (p LinuxExecutionPolicy) DockerCLIPath() string { return p.dockerCLIPath }

// DockerCLISHA256 returns the exact installed Docker client byte digest.
func (p LinuxExecutionPolicy) DockerCLISHA256() Digest { return p.dockerCLISHA256 }

// ComposePluginPath returns the fixed package-owned Compose plugin path.
func (p LinuxExecutionPolicy) ComposePluginPath() string { return p.composePluginPath }

// ComposePluginSHA256 returns the exact installed Compose plugin byte digest.
func (p LinuxExecutionPolicy) ComposePluginSHA256() Digest { return p.composePluginSHA256 }

// RPMKeysPath returns the DNF cell's fixed RPM signature verifier path.
func (p LinuxExecutionPolicy) RPMKeysPath() string { return p.rpmKeysPath }

// RPMKeysSHA256 returns the DNF cell's exact RPM verifier byte digest.
func (p LinuxExecutionPolicy) RPMKeysSHA256() Digest { return p.rpmKeysSHA256 }

// RPMKeysPackageVersion returns the exact installed distribution RPM package version.
func (p LinuxExecutionPolicy) RPMKeysPackageVersion() string { return p.rpmKeysPackageVersion }

// RPMKeysPackageReceiptDigest returns the signed native package receipt binding for rpmkeys.
func (p LinuxExecutionPolicy) RPMKeysPackageReceiptDigest() Digest {
	return p.rpmKeysPackageReceiptDigest
}

// PrivilegeToolPath returns the fixed native Polkit execution path.
func (p LinuxExecutionPolicy) PrivilegeToolPath() string { return p.privilegeToolPath }

// PrivilegeToolSHA256 returns the exact installed pkexec byte digest.
func (p LinuxExecutionPolicy) PrivilegeToolSHA256() Digest { return p.privilegeToolSHA256 }

// PrivilegeToolPackage returns the distribution package that owns pkexec.
func (p LinuxExecutionPolicy) PrivilegeToolPackage() string { return p.privilegeToolPackage }

// PrivilegeToolPackageVersion returns the exact installed native package version.
func (p LinuxExecutionPolicy) PrivilegeToolPackageVersion() string {
	return p.privilegeToolPackageVersion
}

// PrivilegeToolPackageReceiptDigest returns the signed package receipt binding for pkexec.
func (p LinuxExecutionPolicy) PrivilegeToolPackageReceiptDigest() Digest {
	return p.privilegeToolPackageReceiptDigest
}

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
			Name: pkg.name, Version: pkg.version, Purpose: pkg.purpose, RepositoryID: pkg.repositoryID,
			DownloadBytes: pkg.downloadBytes, SHA256: pkg.sha256,
			NativeReceiptDigest: pkg.nativeReceiptDigest,
			Source:              OfficialSourceInput{Scheme: pkg.source.scheme, Host: pkg.source.host, PathPrefix: pkg.source.pathPrefix},
		})
	}
	verificationRepositories := make([]LinuxRepositoryInput, 0, len(p.verificationRepositories))
	for _, repository := range p.verificationRepositories {
		verificationInputs := make([]LinuxRepositoryArtifactInput, 0, len(repository.verification))
		for _, resource := range repository.verification {
			verificationInputs = append(verificationInputs, LinuxRepositoryArtifactInput{
				Role: resource.role, DownloadBytes: resource.downloadBytes, SHA256: resource.sha256,
				Source: OfficialSourceInput{
					Scheme: resource.source.scheme, Host: resource.source.host, PathPrefix: resource.source.pathPrefix,
				},
			})
		}
		verificationRepositories = append(verificationRepositories, LinuxRepositoryInput{
			ID: repository.id,
			URL: OfficialSourceInput{
				Scheme: repository.url.scheme, Host: repository.url.host, PathPrefix: repository.url.pathPrefix,
			},
			Suite: repository.suite, Component: repository.component,
			SigningKeyFingerprint: repository.signingKeyFingerprint,
			SigningKeyDigest:      repository.signingKeyDigest, ConfigurationDigest: repository.configurationDigest,
			MetadataAuthentication: repository.metadataAuthentication,
			MetadataDigest:         repository.metadataDigest, VerificationArtifacts: verificationInputs,
		})
	}
	verification := make([]LinuxRepositoryArtifactInput, 0, len(p.repository.verification))
	for _, resource := range p.repository.verification {
		verification = append(verification, LinuxRepositoryArtifactInput{
			Role: resource.role, DownloadBytes: resource.downloadBytes, SHA256: resource.sha256,
			Source: OfficialSourceInput{
				Scheme: resource.source.scheme, Host: resource.source.host, PathPrefix: resource.source.pathPrefix,
			},
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
			SigningKeyFingerprint:  p.repository.signingKeyFingerprint,
			SigningKeyDigest:       p.repository.signingKeyDigest,
			ConfigurationDigest:    p.repository.configurationDigest,
			MetadataAuthentication: p.repository.metadataAuthentication,
			MetadataDigest:         p.repository.metadataDigest,
			VerificationArtifacts:  verification,
		},
		VerificationRepositories: verificationRepositories,
		Packages:                 inputs, PackageSetDigest: p.packageSetDigest,
		RollbackHeadroomBytes:     p.rollbackHeadroomBytes,
		AcquisitionSafetyBytes:    p.acquisitionSafetyBytes,
		SubordinateIDCount:        p.subordinateIDCount,
		SELinuxEnforcingSupported: p.selinuxEnforcingSupported,
		ServiceID:                 p.serviceID, ServiceUnitDigest: p.serviceUnitDigest,
		DockerCLIPath: p.dockerCLIPath, DockerCLISHA256: p.dockerCLISHA256,
		ComposePluginPath: p.composePluginPath, ComposePluginSHA256: p.composePluginSHA256,
		RPMKeysPath: p.rpmKeysPath, RPMKeysSHA256: p.rpmKeysSHA256,
		RPMKeysPackageVersion:             p.rpmKeysPackageVersion,
		RPMKeysPackageReceiptDigest:       p.rpmKeysPackageReceiptDigest,
		PrivilegeToolPath:                 p.privilegeToolPath,
		PrivilegeToolSHA256:               p.privilegeToolSHA256,
		PrivilegeToolPackage:              p.privilegeToolPackage,
		PrivilegeToolPackageVersion:       p.privilegeToolPackageVersion,
		PrivilegeToolPackageReceiptDigest: p.privilegeToolPackageReceiptDigest,
		RootlessToolPath:                  p.rootlessToolPath, RootlessToolDigest: p.rootlessToolDigest,
		ProbeImage: p.probeImage, ProbeImageDigest: p.probeImageDigest,
		ProbeContractVersion:   p.probeContractVersion,
		CapabilityPolicyDigest: p.capabilityPolicyDigest,
	}, artifact)
	return err == nil && len(validated.packages) == len(p.packages) &&
		len(validated.verificationRepositories) == len(p.verificationRepositories)
}
