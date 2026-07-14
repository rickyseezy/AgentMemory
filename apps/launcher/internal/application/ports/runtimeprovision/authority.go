// Package runtimeprovision defines the closed execution authority and helper
// boundaries used by platform runtime-provisioning adapters.
package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	maximumAuthorityBytes = 64 * 1024
	minimumSubordinateIDs = uint32(65536)
	maximumSafeJSONInt    = uint64(1<<53 - 1)
)

var (
	// ErrAuthorityUnavailable means no authenticated signed Linux execution
	// projection exists for the canonical PF-006 plan.
	ErrAuthorityUnavailable = errors.New("authenticated Linux runtime execution authority is unavailable")
	// ErrAuthorityInvalid rejects incomplete, mutable, or cross-plan authority.
	ErrAuthorityInvalid = errors.New("linux runtime execution authority is invalid")
)

// PackageManager is the closed package transaction backend certified by a
// signed Linux platform cell.
type PackageManager string

const (
	// PackageManagerAPT identifies a Debian-family apt transaction.
	PackageManagerAPT PackageManager = "apt"
	// PackageManagerDNF identifies an RPM-family dnf transaction.
	PackageManagerDNF PackageManager = "dnf"
)

func (m PackageManager) valid() bool { return m == PackageManagerAPT || m == PackageManagerDNF }

// PackagePurpose prevents a prerequisite package from being substituted for
// a Docker runtime component, even when its native name happens to match.
type PackagePurpose string

const (
	// PackagePurposePrerequisite supplies newuidmap/newgidmap.
	PackagePurposePrerequisite PackagePurpose = "rootless_prerequisite"
	// PackagePurposeRuntime is one of the six mandatory Docker packages.
	PackagePurposeRuntime PackagePurpose = "runtime_component"
)

func (p PackagePurpose) valid() bool {
	return p == PackagePurposePrerequisite || p == PackagePurposeRuntime
}

// PackageInput is populated from a decoded, signature-verified Linux runtime
// plan. Version is the complete native package version, including epoch and
// distribution suffix; a Docker semantic version is not sufficient.
type PackageInput struct {
	Name                string
	Version             string
	Purpose             PackagePurpose
	RepositoryID        string
	NativeReceiptDigest runtimeinstall.Hash
}

// Package is an immutable exact native-package receipt expectation.
type Package struct {
	name         string
	version      string
	purpose      PackagePurpose
	repositoryID string
	receipt      runtimeinstall.Hash
}

// Name returns the signed native package identity.
func (p Package) Name() string { return p.name }

// Version returns the complete immutable native version.
func (p Package) Version() string { return p.version }

// Purpose returns the package's closed semantic role.
func (p Package) Purpose() PackagePurpose { return p.purpose }

// RepositoryID returns the signed repository that authenticated this package.
func (p Package) RepositoryID() string { return p.repositoryID }

// NativeReceiptDigest returns the expected package-manager publisher receipt.
func (p Package) NativeReceiptDigest() runtimeinstall.Hash { return p.receipt }

// RepositoryInput declares the exact official stable repository and all
// security-relevant state digests written or consumed by the helper.
type RepositoryInput struct {
	ID                    string
	URL                   string
	Suite                 string
	Component             string
	SigningKeyFingerprint string
	SigningKeyDigest      runtimeinstall.Hash
	ConfigurationDigest   runtimeinstall.Hash
	MetadataDigest        runtimeinstall.Hash
}

// Repository is immutable official Docker repository authority.
type Repository struct {
	id                  string
	url                 string
	suite               string
	component           string
	keyFingerprint      string
	keyDigest           runtimeinstall.Hash
	configurationDigest runtimeinstall.Hash
	metadataDigest      runtimeinstall.Hash
}

// ID returns the signed repository identity.
func (r Repository) ID() string { return r.id }

// URL returns the exact HTTPS Docker repository base URL.
func (r Repository) URL() string { return r.url }

// Suite returns the exact distribution suite/codename.
func (r Repository) Suite() string { return r.suite }

// Component returns the repository component, always stable for schema v1.
func (r Repository) Component() string { return r.component }

// SigningKeyFingerprint returns the exact uppercase native key fingerprint.
func (r Repository) SigningKeyFingerprint() string { return r.keyFingerprint }

// SigningKeyDigest returns the exact key artifact digest.
func (r Repository) SigningKeyDigest() runtimeinstall.Hash { return r.keyDigest }

// ConfigurationDigest returns the expected repository configuration bytes.
func (r Repository) ConfigurationDigest() runtimeinstall.Hash { return r.configurationDigest }

// MetadataDigest returns the signed repository-metadata snapshot binding.
func (r Repository) MetadataDigest() runtimeinstall.Hash { return r.metadataDigest }

// LinuxAuthorityInput contains only fields decoded from a signed Linux
// execution projection. AuthorityResolver, not an inbound caller, owns this
// construction input in production.
type LinuxAuthorityInput struct {
	PlanDigest             runtimeinstall.Hash
	CatalogDigest          runtimeinstall.Hash
	TermsDigest            runtimeinstall.Hash
	TermsID                string
	TermsVersion           string
	TermsURL               string
	TermsPresentation      string
	ArtifactDigest         runtimeinstall.Hash
	SigningKeyID           string
	Architecture           runtimeinstall.Architecture
	Distribution           string
	VersionID              string
	Codename               string
	MinimumKernel          string
	MinimumCPUs            uint16
	MinimumTotalMemory     uint64
	MinimumAvailableMemory uint64
	MinimumFreeDisk        uint64
	PackageManager         PackageManager
	PackageManagerVersion  string
	Repository             RepositoryInput
	Packages               []PackageInput
	RuntimeVersion         string
	ComposeVersion         string
	UnrelatedWorkloads     uint32
	InvokingUID            uint32
	InvokingGID            uint32
	AccountName            string
	PrincipalID            string
	MachineDigest          runtimeinstall.Hash
	HomeDirectory          string
	RuntimeDirectory       string
	Endpoint               string
	SubordinateIDCount     uint32
	SELinuxEnforcing       bool
	ServiceID              string
	ServiceUnitDigest      runtimeinstall.Hash
	RootlessToolPath       string
	RootlessToolDigest     runtimeinstall.Hash
	ProbeImage             string
	ProbeImageDigest       runtimeinstall.Hash
	ProbeContractVersion   string
	CapabilityPolicyDigest runtimeinstall.Hash
}

// LinuxAuthority is the immutable, digest-bound execution projection. Its
// digest is evidence identity, not a signature; AuthorityResolver must verify
// the signed envelope before returning it.
type LinuxAuthority struct {
	input      LinuxAuthorityInput
	repository Repository
	packages   []Package
	digest     runtimeinstall.Hash
}

// NewLinuxAuthority validates and copies one already authenticated projection.
func NewLinuxAuthority(input LinuxAuthorityInput) (LinuxAuthority, error) {
	repository, err := newRepository(input.Repository, input.Distribution, input.Codename)
	if err != nil || !validLinuxAuthorityScalar(input) {
		return LinuxAuthority{}, ErrAuthorityInvalid
	}
	packages, err := newPackages(input.PackageManager, input.Packages)
	if err != nil {
		return LinuxAuthority{}, ErrAuthorityInvalid
	}
	input.Packages = append([]PackageInput(nil), input.Packages...)
	authority := LinuxAuthority{input: input, repository: repository, packages: packages}
	canonical, err := authority.canonicalBytes()
	if err != nil || len(canonical) == 0 || len(canonical) > maximumAuthorityBytes {
		return LinuxAuthority{}, ErrAuthorityInvalid
	}
	authority.digest = runtimeinstall.Sum(canonical)
	return authority, nil
}

func validLinuxAuthorityScalar(input LinuxAuthorityInput) bool {
	if input.PlanDigest.IsZero() || input.CatalogDigest.IsZero() || input.TermsDigest.IsZero() ||
		!validLinuxTerms(input) ||
		input.ArtifactDigest.IsZero() ||
		!validIdentity(input.SigningKeyID) || input.Architecture != runtimeinstall.ArchitectureAMD64 &&
		input.Architecture != runtimeinstall.ArchitectureARM64 || !validDistribution(input.Distribution) ||
		!validVersion(input.VersionID) || !validIdentity(input.Codename) || !validVersion(input.MinimumKernel) ||
		input.MinimumCPUs == 0 || input.MinimumTotalMemory == 0 || input.MinimumAvailableMemory == 0 ||
		input.MinimumAvailableMemory > input.MinimumTotalMemory || input.MinimumFreeDisk == 0 ||
		input.MinimumTotalMemory > maximumSafeJSONInt || input.MinimumAvailableMemory > maximumSafeJSONInt ||
		input.MinimumFreeDisk > maximumSafeJSONInt ||
		!input.PackageManager.valid() || !validManagerDistribution(input.PackageManager, input.Distribution) ||
		!validPackageVersion(input.PackageManagerVersion) ||
		!validPackageVersion(input.RuntimeVersion) || !validPackageVersion(input.ComposeVersion) || input.InvokingUID == 0 ||
		input.InvokingGID == 0 || input.PrincipalID != "linux:uid:"+strconv.FormatUint(uint64(input.InvokingUID), 10) ||
		!validAccountName(input.AccountName) ||
		input.MachineDigest.IsZero() || !safeAbsolutePath(input.HomeDirectory) ||
		input.RuntimeDirectory != "/run/user/"+strconv.FormatUint(uint64(input.InvokingUID), 10) ||
		input.Endpoint != "unix://"+input.RuntimeDirectory+"/docker.sock" ||
		input.SubordinateIDCount < minimumSubordinateIDs || !validIdentity(input.ServiceID) ||
		input.ServiceID != "docker.service" || input.ServiceUnitDigest.IsZero() ||
		input.RootlessToolPath != "/usr/bin/dockerd-rootless-setuptool.sh" ||
		input.RootlessToolDigest.IsZero() || !validProbeImage(input.ProbeImage, input.ProbeImageDigest) ||
		input.ProbeContractVersion != "1" || input.CapabilityPolicyDigest.IsZero() {
		return false
	}
	return !strings.HasPrefix(input.HomeDirectory, "/tmp/") && input.HomeDirectory != "/tmp" &&
		input.HomeDirectory != input.RuntimeDirectory
}

func validLinuxTerms(input LinuxAuthorityInput) bool {
	if input.TermsID != runtimeinstall.DockerEngineTermsID || !validPackageVersion(input.TermsVersion) ||
		input.TermsPresentation != "agentmemory" {
		return false
	}
	return input.TermsURL == "https://docs.docker.com/engine/"
}

func newRepository(input RepositoryInput, distribution string, codename string) (Repository, error) {
	wantedURL := "https://download.docker.com/linux/" + distribution
	if input.URL != wantedURL && input.URL != wantedURL+"/" ||
		!validIdentity(input.ID) || !validIdentity(input.Suite) || input.Suite != codename ||
		input.Component != "stable" || !validFingerprint(input.SigningKeyFingerprint) ||
		input.SigningKeyDigest.IsZero() || input.ConfigurationDigest.IsZero() || input.MetadataDigest.IsZero() {
		return Repository{}, ErrAuthorityInvalid
	}
	return Repository{
		id: input.ID, url: input.URL, suite: input.Suite, component: input.Component,
		keyFingerprint: input.SigningKeyFingerprint, keyDigest: input.SigningKeyDigest,
		configurationDigest: input.ConfigurationDigest, metadataDigest: input.MetadataDigest,
	}, nil
}

func validManagerDistribution(manager PackageManager, distribution string) bool {
	return manager == PackageManagerAPT && (distribution == "ubuntu" || distribution == "debian") ||
		manager == PackageManagerDNF && (distribution == "fedora" || distribution == "centos")
}

func newPackages(manager PackageManager, inputs []PackageInput) ([]Package, error) {
	if len(inputs) != 7 || !slices.IsSortedFunc(inputs, func(left, right PackageInput) int {
		return strings.Compare(left.Name, right.Name)
	}) {
		return nil, ErrAuthorityInvalid
	}
	wanted := map[string]PackagePurpose{
		"containerd.io": PackagePurposeRuntime, "docker-buildx-plugin": PackagePurposeRuntime,
		"docker-ce": PackagePurposeRuntime, "docker-ce-cli": PackagePurposeRuntime,
		"docker-ce-rootless-extras": PackagePurposeRuntime, "docker-compose-plugin": PackagePurposeRuntime,
	}
	if manager == PackageManagerAPT {
		wanted["uidmap"] = PackagePurposePrerequisite
	} else {
		wanted["shadow-utils"] = PackagePurposePrerequisite
	}
	packages := make([]Package, 0, len(inputs))
	for index, input := range inputs {
		purpose, present := wanted[input.Name]
		if !present || input.Purpose != purpose || !input.Purpose.valid() || !validIdentity(input.RepositoryID) ||
			!validPackageVersion(input.Version) ||
			input.NativeReceiptDigest.IsZero() || index > 0 && inputs[index-1].Name == input.Name {
			return nil, ErrAuthorityInvalid
		}
		delete(wanted, input.Name)
		packages = append(packages, Package{
			name: input.Name, version: input.Version, purpose: input.Purpose, repositoryID: input.RepositoryID,
			receipt: input.NativeReceiptDigest,
		})
	}
	if len(wanted) != 0 {
		return nil, ErrAuthorityInvalid
	}
	return packages, nil
}

func validPackageVersion(value string) bool {
	if !validVersion(value) || strings.ContainsAny(value, "*?[]{}$`\\/=") {
		return false
	}
	lower := strings.ToLower(value)
	return lower != "latest" && !strings.Contains(lower, "latest")
}

func validProbeImage(value string, digest runtimeinstall.Hash) bool {
	if digest.IsZero() || len(value) > 512 || strings.Count(value, "@sha256:") != 1 ||
		strings.ContainsAny(value, "\x00\r\n *?$`\\") {
		return false
	}
	name, encoded, present := strings.Cut(value, "@sha256:")
	if !present || name == "" || strings.Contains(name, "..") || strings.Contains(name, "//") ||
		encoded != digest.String() {
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

func validVersion(value string) bool {
	if value == "" || len(value) > 128 || value != strings.TrimSpace(value) {
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

func validDistribution(value string) bool {
	return value == "ubuntu" || value == "debian" || value == "fedora" || value == "centos"
}

func validAccountName(value string) bool {
	if value == "" || len(value) > 32 || value[0] == '-' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 256 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:+@/-", character) {
			continue
		}
		return false
	}
	return true
}

func validFingerprint(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'A' || character > 'F' {
				return false
			}
		}
	}
	return true
}

func safeAbsolutePath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, "\x00\r\n") || len(value) > 4096 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (a LinuxAuthority) canonicalBytes() ([]byte, error) {
	type canonicalPackage struct {
		Name       string `json:"name"`
		Purpose    string `json:"purpose"`
		Receipt    string `json:"receipt_digest"`
		Repository string `json:"repository_id"`
		Version    string `json:"version"`
	}
	packages := make([]canonicalPackage, 0, len(a.packages))
	for _, pkg := range a.packages {
		packages = append(packages, canonicalPackage{
			Name: pkg.name, Purpose: string(pkg.purpose), Receipt: pkg.receipt.String(),
			Repository: pkg.repositoryID, Version: pkg.version,
		})
	}
	document := struct {
		Architecture string             `json:"architecture"`
		AccountName  string             `json:"account_name"`
		Artifact     string             `json:"artifact_digest"`
		Capability   string             `json:"capability_policy_digest"`
		Catalog      string             `json:"catalog_digest"`
		Codename     string             `json:"codename"`
		Compose      string             `json:"compose_version"`
		Distribution string             `json:"distribution"`
		Endpoint     string             `json:"endpoint"`
		GID          uint32             `json:"gid"`
		Home         string             `json:"home"`
		Kernel       string             `json:"minimum_kernel"`
		Machine      string             `json:"machine_digest"`
		Manager      string             `json:"package_manager"`
		ManagerVer   string             `json:"package_manager_version"`
		MinimumCPUs  uint16             `json:"minimum_cpus"`
		MinimumDisk  uint64             `json:"minimum_free_disk"`
		MinimumFree  uint64             `json:"minimum_available_memory"`
		MinimumTotal uint64             `json:"minimum_total_memory"`
		Packages     []canonicalPackage `json:"packages"`
		Plan         string             `json:"plan_digest"`
		Principal    string             `json:"principal"`
		Repository   RepositoryInput    `json:"repository"`
		RootlessPath string             `json:"rootless_tool_path"`
		RootlessSHA  string             `json:"rootless_tool_digest"`
		ProbeImage   string             `json:"probe_image"`
		ProbeSHA     string             `json:"probe_image_digest"`
		ProbeVersion string             `json:"probe_contract_version"`
		Runtime      string             `json:"runtime_version"`
		RuntimeDir   string             `json:"runtime_directory"`
		SELinux      bool               `json:"selinux_enforcing_supported"`
		Service      string             `json:"service_id"`
		ServiceSHA   string             `json:"service_unit_digest"`
		SigningKey   string             `json:"signing_key_id"`
		SubIDs       uint32             `json:"subordinate_id_count"`
		Terms        string             `json:"terms_digest"`
		TermsID      string             `json:"terms_id"`
		TermsMode    string             `json:"terms_presentation"`
		TermsURL     string             `json:"terms_url"`
		TermsVersion string             `json:"terms_version"`
		UID          uint32             `json:"uid"`
		Workloads    uint32             `json:"unrelated_workloads"`
		Version      string             `json:"version_id"`
	}{
		Architecture: a.input.Architecture.String(), AccountName: a.input.AccountName,
		Artifact:   a.input.ArtifactDigest.String(),
		Capability: a.input.CapabilityPolicyDigest.String(), Catalog: a.input.CatalogDigest.String(),
		Codename: a.input.Codename, Compose: a.input.ComposeVersion, Distribution: a.input.Distribution,
		Endpoint: a.input.Endpoint, GID: a.input.InvokingGID, Home: a.input.HomeDirectory,
		Kernel: a.input.MinimumKernel, Machine: a.input.MachineDigest.String(), Manager: string(a.input.PackageManager),
		ManagerVer: a.input.PackageManagerVersion, MinimumCPUs: a.input.MinimumCPUs,
		MinimumDisk: a.input.MinimumFreeDisk, MinimumFree: a.input.MinimumAvailableMemory,
		MinimumTotal: a.input.MinimumTotalMemory, Packages: packages, Plan: a.input.PlanDigest.String(),
		Principal: a.input.PrincipalID, Repository: a.input.Repository, RootlessPath: a.input.RootlessToolPath,
		RootlessSHA: a.input.RootlessToolDigest.String(), ProbeImage: a.input.ProbeImage,
		ProbeSHA: a.input.ProbeImageDigest.String(), ProbeVersion: a.input.ProbeContractVersion,
		Runtime:    a.input.RuntimeVersion,
		RuntimeDir: a.input.RuntimeDirectory, SELinux: a.input.SELinuxEnforcing,
		Service: a.input.ServiceID, ServiceSHA: a.input.ServiceUnitDigest.String(),
		SigningKey: a.input.SigningKeyID, SubIDs: a.input.SubordinateIDCount,
		Terms: a.input.TermsDigest.String(), TermsID: a.input.TermsID,
		TermsMode: a.input.TermsPresentation, TermsURL: a.input.TermsURL,
		TermsVersion: a.input.TermsVersion, UID: a.input.InvokingUID,
		Version: a.input.VersionID, Workloads: a.input.UnrelatedWorkloads,
	}
	return json.Marshal(document)
}

// Valid reports whether every copied field still reconstructs the authority.
func (a LinuxAuthority) Valid() bool {
	rebuilt, err := NewLinuxAuthority(a.input)
	return err == nil && rebuilt.digest == a.digest && slices.Equal(rebuilt.packages, a.packages)
}

// ValidFor binds this projection to a decoded canonical PF-006 plan.
func (a LinuxAuthority) ValidFor(plan runtimeinstall.Plan) bool {
	return a.Valid() && len(plan.CanonicalBytes()) != 0 && plan.Digest() == a.input.PlanDigest &&
		plan.CatalogDigest() == a.input.CatalogDigest && plan.TermsDigest() == a.input.TermsDigest
}

// Digest returns the complete Linux execution-authority binding.
func (a LinuxAuthority) Digest() runtimeinstall.Hash { return a.digest }

// PlanDigest returns the canonical PF-006 plan binding.
func (a LinuxAuthority) PlanDigest() runtimeinstall.Hash { return a.input.PlanDigest }

// CatalogDigest returns the verified runtime-catalog binding.
func (a LinuxAuthority) CatalogDigest() runtimeinstall.Hash { return a.input.CatalogDigest }

// TermsDigest returns the exact third-party terms binding that must be shown
// and accepted before a certified Linux runtime mutation.
func (a LinuxAuthority) TermsDigest() runtimeinstall.Hash { return a.input.TermsDigest }

// TermsID returns the exact vendor agreement identity shown to the user.
func (a LinuxAuthority) TermsID() string { return a.input.TermsID }

// TermsVersion returns the exact vendor agreement version.
func (a LinuxAuthority) TermsVersion() string { return a.input.TermsVersion }

// TermsURL returns the exact official HTTPS agreement location.
func (a LinuxAuthority) TermsURL() string { return a.input.TermsURL }

// TermsPresentation returns the signed visible-prompt policy.
func (a LinuxAuthority) TermsPresentation() string { return a.input.TermsPresentation }

// ArtifactDigest returns the publisher-verified runtime artifact binding.
func (a LinuxAuthority) ArtifactDigest() runtimeinstall.Hash { return a.input.ArtifactDigest }

// Architecture returns the only certified CPU architecture.
func (a LinuxAuthority) Architecture() runtimeinstall.Architecture { return a.input.Architecture }

// Distribution returns the exact certified os-release ID.
func (a LinuxAuthority) Distribution() string { return a.input.Distribution }

// VersionID returns the exact certified os-release VERSION_ID.
func (a LinuxAuthority) VersionID() string { return a.input.VersionID }

// Codename returns the exact repository suite/codename.
func (a LinuxAuthority) Codename() string { return a.input.Codename }

// MinimumKernel returns the signed kernel floor.
func (a LinuxAuthority) MinimumKernel() string { return a.input.MinimumKernel }

// MinimumCPUs returns the exact signed CPU floor.
func (a LinuxAuthority) MinimumCPUs() uint16 { return a.input.MinimumCPUs }

// MinimumTotalMemory returns the exact signed total-memory floor.
func (a LinuxAuthority) MinimumTotalMemory() uint64 { return a.input.MinimumTotalMemory }

// MinimumAvailableMemory returns the exact signed available-memory floor.
func (a LinuxAuthority) MinimumAvailableMemory() uint64 { return a.input.MinimumAvailableMemory }

// MinimumFreeDisk returns the exact signed rootless data-volume floor.
func (a LinuxAuthority) MinimumFreeDisk() uint64 { return a.input.MinimumFreeDisk }

// PackageManager returns the exact typed package backend.
func (a LinuxAuthority) PackageManager() PackageManager { return a.input.PackageManager }

// PackageManagerVersion returns the exact supported backend version.
func (a LinuxAuthority) PackageManagerVersion() string { return a.input.PackageManagerVersion }

// Repository returns immutable official repository authority.
func (a LinuxAuthority) Repository() Repository { return a.repository }

// Packages returns a defensive copy of every exact package receipt.
func (a LinuxAuthority) Packages() []Package { return append([]Package(nil), a.packages...) }

// RuntimeVersion returns the expected Docker Engine API product version.
func (a LinuxAuthority) RuntimeVersion() string { return a.input.RuntimeVersion }

// ComposeVersion returns the expected direct Compose plugin version.
func (a LinuxAuthority) ComposeVersion() string { return a.input.ComposeVersion }

// UnrelatedWorkloads returns the exact signed discovery inventory count.
func (a LinuxAuthority) UnrelatedWorkloads() uint32 { return a.input.UnrelatedWorkloads }

// InvokingUID returns the exact non-root user identity.
func (a LinuxAuthority) InvokingUID() uint32 { return a.input.InvokingUID }

// InvokingGID returns the exact invoking user's primary group.
func (a LinuxAuthority) InvokingGID() uint32 { return a.input.InvokingGID }

// AccountName returns the exact NSS account identity bound by the signed plan.
func (a LinuxAuthority) AccountName() string { return a.input.AccountName }

// PrincipalID returns the canonical non-secret principal identifier.
func (a LinuxAuthority) PrincipalID() string { return a.input.PrincipalID }

// MachineDigest returns the signed machine binding.
func (a LinuxAuthority) MachineDigest() runtimeinstall.Hash { return a.input.MachineDigest }

// HomeDirectory returns the exact invoking-user home.
func (a LinuxAuthority) HomeDirectory() string { return a.input.HomeDirectory }

// RuntimeDirectory returns the exact owner-only systemd runtime directory.
func (a LinuxAuthority) RuntimeDirectory() string { return a.input.RuntimeDirectory }

// Endpoint returns the exact local rootless Unix endpoint.
func (a LinuxAuthority) Endpoint() string { return a.input.Endpoint }

// SubordinateIDCount returns the exact minimum UID/GID allocation.
func (a LinuxAuthority) SubordinateIDCount() uint32 { return a.input.SubordinateIDCount }

// SELinuxEnforcingSupported reports signed support for enforcing mode.
func (a LinuxAuthority) SELinuxEnforcingSupported() bool { return a.input.SELinuxEnforcing }

// ServiceID returns the only authorized user service.
func (a LinuxAuthority) ServiceID() string { return a.input.ServiceID }

// ServiceUnitDigest returns the exact expected user unit bytes.
func (a LinuxAuthority) ServiceUnitDigest() runtimeinstall.Hash { return a.input.ServiceUnitDigest }

// RootlessToolPath returns the packaged setup tool's fixed path.
func (a LinuxAuthority) RootlessToolPath() string { return a.input.RootlessToolPath }

// RootlessToolDigest returns the exact setup tool package receipt binding.
func (a LinuxAuthority) RootlessToolDigest() runtimeinstall.Hash { return a.input.RootlessToolDigest }

// ProbeImage returns the exact immutable OCI digest reference for the signed
// AgentMemory runtime-probe contract.
func (a LinuxAuthority) ProbeImage() string { return a.input.ProbeImage }

// ProbeImageDigest returns the exact OCI manifest digest.
func (a LinuxAuthority) ProbeImageDigest() runtimeinstall.Hash { return a.input.ProbeImageDigest }

// ProbeContractVersion returns the only understood probe entrypoint contract.
func (a LinuxAuthority) ProbeContractVersion() string { return a.input.ProbeContractVersion }

// CapabilityPolicyDigest binds every required active runtime probe.
func (a LinuxAuthority) CapabilityPolicyDigest() runtimeinstall.Hash {
	return a.input.CapabilityPolicyDigest
}

// AuthorityResolver verifies the external signed Linux execution projection,
// including its detached signature/release binding, before returning authority.
// Implementations must never synthesize missing package versions or digests.
type AuthorityResolver interface {
	ResolveLinuxAuthority(context.Context, []byte) (LinuxAuthority, error)
}

// AuthorityDigestBytes is a convenience for binding independently verified
// helper state without exposing canonical authority JSON.
func AuthorityDigestBytes(value []byte) runtimeinstall.Hash { return sha256.Sum256(value) }
