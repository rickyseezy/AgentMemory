package runtimeprovision

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

var (
	// ErrDesktopAuthorityUnavailable means no verified release projection exists
	// for the exact host, principal, artifact, and runtime plan.
	ErrDesktopAuthorityUnavailable = errors.New("signed desktop runtime authority is unavailable")
	// ErrDesktopAuthorityIntegrity rejects incomplete, widened, or contradictory
	// desktop execution authority.
	ErrDesktopAuthorityIntegrity = errors.New("desktop runtime authority integrity validation failed")
)

// DesktopPublisherKind selects one native trust mechanism. It is not a free-form
// command or certificate-search policy.
type DesktopPublisherKind string

const (
	// DesktopPublisherAppleNotarized selects Apple Developer ID plus notarization.
	DesktopPublisherAppleNotarized DesktopPublisherKind = "apple_developer_id_notarized"
	// DesktopPublisherAuthenticode selects Windows Authenticode verification.
	DesktopPublisherAuthenticode DesktopPublisherKind = "windows_authenticode"
)

// DesktopPublisherInput is the signed native publisher projection.
type DesktopPublisherInput struct {
	Kind               DesktopPublisherKind
	Identity           string
	SigningKeyIdentity string
	PackageIdentity    string
	CertificateSHA256  runtimeinstall.Hash
}

// DesktopPublisher is immutable native publisher authority.
type DesktopPublisher struct {
	kind               DesktopPublisherKind
	identity           string
	signingKeyIdentity string
	packageIdentity    string
	certificateSHA256  runtimeinstall.Hash
}

func newDesktopPublisher(input DesktopPublisherInput, platform runtimeinstall.Platform) (DesktopPublisher, error) {
	wantedKind := DesktopPublisherAppleNotarized
	wantedIdentity := "developer-id-application-docker-inc-9bnsxjn65r"
	wantedPackage := "com.docker.docker"
	if platform == runtimeinstall.PlatformWindows {
		wantedKind = DesktopPublisherAuthenticode
		wantedIdentity = "microsoft-authenticode-docker-inc"
		wantedPackage = "com.docker.docker"
	}
	if input.Kind != wantedKind || input.Identity != wantedIdentity || input.PackageIdentity != wantedPackage ||
		!safeAuthorityIdentifier(input.SigningKeyIdentity, 128) || input.CertificateSHA256.IsZero() {
		return DesktopPublisher{}, ErrDesktopAuthorityIntegrity
	}
	return DesktopPublisher{
		kind: input.Kind, identity: input.Identity, signingKeyIdentity: input.SigningKeyIdentity,
		packageIdentity: input.PackageIdentity, certificateSHA256: input.CertificateSHA256,
	}, nil
}

func (p DesktopPublisher) valid(platform runtimeinstall.Platform) bool {
	_, err := newDesktopPublisher(DesktopPublisherInput{
		Kind: p.kind, Identity: p.identity, SigningKeyIdentity: p.signingKeyIdentity,
		PackageIdentity: p.packageIdentity, CertificateSHA256: p.certificateSHA256,
	}, platform)
	return err == nil
}

// Kind returns the required native publisher verification mechanism.
func (p DesktopPublisher) Kind() DesktopPublisherKind { return p.kind }

// Identity returns the signed publisher identity.
func (p DesktopPublisher) Identity() string { return p.identity }

// SigningKeyIdentity returns the exact native signing-key identity.
func (p DesktopPublisher) SigningKeyIdentity() string { return p.signingKeyIdentity }

// PackageIdentity returns the exact vendor package identity.
func (p DesktopPublisher) PackageIdentity() string { return p.packageIdentity }

// CertificateSHA256 returns the pinned signer certificate digest.
func (p DesktopPublisher) CertificateSHA256() runtimeinstall.Hash { return p.certificateSHA256 }

// DesktopTermsInput declares the exact vendor agreement displayed before any
// installer can receive its documented acceptance flag.
type DesktopTermsInput struct {
	ID      string
	Version string
	URL     string
	Digest  runtimeinstall.Hash
}

// DesktopTerms is immutable third-party terms authority.
type DesktopTerms struct {
	id      string
	version string
	url     string
	digest  runtimeinstall.Hash
}

func newDesktopTerms(input DesktopTermsInput) (DesktopTerms, error) {
	if !safeAuthorityIdentifier(input.ID, 128) ||
		input.URL != "https://www.docker.com/legal/"+input.ID+"/" ||
		!safeVersion(input.Version) || input.Digest.IsZero() {
		return DesktopTerms{}, ErrDesktopAuthorityIntegrity
	}
	return DesktopTerms{id: input.ID, version: input.Version, url: input.URL, digest: input.Digest}, nil
}

func (t DesktopTerms) valid() bool {
	_, err := newDesktopTerms(DesktopTermsInput{ID: t.id, Version: t.version, URL: t.url, Digest: t.digest})
	return err == nil
}

// ID returns the signed vendor agreement identifier.
func (t DesktopTerms) ID() string { return t.id }

// Version returns the signed vendor agreement version.
func (t DesktopTerms) Version() string { return t.version }

// URL returns the exact vendor agreement URL.
func (t DesktopTerms) URL() string { return t.url }

// Digest returns the signed vendor agreement content digest.
func (t DesktopTerms) Digest() runtimeinstall.Hash { return t.digest }

// DesktopAuthorityInput is populated only from a signature-verified catalog,
// release manifest, host identity, and exact artifact reservation.
type DesktopAuthorityInput struct {
	PlanDigest             runtimeinstall.Hash
	CatalogDigest          runtimeinstall.Hash
	Platform               runtimeinstall.Platform
	Architecture           runtimeinstall.Architecture
	PrincipalID            string
	UserName               string
	MachineDigest          runtimeinstall.Hash
	HomeDirectory          string
	OSProduct              string
	MinimumOSVersion       string
	MaximumOSVersion       string
	MinimumBuild           uint32
	MaximumBuild           uint32
	MinimumCPUs            uint16
	MinimumTotalMemory     uint64
	MinimumAvailableMemory uint64
	MinimumFreeDisk        uint64
	RuntimeVersion         string
	EngineVersion          string
	ComposeVersion         string
	Endpoint               string
	ArtifactPath           string
	ArtifactSHA256         runtimeinstall.Hash
	ArtifactBytes          uint64
	ArtifactSourceURL      string
	Publisher              DesktopPublisherInput
	Terms                  DesktopTermsInput
	InstallerArguments     []string
	ApplicationPath        string
	ApplicationExecutable  string
	DockerCLIPath          string
	ComposePluginPath      string
	ProbeImage             string
	ProbeImageDigest       runtimeinstall.Hash
	ProbeContractVersion   string
	UnrelatedWorkloads     uint32
	CapabilityPolicyDigest runtimeinstall.Hash
	RebootExitCodes        []uint32
	WindowsFeatures        []string
	MinimumWSLVersion      string
	VendorUIMandatory      bool
}

// DesktopAuthority is the complete immutable execution authority for one
// certified Docker Desktop installation on one principal and machine.
type DesktopAuthority struct {
	planDigest             runtimeinstall.Hash
	catalogDigest          runtimeinstall.Hash
	platform               runtimeinstall.Platform
	architecture           runtimeinstall.Architecture
	principalID            string
	userName               string
	machineDigest          runtimeinstall.Hash
	homeDirectory          string
	osProduct              string
	minimumOSVersion       string
	maximumOSVersion       string
	minimumBuild           uint32
	maximumBuild           uint32
	minimumCPUs            uint16
	minimumTotalMemory     uint64
	minimumAvailableMemory uint64
	minimumFreeDisk        uint64
	runtimeVersion         string
	engineVersion          string
	composeVersion         string
	endpoint               string
	artifactPath           string
	artifactSHA256         runtimeinstall.Hash
	artifactBytes          uint64
	artifactSourceURL      string
	publisher              DesktopPublisher
	terms                  DesktopTerms
	installerArguments     []string
	applicationPath        string
	applicationExecutable  string
	dockerCLIPath          string
	composePluginPath      string
	probeImage             string
	probeImageDigest       runtimeinstall.Hash
	probeContractVersion   string
	unrelatedWorkloads     uint32
	capabilityPolicyDigest runtimeinstall.Hash
	rebootExitCodes        []uint32
	windowsFeatures        []string
	minimumWSLVersion      string
	vendorUIMandatory      bool
	digest                 runtimeinstall.Hash
}

// NewDesktopAuthority validates a closed macOS or Windows execution projection.
func NewDesktopAuthority(input DesktopAuthorityInput) (DesktopAuthority, error) {
	if input.PlanDigest.IsZero() || input.CatalogDigest.IsZero() || input.MachineDigest.IsZero() ||
		input.ArtifactSHA256.IsZero() || input.ProbeImageDigest.IsZero() || input.CapabilityPolicyDigest.IsZero() ||
		!validDesktopPlatformArchitecture(input.Platform, input.Architecture) ||
		!safePrincipal(input.PrincipalID, input.Platform) || !safeUserName(input.UserName, input.Platform) ||
		!validDesktopHostPolicy(input) ||
		!safeVersion(input.RuntimeVersion) || !safeVersion(input.EngineVersion) || !safeVersion(input.ComposeVersion) ||
		input.ArtifactBytes == 0 || input.ArtifactBytes > 1<<53-1 ||
		!validDesktopPaths(input) || !validDesktopSource(input.ArtifactSourceURL, input.Platform, input.Architecture) ||
		!validDesktopArguments(input.Platform, input.UserName, input.InstallerArguments) || !validDesktopProbe(input) ||
		input.VendorUIMandatory {
		return DesktopAuthority{}, ErrDesktopAuthorityIntegrity
	}
	publisher, err := newDesktopPublisher(input.Publisher, input.Platform)
	if err != nil {
		return DesktopAuthority{}, err
	}
	terms, err := newDesktopTerms(input.Terms)
	if err != nil {
		return DesktopAuthority{}, err
	}
	rebootCodes := append([]uint32(nil), input.RebootExitCodes...)
	if !validRebootCodes(rebootCodes, input.Platform) {
		return DesktopAuthority{}, ErrDesktopAuthorityIntegrity
	}
	features := append([]string(nil), input.WindowsFeatures...)
	if !validWindowsPrerequisites(input.Platform, input.Architecture, features, input.MinimumWSLVersion) {
		return DesktopAuthority{}, ErrDesktopAuthorityIntegrity
	}
	authority := DesktopAuthority{
		planDigest: input.PlanDigest, catalogDigest: input.CatalogDigest, platform: input.Platform,
		architecture: input.Architecture, principalID: input.PrincipalID, userName: input.UserName,
		machineDigest: input.MachineDigest, homeDirectory: input.HomeDirectory,
		osProduct: input.OSProduct, minimumOSVersion: input.MinimumOSVersion,
		maximumOSVersion: input.MaximumOSVersion, minimumBuild: input.MinimumBuild,
		maximumBuild: input.MaximumBuild, minimumCPUs: input.MinimumCPUs,
		minimumTotalMemory: input.MinimumTotalMemory, minimumAvailableMemory: input.MinimumAvailableMemory,
		minimumFreeDisk: input.MinimumFreeDisk,
		runtimeVersion:  input.RuntimeVersion, engineVersion: input.EngineVersion,
		composeVersion: input.ComposeVersion, endpoint: input.Endpoint, artifactPath: input.ArtifactPath,
		artifactSHA256: input.ArtifactSHA256, artifactBytes: input.ArtifactBytes,
		artifactSourceURL: input.ArtifactSourceURL, publisher: publisher, terms: terms,
		installerArguments: append([]string(nil), input.InstallerArguments...),
		applicationPath:    input.ApplicationPath, applicationExecutable: input.ApplicationExecutable,
		dockerCLIPath: input.DockerCLIPath, composePluginPath: input.ComposePluginPath,
		probeImage: input.ProbeImage, probeImageDigest: input.ProbeImageDigest,
		probeContractVersion: input.ProbeContractVersion, unrelatedWorkloads: input.UnrelatedWorkloads,
		capabilityPolicyDigest: input.CapabilityPolicyDigest, rebootExitCodes: rebootCodes,
		windowsFeatures: features, minimumWSLVersion: input.MinimumWSLVersion,
		vendorUIMandatory: input.VendorUIMandatory,
	}
	authority.digest = authority.computeDigest()
	if authority.digest.IsZero() {
		return DesktopAuthority{}, ErrDesktopAuthorityIntegrity
	}
	return authority, nil
}

func validDesktopPlatformArchitecture(platform runtimeinstall.Platform, architecture runtimeinstall.Architecture) bool {
	return platform == runtimeinstall.PlatformDarwin &&
		(architecture == runtimeinstall.ArchitectureAMD64 || architecture == runtimeinstall.ArchitectureARM64) ||
		platform == runtimeinstall.PlatformWindows && architecture == runtimeinstall.ArchitectureAMD64
}

func validDesktopHostPolicy(input DesktopAuthorityInput) bool {
	wantedProduct := "macos"
	if input.Platform == runtimeinstall.PlatformWindows {
		wantedProduct = "windows-11"
	}
	return input.OSProduct == wantedProduct && safeVersion(input.MinimumOSVersion) &&
		safeVersion(input.MaximumOSVersion) && compareNumericVersion(input.MinimumOSVersion, input.MaximumOSVersion) <= 0 &&
		input.MinimumBuild > 0 && input.MaximumBuild >= input.MinimumBuild && input.MinimumCPUs >= 4 &&
		input.MinimumTotalMemory >= 8<<30 && input.MinimumAvailableMemory > 0 &&
		input.MinimumAvailableMemory <= input.MinimumTotalMemory && input.MinimumFreeDisk >= 30<<30
}

func validDesktopPaths(input DesktopAuthorityInput) bool {
	switch input.Platform {
	case runtimeinstall.PlatformDarwin:
		return safeUnixAbsolute(input.HomeDirectory) && input.HomeDirectory != "/tmp" &&
			!strings.HasPrefix(input.HomeDirectory, "/tmp/") && safeUnixAbsolute(input.ArtifactPath) &&
			!strings.HasPrefix(input.ArtifactPath, "/tmp/") &&
			input.Endpoint == "unix://"+input.HomeDirectory+"/.docker/run/docker.sock" &&
			input.ApplicationPath == "/Applications/Docker.app" &&
			input.ApplicationExecutable == "/Applications/Docker.app/Contents/MacOS/Docker Desktop" &&
			input.DockerCLIPath == "/Applications/Docker.app/Contents/Resources/bin/docker" &&
			input.ComposePluginPath == "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose"
	case runtimeinstall.PlatformWindows:
		root := input.HomeDirectory + `\AppData\Local\Programs\DockerDesktop`
		return safeWindowsAbsolute(input.HomeDirectory) && safeWindowsAbsolute(input.ArtifactPath) &&
			input.Endpoint == "npipe:////./pipe/docker_engine" &&
			input.ApplicationPath == root && input.ApplicationExecutable == root+`\Docker Desktop.exe` &&
			input.DockerCLIPath == root+`\resources\bin\docker.exe` &&
			input.ComposePluginPath == root+`\resources\cli-plugins\docker-compose.exe`
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return false
	}
	return false
}

func validDesktopSource(raw string, platform runtimeinstall.Platform, architecture runtimeinstall.Architecture) bool {
	prefix := "https://desktop.docker.com/mac/main/" + architecture.String() + "/"
	if platform == runtimeinstall.PlatformWindows {
		prefix = "https://desktop.docker.com/win/main/amd64/"
	}
	fileName, found := strings.CutPrefix(raw, prefix)
	return found && safeDesktopSourceFileName(fileName)
}

// safeDesktopSourceFileName deliberately accepts a much smaller grammar than
// a general URL parser. The signed catalog may name one file below the exact
// Docker CDN platform prefix; the only accepted escape is %20, used by the
// Windows installer filename. Authority, query, fragment, traversal, nested
// path, control-character, and ambiguous percent-encoding forms are therefore
// impossible by construction.
func safeDesktopSourceFileName(value string) bool {
	if value == "" || len(value) > 255 || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		if character == '%' && index+2 < len(value) && value[index+1:index+3] == "20" {
			index += 2
			continue
		}
		return false
	}
	return true
}

func validDesktopArguments(platform runtimeinstall.Platform, userName string, arguments []string) bool {
	if platform == runtimeinstall.PlatformDarwin {
		wanted := []string{"--accept-license", "--user=" + userName}
		return equalStrings(arguments, wanted)
	}
	wanted := []string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"}
	return equalStrings(arguments, wanted)
}

func validDesktopProbe(input DesktopAuthorityInput) bool {
	const prefix = "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:"
	return input.ProbeContractVersion == "1" && input.ProbeImage == prefix+input.ProbeImageDigest.String()
}

func validRebootCodes(codes []uint32, platform runtimeinstall.Platform) bool {
	if platform == runtimeinstall.PlatformDarwin {
		return len(codes) == 0
	}
	if !equalUint32(codes, []uint32{1641, 3010}) {
		return false
	}
	return sort.SliceIsSorted(codes, func(i, j int) bool { return codes[i] < codes[j] })
}

func validWindowsPrerequisites(
	platform runtimeinstall.Platform,
	architecture runtimeinstall.Architecture,
	features []string,
	minimumWSL string,
) bool {
	if platform == runtimeinstall.PlatformDarwin {
		return len(features) == 0 && minimumWSL == ""
	}
	return architecture == runtimeinstall.ArchitectureAMD64 &&
		equalStrings(features, []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}) &&
		minimumWSL == "2.1.5"
}

func (a DesktopAuthority) computeDigest() runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Plan, Catalog, Machine, Artifact, Probe, Capability, Certificate, Terms               string
		Platform, Architecture, Principal, User, Home, OSProduct, MinimumOS, MaximumOS        string
		Runtime, Engine, Compose, Endpoint                                                    string
		ArtifactPath, ArtifactSource, Publisher, SigningKey, Package                          string
		Arguments, Features, Reboot                                                           []string
		Application, Executable, Docker, ComposePlugin, ProbeImage, ProbeContract, MinimumWSL string
		ArtifactBytes                                                                         uint64
		UnrelatedWorkloads                                                                    uint32
		MinimumBuild, MaximumBuild                                                            uint32
		MinimumCPUs                                                                           uint16
		MinimumTotalMemory, MinimumAvailableMemory, MinimumFreeDisk                           uint64
		VendorUI                                                                              bool
	}{
		Plan: a.planDigest.String(), Catalog: a.catalogDigest.String(), Machine: a.machineDigest.String(),
		Artifact: a.artifactSHA256.String(), Capability: a.capabilityPolicyDigest.String(),
		Probe:       a.probeImageDigest.String(),
		Certificate: a.publisher.certificateSHA256.String(), Terms: a.terms.digest.String(),
		Platform: a.platform.String(), Architecture: a.architecture.String(), Principal: a.principalID,
		User: a.userName, Home: a.homeDirectory, OSProduct: a.osProduct,
		MinimumOS: a.minimumOSVersion, MaximumOS: a.maximumOSVersion,
		MinimumBuild: a.minimumBuild, MaximumBuild: a.maximumBuild, MinimumCPUs: a.minimumCPUs,
		MinimumTotalMemory: a.minimumTotalMemory, MinimumAvailableMemory: a.minimumAvailableMemory,
		MinimumFreeDisk: a.minimumFreeDisk, Runtime: a.runtimeVersion, Engine: a.engineVersion,
		Compose: a.composeVersion, Endpoint: a.endpoint, ArtifactPath: a.artifactPath,
		ArtifactSource: a.artifactSourceURL, Publisher: a.publisher.identity,
		SigningKey: a.publisher.signingKeyIdentity, Package: a.publisher.packageIdentity,
		Arguments: append([]string(nil), a.installerArguments...), Features: append([]string(nil), a.windowsFeatures...),
		Reboot: uint32Strings(a.rebootExitCodes), Application: a.applicationPath,
		Executable: a.applicationExecutable, Docker: a.dockerCLIPath, ComposePlugin: a.composePluginPath,
		ProbeImage: a.probeImage, ProbeContract: a.probeContractVersion,
		MinimumWSL: a.minimumWSLVersion, ArtifactBytes: a.artifactBytes, VendorUI: a.vendorUIMandatory,
		UnrelatedWorkloads: a.unrelatedWorkloads,
	})
	return runtimeinstall.Sum(encoded)
}

// Valid revalidates the complete immutable projection.
func (a DesktopAuthority) Valid() bool {
	restored, err := NewDesktopAuthority(DesktopAuthorityInput{
		PlanDigest: a.planDigest, CatalogDigest: a.catalogDigest, Platform: a.platform,
		Architecture: a.architecture, PrincipalID: a.principalID, UserName: a.userName,
		MachineDigest: a.machineDigest, HomeDirectory: a.homeDirectory,
		OSProduct: a.osProduct, MinimumOSVersion: a.minimumOSVersion, MaximumOSVersion: a.maximumOSVersion,
		MinimumBuild: a.minimumBuild, MaximumBuild: a.maximumBuild, MinimumCPUs: a.minimumCPUs,
		MinimumTotalMemory: a.minimumTotalMemory, MinimumAvailableMemory: a.minimumAvailableMemory,
		MinimumFreeDisk: a.minimumFreeDisk, RuntimeVersion: a.runtimeVersion,
		EngineVersion: a.engineVersion, ComposeVersion: a.composeVersion, Endpoint: a.endpoint,
		ArtifactPath: a.artifactPath, ArtifactSHA256: a.artifactSHA256, ArtifactBytes: a.artifactBytes,
		ArtifactSourceURL: a.artifactSourceURL,
		Publisher: DesktopPublisherInput{Kind: a.publisher.kind, Identity: a.publisher.identity,
			SigningKeyIdentity: a.publisher.signingKeyIdentity, PackageIdentity: a.publisher.packageIdentity,
			CertificateSHA256: a.publisher.certificateSHA256},
		Terms:              DesktopTermsInput{ID: a.terms.id, Version: a.terms.version, URL: a.terms.url, Digest: a.terms.digest},
		InstallerArguments: append([]string(nil), a.installerArguments...), ApplicationPath: a.applicationPath,
		ApplicationExecutable: a.applicationExecutable, DockerCLIPath: a.dockerCLIPath,
		ComposePluginPath: a.composePluginPath, ProbeImage: a.probeImage, ProbeImageDigest: a.probeImageDigest,
		ProbeContractVersion: a.probeContractVersion, UnrelatedWorkloads: a.unrelatedWorkloads,
		CapabilityPolicyDigest: a.capabilityPolicyDigest,
		RebootExitCodes:        append([]uint32(nil), a.rebootExitCodes...), WindowsFeatures: append([]string(nil), a.windowsFeatures...),
		MinimumWSLVersion: a.minimumWSLVersion, VendorUIMandatory: a.vendorUIMandatory,
	})
	return err == nil && restored.digest == a.digest && !a.digest.IsZero()
}

// ValidFor proves this authority belongs to the decoded canonical plan.
func (a DesktopAuthority) ValidFor(plan runtimeinstall.Plan) bool {
	return a.Valid() && len(plan.CanonicalBytes()) != 0 && plan.Digest() == a.planDigest &&
		plan.CatalogDigest() == a.catalogDigest &&
		plan.TermsPresentation() == runtimeinstall.TermsPresentationAgentMemory
}

// Digest returns the complete immutable authority digest.
func (a DesktopAuthority) Digest() runtimeinstall.Hash { return a.digest }

// PlanDigest returns the bound runtime plan digest.
func (a DesktopAuthority) PlanDigest() runtimeinstall.Hash { return a.planDigest }

// CatalogDigest returns the signed runtime catalog digest.
func (a DesktopAuthority) CatalogDigest() runtimeinstall.Hash { return a.catalogDigest }

// Platform returns the authorized host platform.
func (a DesktopAuthority) Platform() runtimeinstall.Platform { return a.platform }

// Architecture returns the authorized host architecture.
func (a DesktopAuthority) Architecture() runtimeinstall.Architecture { return a.architecture }

// PrincipalID returns the authorized native principal identity.
func (a DesktopAuthority) PrincipalID() string { return a.principalID }

// UserName returns the authorized interactive user name.
func (a DesktopAuthority) UserName() string { return a.userName }

// MachineDigest returns the bound machine identity digest.
func (a DesktopAuthority) MachineDigest() runtimeinstall.Hash { return a.machineDigest }

// HomeDirectory returns the bound native home directory.
func (a DesktopAuthority) HomeDirectory() string { return a.homeDirectory }

// OSProduct returns the authorized operating-system product.
func (a DesktopAuthority) OSProduct() string { return a.osProduct }

// MinimumOSVersion returns the inclusive operating-system version floor.
func (a DesktopAuthority) MinimumOSVersion() string { return a.minimumOSVersion }

// MaximumOSVersion returns the inclusive operating-system version ceiling.
func (a DesktopAuthority) MaximumOSVersion() string { return a.maximumOSVersion }

// MinimumBuild returns the inclusive native build floor.
func (a DesktopAuthority) MinimumBuild() uint32 { return a.minimumBuild }

// MaximumBuild returns the inclusive native build ceiling.
func (a DesktopAuthority) MaximumBuild() uint32 { return a.maximumBuild }

// MinimumCPUs returns the required logical CPU count.
func (a DesktopAuthority) MinimumCPUs() uint16 { return a.minimumCPUs }

// MinimumTotalMemory returns the required total memory in bytes.
func (a DesktopAuthority) MinimumTotalMemory() uint64 { return a.minimumTotalMemory }

// MinimumAvailableMemory returns the required available memory in bytes.
func (a DesktopAuthority) MinimumAvailableMemory() uint64 { return a.minimumAvailableMemory }

// MinimumFreeDisk returns the required free disk capacity in bytes.
func (a DesktopAuthority) MinimumFreeDisk() uint64 { return a.minimumFreeDisk }

// RuntimeVersion returns the exact Docker Desktop version.
func (a DesktopAuthority) RuntimeVersion() string { return a.runtimeVersion }

// EngineVersion returns the exact Docker Engine version.
func (a DesktopAuthority) EngineVersion() string { return a.engineVersion }

// ComposeVersion returns the exact Docker Compose version.
func (a DesktopAuthority) ComposeVersion() string { return a.composeVersion }

// Endpoint returns the exact local Docker endpoint.
func (a DesktopAuthority) Endpoint() string { return a.endpoint }

// ArtifactPath returns the reserved installer artifact path.
func (a DesktopAuthority) ArtifactPath() string { return a.artifactPath }

// ArtifactSHA256 returns the exact installer artifact digest.
func (a DesktopAuthority) ArtifactSHA256() runtimeinstall.Hash { return a.artifactSHA256 }

// ArtifactBytes returns the exact installer artifact size.
func (a DesktopAuthority) ArtifactBytes() uint64 { return a.artifactBytes }

// ArtifactSourceURL returns the exact Docker CDN source URL.
func (a DesktopAuthority) ArtifactSourceURL() string { return a.artifactSourceURL }

// Publisher returns the pinned native publisher authority.
func (a DesktopAuthority) Publisher() DesktopPublisher { return a.publisher }

// Terms returns the exact vendor agreement authority.
func (a DesktopAuthority) Terms() DesktopTerms { return a.terms }

// InstallerArguments returns a defensive copy of the exact installer argv.
func (a DesktopAuthority) InstallerArguments() []string {
	return append([]string(nil), a.installerArguments...)
}

// ApplicationPath returns the exact installed application root.
func (a DesktopAuthority) ApplicationPath() string { return a.applicationPath }

// ApplicationExecutable returns the exact installed application executable.
func (a DesktopAuthority) ApplicationExecutable() string { return a.applicationExecutable }

// DockerCLIPath returns the exact signed Docker CLI path.
func (a DesktopAuthority) DockerCLIPath() string { return a.dockerCLIPath }

// ComposePluginPath returns the exact signed Compose plugin path.
func (a DesktopAuthority) ComposePluginPath() string { return a.composePluginPath }

// ProbeImage returns the digest-addressed capability probe image.
func (a DesktopAuthority) ProbeImage() string { return a.probeImage }

// ProbeImageDigest returns the signed capability probe image digest.
func (a DesktopAuthority) ProbeImageDigest() runtimeinstall.Hash { return a.probeImageDigest }

// ProbeContractVersion returns the exact active-probe contract version.
func (a DesktopAuthority) ProbeContractVersion() string { return a.probeContractVersion }

// UnrelatedWorkloads returns the signed expected unrelated workload count.
func (a DesktopAuthority) UnrelatedWorkloads() uint32 { return a.unrelatedWorkloads }

// CapabilityPolicyDigest returns the signed active-capability policy digest.
func (a DesktopAuthority) CapabilityPolicyDigest() runtimeinstall.Hash {
	return a.capabilityPolicyDigest
}

// RebootExitCodes returns a defensive copy of accepted reboot-required codes.
func (a DesktopAuthority) RebootExitCodes() []uint32 {
	return append([]uint32(nil), a.rebootExitCodes...)
}

// WindowsFeatures returns a defensive copy of required Windows features.
func (a DesktopAuthority) WindowsFeatures() []string {
	return append([]string(nil), a.windowsFeatures...)
}

// MinimumWSLVersion returns the exact WSL version floor.
func (a DesktopAuthority) MinimumWSLVersion() string { return a.minimumWSLVersion }

// VendorUIMandatory reports whether vendor UI startup is required.
func (a DesktopAuthority) VendorUIMandatory() bool { return a.vendorUIMandatory }

func safeAuthorityIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safePrincipal(value string, platform runtimeinstall.Platform) bool {
	prefix := "uid:"
	if platform == runtimeinstall.PlatformWindows {
		prefix = "sid:"
	}
	identity := strings.TrimPrefix(value, prefix)
	if !strings.HasPrefix(value, prefix) || !safeAuthorityIdentifier(identity, 184) {
		return false
	}
	if platform == runtimeinstall.PlatformDarwin {
		return identity != "0"
	}
	return identity != "S-1-5-18" && identity != "S-1-5-19" && identity != "S-1-5-20"
}

func safeUserName(value string, platform runtimeinstall.Platform) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' ||
			platform == runtimeinstall.PlatformWindows && character == ' ' {
			continue
		}
		return false
	}
	return value != "." && value != ".."
}

func safeVersion(value string) bool {
	return safeAuthorityIdentifier(value, 128) && !strings.Contains(strings.ToLower(value), "latest")
}

func safeUnixAbsolute(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, "\x00\r\n") || len(value) > 4096 {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func safeWindowsAbsolute(value string) bool {
	if len(value) < 4 || len(value) > 4096 || value[1:3] != `:\` || value[0] < 'A' || value[0] > 'Z' ||
		strings.HasSuffix(value, `\`) || strings.Contains(value[3:], `\\`) || strings.ContainsAny(value, "\x00\r\n/\"") {
		return false
	}
	if strings.Contains(value[3:], ":") {
		return false
	}
	for _, component := range strings.Split(value[3:], `\`) {
		if component == "" || component == "." || component == ".." || strings.HasSuffix(component, ".") ||
			strings.HasSuffix(component, " ") {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
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

func equalUint32(left, right []uint32) bool {
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

func uint32Strings(values []uint32) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strconv.FormatUint(uint64(value), 10)
	}
	return result
}

func compareNumericVersion(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	length := len(leftParts)
	if len(rightParts) > length {
		length = len(rightParts)
	}
	for index := 0; index < length; index++ {
		var leftValue, rightValue uint64
		var leftError, rightError error
		if index < len(leftParts) {
			leftValue, leftError = strconv.ParseUint(leftParts[index], 10, 32)
		}
		if index < len(rightParts) {
			rightValue, rightError = strconv.ParseUint(rightParts[index], 10, 32)
		}
		if leftError != nil || rightError != nil {
			return 2
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}
