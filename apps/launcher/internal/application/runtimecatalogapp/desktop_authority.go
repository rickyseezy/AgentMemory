package runtimecatalogapp

import (
	"errors"
	"math"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// DesktopHostBindingInput contains only native principal/machine facts and the
// operation-owned artifact path that cannot be declared by a signed catalog.
type DesktopHostBindingInput struct {
	Platform      runtimeinstall.Platform
	Architecture  runtimeinstall.Architecture
	PrincipalID   string
	UserName      string
	MachineDigest runtimeinstall.Hash
	HomeDirectory string
	ArtifactPath  string
	Endpoint      string
}

// DesktopHostBinding is immutable non-catalog execution context.
type DesktopHostBinding struct{ input DesktopHostBindingInput }

// NewDesktopHostBinding rejects cross-platform and ambient endpoint choices.
func NewDesktopHostBinding(input DesktopHostBindingInput) (DesktopHostBinding, error) {
	valid := !input.MachineDigest.IsZero() && input.PrincipalID == strings.TrimSpace(input.PrincipalID) &&
		input.UserName == strings.TrimSpace(input.UserName) && input.PrincipalID != "" && input.UserName != "" &&
		input.HomeDirectory != "" && input.ArtifactPath != ""
	switch input.Platform {
	case runtimeinstall.PlatformDarwin:
		valid = valid && (input.Architecture == runtimeinstall.ArchitectureAMD64 || input.Architecture == runtimeinstall.ArchitectureARM64) &&
			strings.HasPrefix(input.PrincipalID, "uid:") && strings.HasPrefix(input.HomeDirectory, "/") &&
			strings.HasPrefix(input.ArtifactPath, "/") && input.Endpoint == "unix://"+input.HomeDirectory+"/.docker/run/docker.sock"
	case runtimeinstall.PlatformWindows:
		valid = valid && input.Architecture == runtimeinstall.ArchitectureAMD64 &&
			strings.HasPrefix(input.PrincipalID, "sid:S-1-") && desktopWindowsAbsolute(input.HomeDirectory) &&
			desktopWindowsAbsolute(input.ArtifactPath) && input.Endpoint == "npipe:////./pipe/docker_engine"
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		valid = false
	}
	if !valid {
		return DesktopHostBinding{}, errors.New("desktop host binding is invalid")
	}
	return DesktopHostBinding{input: input}, nil
}

func desktopWindowsAbsolute(value string) bool {
	return len(value) >= 3 && value[1] == ':' && (value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') &&
		value[2] == '\\' && !strings.ContainsAny(value, "\x00\r\n")
}

// DesktopAuthority projects only signature-verified catalog policy,
// independently embedded native certificate trust, and native host binding.
func (c VerifiedCatalog) DesktopAuthority(
	canonicalPlan []byte,
	host DesktopHostBinding,
	nativeCertificate runtimecatalog.Digest,
) (runtimeport.DesktopAuthority, error) {
	if !c.manifest.Valid() || c.verifiedAt.IsZero() || c.verifiedAt.Location() != time.UTC ||
		len(canonicalPlan) == 0 || nativeCertificate.IsZero() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityUnavailable
	}
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || runtimecatalog.Digest(plan.CatalogDigest()) != c.manifest.Digest() ||
		runtimecatalog.Digest(plan.TermsDigest()) != c.manifest.Terms().Digest() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	platform := c.manifest.Platform()
	execution, present := c.manifest.DesktopExecution()
	if !present || platform.MinimumCPUCores() > math.MaxUint16 || platform.MinimumBuild() > math.MaxUint32 ||
		platform.MaximumBuild() > math.MaxUint32 || plan.HostOSVersion() == "" {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	projectedPlatform, architecture, product, err := desktopRuntimePlatform(platform)
	if err != nil || host.input.Platform != projectedPlatform || host.input.Architecture != architecture {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	runtimePolicy := c.manifest.Runtime()
	engine, err := runtimePolicy.RuntimeComponentFor(runtimecatalog.ComponentEngine)
	if err != nil {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	artifact := c.manifest.Artifact()
	sources := artifact.Sources()
	if len(sources) != 1 {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	publisherKind, err := desktopPublisherKind(artifact.Publisher().Verification())
	if err != nil {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	application, executable, dockerCLI, composePlugin, arguments := desktopFixedAuthority(
		projectedPlatform, host.input.UserName, host.input.HomeDirectory,
	)
	terms := c.manifest.Terms()
	termsURL := sourceURL(terms.URL())
	if !strings.HasSuffix(termsURL, "/") {
		termsURL += "/"
	}
	input := runtimeport.DesktopAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), Platform: projectedPlatform,
		Architecture: architecture, PrincipalID: host.input.PrincipalID, UserName: host.input.UserName,
		MachineDigest: host.input.MachineDigest, HomeDirectory: host.input.HomeDirectory, OSProduct: product,
		MinimumOSVersion: platform.MinimumOSVersion(), MaximumOSVersion: platform.MaximumOSVersion(),
		MinimumBuild: uint32(platform.MinimumBuild()), MaximumBuild: uint32(platform.MaximumBuild()), // #nosec G115 -- both catalog bounds are proven uint32 above.
		MinimumCPUs:        uint16(platform.MinimumCPUCores()), // #nosec G115 -- catalog floor is proven uint16 above.
		MinimumTotalMemory: platform.MinimumMemoryBytes(), MinimumAvailableMemory: execution.MinimumAvailableMemory(),
		MinimumFreeDisk: platform.MinimumFreeDiskBytes(), RuntimeVersion: runtimePolicy.Version(),
		EngineVersion: engine.Version(), ComposeVersion: runtimePolicy.ComposeVersion(), Endpoint: host.input.Endpoint,
		ArtifactPath: host.input.ArtifactPath, ArtifactSHA256: runtimeinstall.Hash(artifact.SHA256()),
		ArtifactBytes: artifact.DownloadBytes(), ArtifactSourceURL: sourceURL(sources[0]) + execution.ArtifactFileName(),
		Publisher: runtimeport.DesktopPublisherInput{
			Kind: publisherKind, Identity: artifact.Publisher().Identity(),
			SigningKeyIdentity: artifact.Publisher().SigningKeyIdentity(), PackageIdentity: artifact.Publisher().PackageIdentity(),
			CertificateSHA256: runtimeinstall.Hash(nativeCertificate),
		},
		Terms: runtimeport.DesktopTermsInput{
			ID: terms.ID(), Version: terms.Version(), URL: termsURL, Digest: runtimeinstall.Hash(terms.Digest()),
		},
		InstallerArguments: arguments, ApplicationPath: application, ApplicationExecutable: executable,
		DockerCLIPath: dockerCLI, ComposePluginPath: composePlugin, ProbeImage: execution.ProbeImage(),
		ProbeImageDigest: runtimeinstall.Hash(execution.ProbeImageDigest()), ProbeContractVersion: execution.ProbeContractVersion(),
		UnrelatedWorkloads: plan.UnrelatedWorkloads(), CapabilityPolicyDigest: runtimeinstall.Hash(execution.CapabilityPolicyDigest()),
		RebootExitCodes: c.manifest.Install().RebootExitCodes(), WindowsFeatures: execution.WindowsFeatures(),
		MinimumWSLVersion: execution.MinimumWSLVersion(), VendorUIMandatory: c.manifest.Install().VendorUIMandatory(),
	}
	authority, err := runtimeport.NewDesktopAuthority(input)
	if err != nil || !authority.ValidFor(plan) {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	return authority, nil
}

func desktopRuntimePlatform(
	platform runtimecatalog.PlatformPolicy,
) (runtimeinstall.Platform, runtimeinstall.Architecture, string, error) {
	architecture := runtimeinstall.ArchitectureUnknown
	switch platform.Architecture() {
	case runtimecatalog.ArchitectureX8664:
		architecture = runtimeinstall.ArchitectureAMD64
	case runtimecatalog.ArchitectureARM64:
		architecture = runtimeinstall.ArchitectureARM64
	default:
		return runtimeinstall.PlatformUnknown, architecture, "", runtimeport.ErrDesktopAuthorityIntegrity
	}
	switch platform.OperatingSystem() {
	case runtimecatalog.OSKindMacOS:
		return runtimeinstall.PlatformDarwin, architecture, "macos", nil
	case runtimecatalog.OSKindWindows:
		if architecture != runtimeinstall.ArchitectureAMD64 {
			return runtimeinstall.PlatformUnknown, architecture, "", runtimeport.ErrDesktopAuthorityIntegrity
		}
		return runtimeinstall.PlatformWindows, architecture, "windows-11", nil
	case runtimecatalog.OSKindLinux:
	}
	return runtimeinstall.PlatformUnknown, architecture, "", runtimeport.ErrDesktopAuthorityIntegrity
}

func desktopPublisherKind(value runtimecatalog.NativeVerification) (runtimeport.DesktopPublisherKind, error) {
	switch value {
	case runtimecatalog.NativeVerificationAppleNotarized:
		return runtimeport.DesktopPublisherAppleNotarized, nil
	case runtimecatalog.NativeVerificationAuthenticode:
		return runtimeport.DesktopPublisherAuthenticode, nil
	case runtimecatalog.NativeVerificationPackageSignature:
	}
	return "", runtimeport.ErrDesktopAuthorityIntegrity
}

func desktopFixedAuthority(
	platform runtimeinstall.Platform,
	userName string,
	homeDirectory string,
) (string, string, string, string, []string) {
	if platform == runtimeinstall.PlatformDarwin {
		return "/Applications/Docker.app", "/Applications/Docker.app/Contents/MacOS/Docker Desktop",
			"/Applications/Docker.app/Contents/Resources/bin/docker",
			"/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
			[]string{"--accept-license", "--user=" + userName}
	}
	root := homeDirectory + `\AppData\Local\Programs\DockerDesktop`
	return root, root + `\Docker Desktop.exe`, root + `\resources\bin\docker.exe`,
		root + `\resources\cli-plugins\docker-compose.exe`,
		[]string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"}
}
