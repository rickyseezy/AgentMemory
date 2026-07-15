package runtimecatalog

import "strings"

// DesktopExecutionPolicyInput is the signed macOS/Windows-only continuation
// authority needed to construct a complete Desktop runtime installer.
type DesktopExecutionPolicyInput struct {
	AcquisitionSafetyBytes uint64
	MinimumAvailableMemory uint64
	ArtifactFileName       string
	DockerCLISHA256        Digest
	ComposePluginSHA256    Digest
	ProbeImage             string
	ProbeImageDigest       Digest
	ProbeContractVersion   string
	CapabilityPolicyDigest Digest
	RollbackHeadroomBytes  uint64
	MinimumWSLVersion      string
	WindowsFeatures        []string
}

// DesktopExecutionPolicy is absent from Linux cells and immutable by value.
type DesktopExecutionPolicy struct {
	acquisitionSafetyBytes uint64
	minimumAvailableMemory uint64
	artifactFileName       string
	dockerCLISHA256        Digest
	composePluginSHA256    Digest
	probeImage             string
	probeImageDigest       Digest
	probeContractVersion   string
	capabilityPolicyDigest Digest
	rollbackHeadroomBytes  uint64
	minimumWSLVersion      string
	windowsFeatures        []string
}

func newDesktopExecutionPolicy(
	input DesktopExecutionPolicyInput,
	platform PlatformPolicy,
	artifact ArtifactPolicy,
	capabilities []CapabilityProbe,
) (DesktopExecutionPolicy, error) {
	if platform.operatingSystem != OSKindMacOS && platform.operatingSystem != OSKindWindows ||
		input.AcquisitionSafetyBytes == 0 || input.RollbackHeadroomBytes == 0 ||
		!validDesktopArtifactCapacity(input, artifact) ||
		input.MinimumAvailableMemory == 0 || input.MinimumAvailableMemory > platform.minimumMemoryBytes ||
		!validDesktopArtifactFileName(input.ArtifactFileName, platform.operatingSystem) ||
		input.DockerCLISHA256.IsZero() || input.ComposePluginSHA256.IsZero() ||
		input.DockerCLISHA256.Equal(input.ComposePluginSHA256) ||
		input.ProbeContractVersion != "1" || input.ProbeImageDigest.IsZero() ||
		input.ProbeImage != "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:"+input.ProbeImageDigest.Hex() ||
		!RuntimeCapabilityPolicyDigest(capabilities).Equal(input.CapabilityPolicyDigest) ||
		len(artifact.sources) != 1 ||
		platform.operatingSystem == OSKindMacOS && input.MinimumWSLVersion != "" ||
		platform.operatingSystem == OSKindMacOS && len(input.WindowsFeatures) != 0 ||
		platform.operatingSystem == OSKindWindows && (input.MinimumWSLVersion != "2.1.5" ||
			!slicesEqualStrings(input.WindowsFeatures, []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"})) {
		return DesktopExecutionPolicy{}, ErrManifestIntegrity
	}
	return DesktopExecutionPolicy{
		acquisitionSafetyBytes: input.AcquisitionSafetyBytes,
		minimumAvailableMemory: input.MinimumAvailableMemory, artifactFileName: input.ArtifactFileName,
		dockerCLISHA256: input.DockerCLISHA256, composePluginSHA256: input.ComposePluginSHA256,
		probeImage: input.ProbeImage, probeImageDigest: input.ProbeImageDigest,
		probeContractVersion:   input.ProbeContractVersion,
		capabilityPolicyDigest: input.CapabilityPolicyDigest, rollbackHeadroomBytes: input.RollbackHeadroomBytes,
		minimumWSLVersion: input.MinimumWSLVersion,
		windowsFeatures:   append([]string(nil), input.WindowsFeatures...),
	}, nil
}

func validDesktopArtifactCapacity(input DesktopExecutionPolicyInput, artifact ArtifactPolicy) bool {
	const maximumSafe = uint64(1<<53 - 1)
	values := []uint64{
		artifact.downloadBytes, artifact.expandedBytes,
		input.RollbackHeadroomBytes, input.AcquisitionSafetyBytes,
	}
	var required uint64
	for _, value := range values {
		if value > maximumSafe || required > maximumSafe-value {
			return false
		}
		required += value
	}
	return required == artifact.reserveBytes
}

func validDesktopArtifactFileName(value string, platform OSKind) bool {
	if value == "" || len(value) > 255 || value != strings.TrimSpace(value) ||
		strings.ContainsAny(value, "/\\?#%\x00\r\n") {
		return false
	}
	if platform == OSKindMacOS {
		return strings.HasSuffix(value, ".dmg")
	}
	return platform == OSKindWindows && strings.HasSuffix(value, ".exe")
}

func desktopExecutionInputZero(input DesktopExecutionPolicyInput) bool {
	return input.AcquisitionSafetyBytes == 0 && input.MinimumAvailableMemory == 0 &&
		input.ArtifactFileName == "" && input.ProbeImage == "" &&
		input.DockerCLISHA256.IsZero() && input.ComposePluginSHA256.IsZero() &&
		input.ProbeImageDigest.IsZero() && input.ProbeContractVersion == "" &&
		input.CapabilityPolicyDigest.IsZero() && input.RollbackHeadroomBytes == 0 &&
		input.MinimumWSLVersion == "" && len(input.WindowsFeatures) == 0
}

// AcquisitionSafetyBytes returns the signed post-install free-space floor.
func (p DesktopExecutionPolicy) AcquisitionSafetyBytes() uint64 { return p.acquisitionSafetyBytes }

// MinimumAvailableMemory returns the signed live-memory floor.
func (p DesktopExecutionPolicy) MinimumAvailableMemory() uint64 { return p.minimumAvailableMemory }

// ArtifactFileName returns the exact file below the single official source prefix.
func (p DesktopExecutionPolicy) ArtifactFileName() string { return p.artifactFileName }

// DockerCLISHA256 returns the exact installed Docker CLI content digest.
func (p DesktopExecutionPolicy) DockerCLISHA256() Digest { return p.dockerCLISHA256 }

// ComposePluginSHA256 returns the exact installed Compose plugin content digest.
func (p DesktopExecutionPolicy) ComposePluginSHA256() Digest { return p.composePluginSHA256 }

// ProbeImage returns the immutable active-probe OCI reference.
func (p DesktopExecutionPolicy) ProbeImage() string { return p.probeImage }

// ProbeImageDigest returns the exact active-probe OCI manifest digest.
func (p DesktopExecutionPolicy) ProbeImageDigest() Digest { return p.probeImageDigest }

// ProbeContractVersion returns the closed active-probe entrypoint contract.
func (p DesktopExecutionPolicy) ProbeContractVersion() string { return p.probeContractVersion }

// CapabilityPolicyDigest returns the complete active-probe policy binding.
func (p DesktopExecutionPolicy) CapabilityPolicyDigest() Digest { return p.capabilityPolicyDigest }

// RollbackHeadroomBytes returns the signed preserved rollback-generation capacity.
func (p DesktopExecutionPolicy) RollbackHeadroomBytes() uint64 { return p.rollbackHeadroomBytes }

// MinimumWSLVersion returns the Windows WSL floor or empty on macOS.
func (p DesktopExecutionPolicy) MinimumWSLVersion() string { return p.minimumWSLVersion }

// WindowsFeatures returns the exact Windows optional-feature set.
func (p DesktopExecutionPolicy) WindowsFeatures() []string {
	return append([]string(nil), p.windowsFeatures...)
}

func (p DesktopExecutionPolicy) valid(
	platform PlatformPolicy,
	artifact ArtifactPolicy,
	capabilities []CapabilityProbe,
) bool {
	validated, err := newDesktopExecutionPolicy(DesktopExecutionPolicyInput{
		AcquisitionSafetyBytes: p.acquisitionSafetyBytes,
		MinimumAvailableMemory: p.minimumAvailableMemory, ArtifactFileName: p.artifactFileName,
		DockerCLISHA256: p.dockerCLISHA256, ComposePluginSHA256: p.composePluginSHA256,
		ProbeImage: p.probeImage, ProbeImageDigest: p.probeImageDigest,
		ProbeContractVersion: p.probeContractVersion, CapabilityPolicyDigest: p.capabilityPolicyDigest,
		RollbackHeadroomBytes: p.rollbackHeadroomBytes, MinimumWSLVersion: p.minimumWSLVersion,
		WindowsFeatures: append([]string(nil), p.windowsFeatures...),
	}, platform, artifact, capabilities)
	return err == nil && validated.acquisitionSafetyBytes == p.acquisitionSafetyBytes &&
		validated.minimumAvailableMemory == p.minimumAvailableMemory &&
		validated.artifactFileName == p.artifactFileName && validated.probeImage == p.probeImage &&
		validated.dockerCLISHA256 == p.dockerCLISHA256 &&
		validated.composePluginSHA256 == p.composePluginSHA256 &&
		validated.probeImageDigest == p.probeImageDigest && validated.probeContractVersion == p.probeContractVersion &&
		validated.capabilityPolicyDigest == p.capabilityPolicyDigest &&
		validated.rollbackHeadroomBytes == p.rollbackHeadroomBytes &&
		validated.minimumWSLVersion == p.minimumWSLVersion &&
		slicesEqualStrings(validated.windowsFeatures, p.windowsFeatures)
}

// RuntimeCapabilityPolicyDigest binds any sorted platform active-probe contract.
func RuntimeCapabilityPolicyDigest(capabilities []CapabilityProbe) Digest {
	return LinuxCapabilityPolicyDigest(capabilities)
}
