package runtimecatalog

import "strings"

// DesktopExecutionPolicyInput is the signed macOS/Windows-only continuation
// authority needed to construct a complete Desktop runtime installer.
type DesktopExecutionPolicyInput struct {
	MinimumAvailableMemory uint64
	ArtifactFileName       string
	ProbeImage             string
	ProbeImageDigest       Digest
	ProbeContractVersion   string
	CapabilityPolicyDigest Digest
	MinimumWSLVersion      string
	WindowsFeatures        []string
}

// DesktopExecutionPolicy is absent from Linux cells and immutable by value.
type DesktopExecutionPolicy struct {
	minimumAvailableMemory uint64
	artifactFileName       string
	probeImage             string
	probeImageDigest       Digest
	probeContractVersion   string
	capabilityPolicyDigest Digest
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
		input.MinimumAvailableMemory == 0 || input.MinimumAvailableMemory > platform.minimumMemoryBytes ||
		!validDesktopArtifactFileName(input.ArtifactFileName, platform.operatingSystem) ||
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
		minimumAvailableMemory: input.MinimumAvailableMemory, artifactFileName: input.ArtifactFileName,
		probeImage: input.ProbeImage, probeImageDigest: input.ProbeImageDigest,
		probeContractVersion:   input.ProbeContractVersion,
		capabilityPolicyDigest: input.CapabilityPolicyDigest, minimumWSLVersion: input.MinimumWSLVersion,
		windowsFeatures: append([]string(nil), input.WindowsFeatures...),
	}, nil
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
	return input.MinimumAvailableMemory == 0 && input.ArtifactFileName == "" && input.ProbeImage == "" &&
		input.ProbeImageDigest.IsZero() && input.ProbeContractVersion == "" &&
		input.CapabilityPolicyDigest.IsZero() && input.MinimumWSLVersion == "" && len(input.WindowsFeatures) == 0
}

// MinimumAvailableMemory returns the signed live-memory floor.
func (p DesktopExecutionPolicy) MinimumAvailableMemory() uint64 { return p.minimumAvailableMemory }

// ArtifactFileName returns the exact file below the single official source prefix.
func (p DesktopExecutionPolicy) ArtifactFileName() string { return p.artifactFileName }

// ProbeImage returns the immutable active-probe OCI reference.
func (p DesktopExecutionPolicy) ProbeImage() string { return p.probeImage }

// ProbeImageDigest returns the exact active-probe OCI manifest digest.
func (p DesktopExecutionPolicy) ProbeImageDigest() Digest { return p.probeImageDigest }

// ProbeContractVersion returns the closed active-probe entrypoint contract.
func (p DesktopExecutionPolicy) ProbeContractVersion() string { return p.probeContractVersion }

// CapabilityPolicyDigest returns the complete active-probe policy binding.
func (p DesktopExecutionPolicy) CapabilityPolicyDigest() Digest { return p.capabilityPolicyDigest }

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
		MinimumAvailableMemory: p.minimumAvailableMemory, ArtifactFileName: p.artifactFileName,
		ProbeImage: p.probeImage, ProbeImageDigest: p.probeImageDigest,
		ProbeContractVersion: p.probeContractVersion, CapabilityPolicyDigest: p.capabilityPolicyDigest,
		MinimumWSLVersion: p.minimumWSLVersion, WindowsFeatures: append([]string(nil), p.windowsFeatures...),
	}, platform, artifact, capabilities)
	return err == nil && validated.minimumAvailableMemory == p.minimumAvailableMemory &&
		validated.artifactFileName == p.artifactFileName && validated.probeImage == p.probeImage &&
		validated.probeImageDigest == p.probeImageDigest && validated.probeContractVersion == p.probeContractVersion &&
		validated.capabilityPolicyDigest == p.capabilityPolicyDigest && validated.minimumWSLVersion == p.minimumWSLVersion &&
		slicesEqualStrings(validated.windowsFeatures, p.windowsFeatures)
}

// RuntimeCapabilityPolicyDigest binds any sorted platform active-probe contract.
func RuntimeCapabilityPolicyDigest(capabilities []CapabilityProbe) Digest {
	return LinuxCapabilityPolicyDigest(capabilities)
}
