package runtimeprovision

import runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"

// DesktopArtifactVerifierDependencies are the release-bound provenance and
// platform-specific signer authorities required by native verification.
type DesktopArtifactVerifierDependencies struct {
	Provenance    runtimeport.DesktopArtifactAcquirer
	WindowsSigner runtimeport.DesktopWindowsSignerIdentityVerifier
}

// DesktopHostProbeDependencies supplies platform-native security evidence.
type DesktopHostProbeDependencies struct {
	WindowsEncryption runtimeport.DesktopWindowsEncryptionAttestor
}

// DesktopInstalledApplicationProbeDependencies supplies the platform-specific
// exact signer authority needed for installed Docker Desktop discovery.
type DesktopInstalledApplicationProbeDependencies struct {
	WindowsSigner runtimeport.DesktopWindowsApplicationSignerIdentityVerifier
}
