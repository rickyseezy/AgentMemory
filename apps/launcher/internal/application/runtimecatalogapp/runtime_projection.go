package runtimecatalogapp

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// CertifiedRuntime projects verified catalog authority into the existing PF-006
// plan policy. An unverified or zero catalog cannot create this projection.
func (c VerifiedCatalog) CertifiedRuntime() (runtimeinstall.CertifiedRuntime, error) {
	if !c.manifest.Valid() || c.verifiedAt.IsZero() {
		return runtimeinstall.CertifiedRuntime{}, errors.New("verified runtime catalog is invalid")
	}
	platform, architecture, err := runtimeTarget(c.manifest.Platform())
	if err != nil {
		return runtimeinstall.CertifiedRuntime{}, err
	}
	manifestDigest := runtimeinstall.Hash(c.manifest.Digest())
	termsDigest := runtimeinstall.Hash(c.manifest.Terms().Digest())
	return runtimeinstall.NewCertifiedRuntime(
		platform,
		architecture,
		string(c.manifest.Runtime().Product()),
		c.manifest.Runtime().Version(),
		string(c.manifest.Runtime().Channel()),
		c.manifest.CatalogSequence(),
		manifestDigest,
		termsDigest,
		c.manifest.Artifact().DownloadBytes(),
		c.manifest.Artifact().ExpandedBytes(),
	)
}

func runtimeTarget(
	platform runtimecatalog.PlatformPolicy,
) (runtimeinstall.Platform, runtimeinstall.Architecture, error) {
	var targetPlatform runtimeinstall.Platform
	switch platform.OperatingSystem() {
	case runtimecatalog.OSKindMacOS:
		targetPlatform = runtimeinstall.PlatformDarwin
	case runtimecatalog.OSKindLinux:
		targetPlatform = runtimeinstall.PlatformLinux
	case runtimecatalog.OSKindWindows:
		targetPlatform = runtimeinstall.PlatformWindows
	default:
		return runtimeinstall.PlatformUnknown, runtimeinstall.ArchitectureUnknown,
			errors.New("verified runtime platform is unsupported")
	}
	var targetArchitecture runtimeinstall.Architecture
	switch platform.Architecture() {
	case runtimecatalog.ArchitectureARM64:
		targetArchitecture = runtimeinstall.ArchitectureARM64
	case runtimecatalog.ArchitectureX8664:
		targetArchitecture = runtimeinstall.ArchitectureAMD64
	default:
		return runtimeinstall.PlatformUnknown, runtimeinstall.ArchitectureUnknown,
			errors.New("verified runtime architecture is unsupported")
	}
	return targetPlatform, targetArchitecture, nil
}
