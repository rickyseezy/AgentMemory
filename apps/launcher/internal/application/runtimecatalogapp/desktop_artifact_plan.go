package runtimecatalogapp

import (
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const desktopInstallerArtifactID = "docker-desktop-installer"

// DesktopArtifactPlan projects the exact signed Docker Desktop installer into
// the common reserve-before-download CAS protocol. Installer expansion remains
// host capacity, not a CAS expanded target, so the CAS plan contains only the
// retained installer plus its signed acquisition headroom.
func (c VerifiedCatalog) DesktopArtifactPlan(
	authority runtimeport.DesktopAuthority,
) (artifactacquisition.Plan, error) {
	if !c.manifest.Valid() || c.verifiedAt.IsZero() || !authority.Valid() ||
		authority.CatalogDigest() != runtimeinstall.Hash(c.manifest.Digest()) ||
		authority.Terms().Digest() != runtimeinstall.Hash(c.manifest.Terms().Digest()) {
		return artifactacquisition.Plan{}, errors.New("verified desktop artifact authority is unavailable")
	}
	execution, present := c.manifest.DesktopExecution()
	artifact := c.manifest.Artifact()
	if !present || authority.ArtifactSHA256() != runtimeinstall.Hash(artifact.SHA256()) ||
		authority.ArtifactBytes() != artifact.DownloadBytes() ||
		authority.ArtifactSourceURL() != catalogSourceURL(artifact.Sources()[0])+execution.ArtifactFileName() {
		return artifactacquisition.Plan{}, errors.New("verified desktop artifact authority is invalid")
	}
	acquisitionRequired, overflow := checkedArtifactCapacity(
		artifact.DownloadBytes(), execution.RollbackHeadroomBytes(), execution.AcquisitionSafetyBytes(),
	)
	overallRequired, overallOverflow := checkedArtifactCapacity(acquisitionRequired, artifact.ExpandedBytes())
	if overflow || overallOverflow || overallRequired != artifact.ReserveBytes() {
		return artifactacquisition.Plan{}, errors.New("verified desktop artifact capacity is invalid")
	}
	digest := releaseinventory.Digest(artifact.SHA256())
	return artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.Digest(c.manifest.Digest()),
		ProxyMode:  artifactacquisition.ProxyMode(artifact.ProxyMode()),
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: desktopInstallerArtifactID, Digest: digest, Size: artifact.DownloadBytes(),
			Sources: []string{authority.ArtifactSourceURL()},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: artifact.DownloadBytes(), Digest: digest}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: artifact.DownloadBytes(), ExpandedBytes: 0,
			RollbackHeadroomBytes: execution.RollbackHeadroomBytes(),
			SafetyHeadroomBytes:   execution.AcquisitionSafetyBytes(),
			RequiredBytes:         acquisitionRequired,
		},
	})
}
