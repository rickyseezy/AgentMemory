package runtimecatalogapp

import (
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// LinuxArtifactPlan projects the exact package artifacts from an already
// verified catalog into the common reserve-before-download CAS protocol.
func (c VerifiedCatalog) LinuxArtifactPlan(
	authority runtimeport.LinuxAuthority,
) (artifactacquisition.Plan, error) {
	if !c.manifest.Valid() || c.verifiedAt.IsZero() || !authority.Valid() ||
		authority.CatalogDigest() != runtimeinstall.Hash(c.manifest.Digest()) ||
		authority.TermsDigest() != runtimeinstall.Hash(c.manifest.Terms().Digest()) {
		return artifactacquisition.Plan{}, errors.New("verified Linux artifact authority is unavailable")
	}
	execution, present := c.manifest.LinuxExecution()
	if !present || authority.ArtifactDigest() != runtimeinstall.Hash(execution.PackageSetDigest()) ||
		!linuxAuthorityPackageSetMatches(execution.Packages(), authority.Packages()) {
		return artifactacquisition.Plan{}, errors.New("verified Linux artifact authority is invalid")
	}
	verification := execution.Repository().VerificationArtifacts()
	artifacts := make([]artifactacquisition.ArtifactInput, 0, len(verification)+len(execution.Packages()))
	for _, resource := range verification {
		digest := releaseinventory.Digest(resource.SHA256())
		artifacts = append(artifacts, artifactacquisition.ArtifactInput{
			ID: "repo-" + string(resource.Role()), Digest: digest, Size: resource.DownloadBytes(),
			Sources: []string{catalogSourceURL(resource.Source())},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: resource.DownloadBytes(), Digest: digest}},
		})
	}
	for _, pkg := range execution.Packages() {
		digest := releaseinventory.Digest(pkg.SHA256())
		artifacts = append(artifacts, artifactacquisition.ArtifactInput{
			ID: pkg.Name(), Digest: digest, Size: pkg.DownloadBytes(),
			Sources: []string{catalogSourceURL(pkg.Source())},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: pkg.DownloadBytes(), Digest: digest}},
		})
	}
	download := c.manifest.Artifact().DownloadBytes()
	required, overflow := checkedArtifactCapacity(
		download, execution.RollbackHeadroomBytes(), execution.AcquisitionSafetyBytes(),
	)
	if overflow || required != c.manifest.Artifact().ReserveBytes() {
		return artifactacquisition.Plan{}, errors.New("verified Linux artifact capacity is invalid")
	}
	return artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		// The signed catalog digest binds the exact packages and every retained
		// repository trust-chain input. The package-set digest alone would permit
		// distinct metadata snapshots to share an acquisition identity.
		PlanDigest: releaseinventory.Digest(c.manifest.Digest()),
		Artifacts:  artifacts,
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: download, ExpandedBytes: 0,
			RollbackHeadroomBytes: execution.RollbackHeadroomBytes(),
			SafetyHeadroomBytes:   execution.AcquisitionSafetyBytes(), RequiredBytes: required,
		},
	})
}

func linuxAuthorityPackageSetMatches(
	catalogPackages []runtimecatalog.LinuxPackage,
	authorityPackages []runtimeport.Package,
) bool {
	if len(catalogPackages) != len(authorityPackages) {
		return false
	}
	for index := range catalogPackages {
		catalogPackage := catalogPackages[index]
		authorityPackage := authorityPackages[index]
		if catalogPackage.Name() != authorityPackage.Name() ||
			catalogPackage.Version() != authorityPackage.Version() ||
			runtimeinstall.Hash(catalogPackage.NativeReceiptDigest()) != authorityPackage.NativeReceiptDigest() {
			return false
		}
	}
	return true
}

func checkedArtifactCapacity(values ...uint64) (uint64, bool) {
	const maximumSafe = uint64(1<<53 - 1)
	var total uint64
	for _, value := range values {
		if value > maximumSafe || total > maximumSafe-value {
			return 0, true
		}
		total += value
	}
	return total, false
}

func catalogSourceURL(source runtimecatalog.SourceLocation) string {
	return source.Scheme() + "://" + source.Host() + source.PathPrefix()
}
