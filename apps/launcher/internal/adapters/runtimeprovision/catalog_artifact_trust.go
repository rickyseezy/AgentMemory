package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// CatalogLinuxArtifactVerifier authenticates every retained native repository
// and package through the package manager's publisher trust chain. It receives
// no filesystem path and performs no privileged operation.
type CatalogLinuxArtifactVerifier struct {
	catalog runtimecatalogapp.VerifiedCatalog
	reader  artifactapp.VerifiedFinalReader
	clock   runtimeport.Clock
	rpm     rpmPackageSignatureVerifier
}

// NewCatalogLinuxArtifactVerifier constructs the production CAS-to-native-
// trust adapter from an already signature-verified catalog.
func NewCatalogLinuxArtifactVerifier(
	catalog runtimecatalogapp.VerifiedCatalog,
	reader artifactapp.VerifiedFinalReader,
	clock runtimeport.Clock,
) (*CatalogLinuxArtifactVerifier, error) {
	verifier, err := newCatalogLinuxArtifactVerifier(catalog, reader, clock, nil)
	if err != nil {
		return nil, err
	}
	execution, _ := catalog.Manifest().LinuxExecution()
	if execution.PackageManager() == runtimecatalog.LinuxPackageManagerDNF {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	return verifier, nil
}

// NewCatalogLinuxArtifactVerifierWithRPMKeys constructs the DNF verifier with
// mandatory isolated native RPM package-signature authentication.
func NewCatalogLinuxArtifactVerifierWithRPMKeys(
	catalog runtimecatalogapp.VerifiedCatalog,
	reader artifactapp.VerifiedFinalReader,
	clock runtimeport.Clock,
	rpm rpmPackageSignatureVerifier,
) (*CatalogLinuxArtifactVerifier, error) {
	if nilArtifactDependency(rpm) {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	verifier, err := newCatalogLinuxArtifactVerifier(catalog, reader, clock, rpm)
	if err != nil {
		return nil, err
	}
	execution, _ := catalog.Manifest().LinuxExecution()
	if execution.PackageManager() != runtimecatalog.LinuxPackageManagerDNF {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	return verifier, nil
}

func newCatalogLinuxArtifactVerifier(
	catalog runtimecatalogapp.VerifiedCatalog,
	reader artifactapp.VerifiedFinalReader,
	clock runtimeport.Clock,
	rpm rpmPackageSignatureVerifier,
) (*CatalogLinuxArtifactVerifier, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() ||
		nilArtifactDependency(reader) || nilArtifactDependency(clock) {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	if _, present := catalog.Manifest().LinuxExecution(); !present {
		return nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	return &CatalogLinuxArtifactVerifier{catalog: catalog, reader: reader, clock: clock, rpm: rpm}, nil
}

// VerifyLinuxArtifacts reopens the complete catalog-bound CAS set and proves
// repository signatures, metadata-to-index hashes, and index-to-package
// checksums before any elevation can occur.
func (v *CatalogLinuxArtifactVerifier) VerifyLinuxArtifacts(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (runtimeport.LinuxArtifactEvidence, error) {
	if v == nil || ctx == nil || !authority.Valid() || !v.catalog.Manifest().Valid() ||
		nilArtifactDependency(v.reader) || nilArtifactDependency(v.clock) {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.LinuxArtifactEvidence{}, err
	}
	plan, err := v.catalog.LinuxArtifactPlan(authority)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	retained, resources, err := v.readAndBindLinuxArtifacts(ctx, plan)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, err
	}
	execution, present := v.catalog.Manifest().LinuxExecution()
	if !present {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	now := v.clock.Now()
	if now.Location() != time.UTC {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	if err = v.verifyLinuxRepositories(ctx, plan, execution, resources, now); err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	repositoryState, err := runtimeport.ExpectedRepositoryStateDigest(authority)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	packageState, err := runtimeport.ExpectedPackageStateDigest(authority)
	if err != nil {
		return runtimeport.LinuxArtifactEvidence{}, runtimeport.ErrLinuxArtifactIntegrity
	}
	return runtimeport.NewLinuxArtifactEvidence(runtimeport.LinuxArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), ArtifactDigest: authority.ArtifactDigest(),
		RepositoryStateDigest: repositoryState, PackageStateDigest: packageState,
		RetainedSetDigest: retained, EveryPackageAcquired: true,
		RepositoryAuthenticated: true, PackagesAuthenticated: true,
	})
}

func (v *CatalogLinuxArtifactVerifier) readAndBindLinuxArtifacts(
	ctx context.Context,
	plan artifactacquisition.Plan,
) (runtimeinstall.Hash, map[string][]byte, error) {
	verified := make([]artifactapp.VerifiedArtifact, 0, len(plan.Artifacts()))
	resources := make(map[string][]byte)
	for _, artifact := range plan.Artifacts() {
		reader, err := v.reader.OpenFinal(ctx, artifact)
		if err != nil {
			return runtimeinstall.Hash{}, nil, mapLinuxArtifactReadError(ctx, err)
		}
		if len(artifact.ID()) >= 5 && artifact.ID()[:5] == "repo-" {
			limit := int64(artifact.Size()) + 1 // #nosec G115 -- Plan validation caps size at 2^53-1.
			value, readError := io.ReadAll(io.LimitReader(reader, limit))
			closeError := reader.Close()
			if readError != nil || closeError != nil || uint64(len(value)) != artifact.Size() {
				return runtimeinstall.Hash{}, nil, runtimeport.ErrLinuxArtifactIntegrity
			}
			resources[artifact.ID()] = value
		} else {
			readBytes, readError := io.Copy(io.Discard, reader)
			closeError := reader.Close()
			if readError != nil || closeError != nil || readBytes < 0 || uint64(readBytes) != artifact.Size() {
				return runtimeinstall.Hash{}, nil, runtimeport.ErrLinuxArtifactIntegrity
			}
		}
		verified = append(verified, artifactapp.VerifiedArtifact{
			ID: artifact.ID(), Digest: artifact.Digest(), Size: artifact.Size(), ContentKey: artifact.ContentKey(),
		})
	}
	completed := uint32(len(verified)) // #nosec G115 -- Plan validation caps artifacts at 4096.
	retained, err := retainedLinuxArtifactDigest(plan, artifactapp.AcquireResult{
		CompletedArtifacts: completed, VerifiedArtifacts: verified,
	})
	if err != nil {
		return runtimeinstall.Hash{}, nil, runtimeport.ErrLinuxArtifactIntegrity
	}
	return retained, resources, nil
}

func (v *CatalogLinuxArtifactVerifier) verifyLinuxRepositories(
	ctx context.Context,
	plan artifactacquisition.Plan,
	execution runtimecatalog.LinuxExecutionPolicy,
	resources map[string][]byte,
	now time.Time,
) error {
	repositories := append([]runtimecatalog.LinuxRepository{execution.Repository()}, execution.VerificationRepositories()...)
	architecture, present := nativeLinuxPackageArchitecture(
		execution.PackageManager(), v.catalog.Manifest().Platform().Architecture(),
	)
	if !present {
		return runtimeport.ErrLinuxArtifactIntegrity
	}
	for _, repository := range repositories {
		packages := linuxPackagesForRepository(execution.Packages(), repository.ID())
		indexArtifact, indexPresent := repositoryArtifactByRole(
			repository, runtimecatalog.LinuxRepositoryArtifactPackageIndex,
		)
		if !indexPresent {
			return runtimeport.ErrLinuxArtifactIntegrity
		}
		key := resources[linuxRepositoryArtifactID(repository, runtimecatalog.LinuxRepositoryArtifactSigningKey)]
		metadata := resources[linuxRepositoryArtifactID(repository, runtimecatalog.LinuxRepositoryArtifactSignedMetadata)]
		index := resources[linuxRepositoryArtifactID(repository, runtimecatalog.LinuxRepositoryArtifactPackageIndex)]
		switch execution.PackageManager() {
		case runtimecatalog.LinuxPackageManagerAPT:
			if verifyAPTRepositoryTrust(aptRepositoryTrustInput{
				Now: now, Architecture: architecture,
				Repository: aptRepositoryExpectation{
					ID: repository.ID(), BasePath: repository.URL().PathPrefix(), Suite: repository.Suite(),
					Component: repository.Component(), SigningKeyFingerprint: repository.SigningKeyFingerprint(),
					Index: aptArtifactExpectation{
						Path: indexArtifact.Source().PathPrefix(), Size: indexArtifact.DownloadBytes(),
						SHA256: indexArtifact.SHA256().Hex(),
					},
				},
				Packages:   aptPackageExpectations(packages),
				SigningKey: key, InRelease: metadata, PackageIndex: index,
			}) != nil {
				return runtimeport.ErrLinuxArtifactIntegrity
			}
		case runtimecatalog.LinuxPackageManagerDNF:
			if nilArtifactDependency(v.rpm) {
				return runtimeport.ErrLinuxArtifactIntegrity
			}
			signature := resources[linuxRepositoryArtifactID(
				repository, runtimecatalog.LinuxRepositoryArtifactMetadataSignature,
			)]
			if verifyDNFRepositoryTrust(dnfRepositoryTrustInput{
				Now: now, Architecture: architecture,
				Repository: dnfRepositoryExpectation{
					ID: repository.ID(), BasePath: repository.URL().PathPrefix(),
					SigningKeyFingerprint:  repository.SigningKeyFingerprint(),
					MetadataAuthentication: string(repository.MetadataAuthentication()),
					Index: aptArtifactExpectation{
						Path: indexArtifact.Source().PathPrefix(), Size: indexArtifact.DownloadBytes(),
						SHA256: indexArtifact.SHA256().Hex(),
					},
				},
				Packages: dnfPackageExpectations(packages), SigningKey: key,
				RepositoryMetadata: metadata, MetadataSignature: signature, PackageIndex: index,
			}) != nil || v.verifyRPMPackages(ctx, plan, repository, packages, key) != nil {
				return runtimeport.ErrLinuxArtifactIntegrity
			}
		default:
			return runtimeport.ErrLinuxArtifactIntegrity
		}
	}
	return nil
}

func (v *CatalogLinuxArtifactVerifier) verifyRPMPackages(
	ctx context.Context,
	plan artifactacquisition.Plan,
	repository runtimecatalog.LinuxRepository,
	packages []runtimecatalog.LinuxPackage,
	key []byte,
) error {
	for _, pkg := range packages {
		artifact, present := linuxArtifactByID(plan, pkg.Name())
		if !present {
			return runtimeport.ErrLinuxArtifactIntegrity
		}
		reader, err := v.reader.OpenFinal(ctx, artifact)
		if err != nil {
			return mapLinuxArtifactReadError(ctx, err)
		}
		verifyError := v.rpm.VerifyRPMPackage(
			ctx, key, repository.SigningKeyFingerprint(), artifact, reader,
		)
		closeError := reader.Close()
		if verifyError != nil || closeError != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return runtimeport.ErrLinuxArtifactIntegrity
		}
	}
	return nil
}

func linuxArtifactByID(plan artifactacquisition.Plan, id string) (artifactacquisition.Artifact, bool) {
	for _, artifact := range plan.Artifacts() {
		if artifact.ID() == id {
			return artifact, true
		}
	}
	return artifactacquisition.Artifact{}, false
}

func repositoryArtifactByRole(
	repository runtimecatalog.LinuxRepository,
	role runtimecatalog.LinuxRepositoryArtifactRole,
) (runtimecatalog.LinuxRepositoryArtifact, bool) {
	for _, artifact := range repository.VerificationArtifacts() {
		if artifact.Role() == role {
			return artifact, true
		}
	}
	return runtimecatalog.LinuxRepositoryArtifact{}, false
}

func aptPackageExpectations(packages []runtimecatalog.LinuxPackage) []aptPackageExpectation {
	result := make([]aptPackageExpectation, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, aptPackageExpectation{
			Name: pkg.Name(), Version: pkg.Version(), RepositoryID: pkg.RepositoryID(),
			Path: pkg.Source().PathPrefix(), Size: pkg.DownloadBytes(), SHA256: pkg.SHA256().Hex(),
		})
	}
	return result
}

func dnfPackageExpectations(packages []runtimecatalog.LinuxPackage) []dnfPackageExpectation {
	result := make([]dnfPackageExpectation, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, dnfPackageExpectation{
			Name: pkg.Name(), Version: pkg.Version(), RepositoryID: pkg.RepositoryID(),
			Path: pkg.Source().PathPrefix(), Size: pkg.DownloadBytes(), SHA256: pkg.SHA256().Hex(),
		})
	}
	return result
}

func linuxRepositoryArtifactID(
	repository runtimecatalog.LinuxRepository,
	role runtimecatalog.LinuxRepositoryArtifactRole,
) string {
	return "repo-" + repository.ID() + "-" + string(role)
}

func linuxPackagesForRepository(
	packages []runtimecatalog.LinuxPackage,
	repositoryID string,
) []runtimecatalog.LinuxPackage {
	result := make([]runtimecatalog.LinuxPackage, 0, len(packages))
	for _, pkg := range packages {
		if pkg.RepositoryID() == repositoryID {
			result = append(result, pkg)
		}
	}
	return result
}

func nativeLinuxPackageArchitecture(
	manager runtimecatalog.LinuxPackageManager,
	architecture runtimecatalog.Architecture,
) (string, bool) {
	switch architecture {
	case runtimecatalog.ArchitectureX8664:
		if manager == runtimecatalog.LinuxPackageManagerAPT {
			return "amd64", true
		}
		return "x86_64", manager == runtimecatalog.LinuxPackageManagerDNF
	case runtimecatalog.ArchitectureARM64:
		if manager == runtimecatalog.LinuxPackageManagerAPT {
			return "arm64", true
		}
		return "aarch64", manager == runtimecatalog.LinuxPackageManagerDNF
	default:
		return "", false
	}
}

func mapLinuxArtifactReadError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, artifactapp.ErrArtifactNotFound) || errors.Is(err, artifactapp.ErrStoreOperation) {
		return runtimeport.ErrLinuxArtifactUnavailable
	}
	return runtimeport.ErrLinuxArtifactIntegrity
}
