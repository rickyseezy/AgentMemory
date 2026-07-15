package nativepackage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const (
	maximumInstalledDistributionBytes = 32 * 1024 * 1024
	maximumInstalledExecutableBytes   = int64(512 * 1024 * 1024)
)

// ErrInstalledProductIntegrity is the sanitized postcondition failure.
var ErrInstalledProductIntegrity = errors.New("installed native product integrity failed")

// InstalledLayout contains only package-manager-owned fixed locations.
type InstalledLayout struct {
	Launcher             string
	RuntimeHelper        string
	DistributionEnvelope string
}

type installedFileAuthority struct {
	digest releaseinventory.Digest
	size   uint64
}

type installedDistributionAuthority struct {
	releaseID      string
	version        string
	buildID        string
	sourceCommit   string
	buildTimestamp time.Time
	launcher       installedFileAuthority
	runtimeHelper  installedFileAuthority
}

type distributionAuthorityDecoder func(
	[]byte,
	string,
	string,
) (installedDistributionAuthority, error)

type installedDistributionManifest interface {
	ReleaseID() string
	Version() string
	BuildID() string
	SourceCommit() string
	BuildTimestamp() time.Time
	ResourcesFor(releaseinventory.Platform) ([]releaseinventory.Resource, error)
}

// InstalledProductVerifier proves that the native transaction materialized
// the exact publication-bound distribution and its exact launcher/helper
// resources at package-manager-owned locations.
type InstalledProductVerifier struct {
	layout          InstalledLayout
	operatingSystem string
	architecture    string
	decode          distributionAuthorityDecoder
}

// NewInstalledProductVerifier is injectable for certified platform tests.
func NewInstalledProductVerifier(
	layout InstalledLayout,
	operatingSystem string,
	architecture string,
	decode distributionAuthorityDecoder,
) (*InstalledProductVerifier, error) {
	if !validPlatformCell(operatingSystem, architecture) || decode == nil || !validInstalledLayout(layout) {
		return nil, ErrInstalledProductIntegrity
	}
	return &InstalledProductVerifier{
		layout: layout, operatingSystem: operatingSystem, architecture: architecture, decode: decode,
	}, nil
}

// NewNativeInstalledProductVerifier selects only compile-time platform-owned
// locations; environment variables and working directories are not consulted.
func NewNativeInstalledProductVerifier() (*InstalledProductVerifier, error) {
	layout, err := nativeInstalledLayout()
	if err != nil {
		return nil, ErrInstalledProductIntegrity
	}
	return NewInstalledProductVerifier(layout, runtimeOS(), runtimeArchitecture(), decodeInstalledDistribution)
}

// NativeInstalledReleaseBundleRoot returns the package-manager-owned retained
// release root for the compile-time platform. It derives the root from the
// same installed postcondition layout instead of executable location, PATH,
// environment variables, or the current working directory.
func NativeInstalledReleaseBundleRoot() (string, error) {
	layout, err := nativeInstalledLayout()
	if err != nil || !validInstalledLayout(layout) {
		return "", ErrInstalledProductIntegrity
	}
	root := filepath.Dir(filepath.Dir(layout.DistributionEnvelope))
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", ErrInstalledProductIntegrity
	}
	return root, nil
}

// VerifyInstalled proves the exact installed manifest and both executable
// bytes, then cross-binds inner and outer release identity.
func (v *InstalledProductVerifier) VerifyInstalled(
	ctx context.Context,
	publication releasepublication.Publication,
	artifact releasepublication.Artifact,
) error {
	if v == nil || ctx == nil || v.decode == nil || !validInstalledLayout(v.layout) ||
		publication.SchemaVersion() != releasepublication.SupportedSchemaMajor ||
		artifact.Kind() != releasepublication.ArtifactKindNativePackage ||
		artifact.OperatingSystem() != v.operatingSystem || artifact.Architecture() != v.architecture {
		return ErrInstalledProductIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := readExactInstalledFile(
		v.layout.DistributionEnvelope,
		installedFileAuthority{
			digest: publication.DistributionEnvelopeDigest(), size: publication.DistributionEnvelopeSize(),
		},
		maximumInstalledDistributionBytes,
	)
	if err != nil {
		return ErrInstalledProductIntegrity
	}
	authority, err := v.decode(raw, v.operatingSystem, v.architecture)
	clear(raw)
	if err != nil || authority.releaseID != publication.ReleaseID() || authority.version != publication.Version() ||
		authority.buildID != publication.BuildID() || authority.sourceCommit != publication.SourceCommit() ||
		!authority.buildTimestamp.Equal(publication.BuildTimestamp()) ||
		!authority.launcher.valid() || !authority.runtimeHelper.valid() ||
		authority.launcher.digest.Equal(authority.runtimeHelper.digest) {
		return ErrInstalledProductIntegrity
	}
	if _, err := readExactInstalledFile(v.layout.Launcher, authority.launcher, maximumInstalledExecutableBytes); err != nil {
		return ErrInstalledProductIntegrity
	}
	if _, err := readExactInstalledFile(v.layout.RuntimeHelper, authority.runtimeHelper, maximumInstalledExecutableBytes); err != nil {
		return ErrInstalledProductIntegrity
	}
	return ctx.Err()
}

func (a installedFileAuthority) valid() bool { return !a.digest.IsZero() && a.size > 0 }

func validInstalledLayout(layout InstalledLayout) bool {
	values := []string{layout.Launcher, layout.RuntimeHelper, layout.DistributionEnvelope}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func readExactInstalledFile(
	path string,
	authority installedFileAuthority,
	maximum int64,
) ([]byte, error) {
	if path == "" || !authority.valid() || maximum <= 0 || authority.size > uint64(maximum) {
		return nil, ErrInstalledProductIntegrity
	}
	info, err := os.Lstat(path)
	// #nosec G115 -- authority.size is proven at most the positive int64 maximum above.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() != int64(authority.size) {
		return nil, ErrInstalledProductIntegrity
	}
	// #nosec G304 -- path is constructor-validated fixed package-manager authority.
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInstalledProductIntegrity
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrInstalledProductIntegrity
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) != info.Size() ||
		!releaseinventory.DigestBytes(content).Equal(authority.digest) {
		return nil, ErrInstalledProductIntegrity
	}
	return content, nil
}

func decodeInstalledDistribution(
	raw []byte,
	operatingSystem string,
	architecture string,
) (installedDistributionAuthority, error) {
	signed, err := releaseinventory.DecodeSignedManifestV1(raw)
	if err != nil {
		return installedDistributionAuthority{}, ErrInstalledProductIntegrity
	}
	return projectInstalledDistribution(signed.Manifest(), operatingSystem, architecture)
}

func projectInstalledDistribution(
	manifest installedDistributionManifest,
	operatingSystem string,
	architecture string,
) (installedDistributionAuthority, error) {
	if manifest == nil {
		return installedDistributionAuthority{}, ErrInstalledProductIntegrity
	}
	platform, err := releaseinventory.NewPlatform(operatingSystem, architecture)
	if err != nil || platform.IsAny() {
		return installedDistributionAuthority{}, ErrInstalledProductIntegrity
	}
	resources, err := manifest.ResourcesFor(platform)
	if err != nil {
		return installedDistributionAuthority{}, ErrInstalledProductIntegrity
	}
	authority := installedDistributionAuthority{
		releaseID: manifest.ReleaseID(), version: manifest.Version(),
		buildID: manifest.BuildID(), sourceCommit: manifest.SourceCommit(),
		buildTimestamp: manifest.BuildTimestamp(),
	}
	for _, resource := range resources {
		target := (*installedFileAuthority)(nil)
		switch resource.Kind() { //nolint:exhaustive // Non-native resources are intentionally irrelevant.
		case releaseinventory.ResourceKindLauncher:
			target = &authority.launcher
		case releaseinventory.ResourceKindHelper:
			target = &authority.runtimeHelper
		default:
			continue
		}
		if target.valid() || resource.Platform() != platform || resource.Digest().IsZero() || resource.Size() == 0 {
			return installedDistributionAuthority{}, ErrInstalledProductIntegrity
		}
		*target = installedFileAuthority{digest: resource.Digest(), size: resource.Size()}
	}
	if !authority.launcher.valid() || !authority.runtimeHelper.valid() {
		return installedDistributionAuthority{}, ErrInstalledProductIntegrity
	}
	return authority, nil
}
