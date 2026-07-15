package launcher

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ValidateNativeReleaseBundle applies the launcher's exact production trust,
// evidence, inventory, and bootstrap-template stack to one retained bundle.
// Release assembly supplies an explicit policy time and target platform; the
// verifier never consults ambient time, the network, an environment variable,
// or a mutable release locator.
func ValidateNativeReleaseBundle(
	ctx context.Context,
	root string,
	encodedTrust string,
	operatingSystem string,
	architecture string,
	verifiedAt time.Time,
) error {
	_, err := ResolveNativeReleasePackage(
		ctx, root, encodedTrust, operatingSystem, architecture, verifiedAt,
	)
	return err
}

// NativeReleasePackageResource is one fully verified native package payload.
// Its bundle path is taken only from the signed source_ref and has no ambient
// filename or caller-selected fallback.
type NativeReleasePackageResource struct {
	resourceID string
	bundlePath string
	digest     releaseinventory.Digest
	size       uint64
}

// ResourceID returns the exact signed resource identifier.
func (r NativeReleasePackageResource) ResourceID() string { return r.resourceID }

// BundlePath returns the canonical path relative to the retained bundle.
func (r NativeReleasePackageResource) BundlePath() string { return r.bundlePath }

// SHA256 returns the lowercase manifest-bound content digest.
func (r NativeReleasePackageResource) SHA256() string { return r.digest.Hex() }

// Size returns the exact manifest-bound byte length.
func (r NativeReleasePackageResource) Size() uint64 { return r.size }

func (r NativeReleasePackageResource) valid() bool {
	return r.resourceID != "" && r.bundlePath != "" && !r.digest.IsZero() && r.size > 0
}

// NativeReleasePackage is the exact signed launcher/helper pair selected for
// one target platform after every release verification gate has passed.
type NativeReleasePackage struct {
	platform releaseinventory.Platform
	launcher NativeReleasePackageResource
	helper   NativeReleasePackageResource
}

// OperatingSystem returns the verified target operating system.
func (p NativeReleasePackage) OperatingSystem() string { return p.platform.OS() }

// Architecture returns the verified target processor architecture.
func (p NativeReleasePackage) Architecture() string { return p.platform.Architecture() }

// Launcher returns the exact verified launcher projection.
func (p NativeReleasePackage) Launcher() NativeReleasePackageResource { return p.launcher }

// Helper returns the exact verified privilege-helper projection.
func (p NativeReleasePackage) Helper() NativeReleasePackageResource { return p.helper }

// Valid reports whether the package is a complete, non-aliased native pair.
func (p NativeReleasePackage) Valid() bool {
	return p.platform.Valid() && !p.platform.IsAny() && p.launcher.valid() && p.helper.valid() &&
		p.launcher.resourceID != p.helper.resourceID && p.launcher.bundlePath != p.helper.bundlePath &&
		!p.launcher.digest.Equal(p.helper.digest)
}

// ResolveNativeReleasePackage verifies a retained release and returns only
// its inventory-authorized native launcher/helper package projection.
func ResolveNativeReleasePackage(
	ctx context.Context,
	root string,
	encodedTrust string,
	operatingSystem string,
	architecture string,
	verifiedAt time.Time,
) (NativeReleasePackage, error) {
	if ctx == nil || verifiedAt.IsZero() || verifiedAt.Unix() <= 0 {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return NativeReleasePackage{}, err
	}
	platform, err := releaseinventory.NewPlatform(operatingSystem, architecture)
	if err != nil || platform.IsAny() {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	trust, err := decodeNativeReleaseTrust(encodedTrust)
	if err != nil {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	source, err := artifactfs.NewBundleFetcher(root)
	if err != nil {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	defer func() { _ = source.Close() }()
	stack, err := newNativeReleaseStack(nativeReleaseStackDependencies{
		Source: source, Clock: exactReleaseValidationClock{at: verifiedAt.UTC()},
		Platform: nativeReleaseExactPlatform{platform: platform}, Protocol: nativeReleaseProtocol{},
		AntiRollback: newReleaseValidationAnchor(), Trust: trust,
	})
	if err != nil {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	raw, err := source.ReadDistributionEnvelope(ctx)
	if err != nil {
		return NativeReleasePackage{}, nativeReleaseValidationError(ctx, err)
	}
	distribution, err := releaseinventory.DecodeSignedManifestV1(raw)
	clear(raw)
	if err != nil {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	inventory, err := stack.application.Verify(ctx, distribution)
	if err != nil {
		return NativeReleasePackage{}, nativeReleaseValidationError(ctx, err)
	}
	template, err := stack.bootstrap.Resolve(ctx, inventory, distribution)
	if err != nil || !template.Valid() {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return NativeReleasePackage{}, err
		}
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	resources, err := distribution.Manifest().ResourcesFor(platform)
	if err != nil {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	selection, err := selectNativeReleasePackage(
		platform, resources, nativeVerifiedPackageAuthorizer{inventory: inventory},
	)
	if err != nil || !selection.Valid() {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	return selection, nil
}

func nativeReleaseValidationError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errNativeInstallerIntegrity
}

type nativePackageResourceAuthorizer interface {
	Authorizes(releaseinventory.Resource) bool
}

type nativeVerifiedPackageAuthorizer struct {
	inventory appreleaseverify.VerifiedInventory
}

func (a nativeVerifiedPackageAuthorizer) Authorizes(resource releaseinventory.Resource) bool {
	verified, found := a.inventory.Resource(resource.ID())
	return found && verified.Authorizes(resource)
}

func selectNativeReleasePackage(
	platform releaseinventory.Platform,
	resources []releaseinventory.Resource,
	authorizer nativePackageResourceAuthorizer,
) (NativeReleasePackage, error) {
	if !platform.Valid() || platform.IsAny() || len(resources) == 0 || nilAny(authorizer) {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	selection := NativeReleasePackage{platform: platform}
	for _, resource := range resources {
		if resource.Platform() != platform {
			continue
		}
		var target *NativeReleasePackageResource
		switch resource.Kind() { //nolint:exhaustive // Every non-native resource is deliberately ignored.
		case releaseinventory.ResourceKindLauncher:
			target = &selection.launcher
		case releaseinventory.ResourceKindHelper:
			target = &selection.helper
		default:
			continue
		}
		if target.valid() || !authorizer.Authorizes(resource) {
			return NativeReleasePackage{}, errNativeInstallerIntegrity
		}
		path := strings.TrimPrefix(resource.SourceRef(), "bundle://")
		if path == resource.SourceRef() || path == "" {
			return NativeReleasePackage{}, errNativeInstallerIntegrity
		}
		*target = NativeReleasePackageResource{
			resourceID: resource.ID(), bundlePath: path,
			digest: resource.Digest(), size: resource.Size(),
		}
	}
	if !selection.Valid() {
		return NativeReleasePackage{}, errNativeInstallerIntegrity
	}
	return selection, nil
}

type exactReleaseValidationClock struct{ at time.Time }

func (c exactReleaseValidationClock) Now() time.Time { return c.at }

type nativeReleaseExactPlatform struct{ platform releaseinventory.Platform }

func (p nativeReleaseExactPlatform) CurrentPlatform(ctx context.Context) (releaseinventory.Platform, error) {
	if ctx == nil || !p.platform.Valid() || p.platform.IsAny() {
		return releaseinventory.Platform{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return releaseinventory.Platform{}, err
	}
	return p.platform, nil
}

// releaseValidationAnchor preserves the production application's CAS contract
// while keeping release qualification side-effect free outside this process.
// It is deliberately not accepted by the native launcher composition root.
type releaseValidationAnchor struct {
	mu      sync.Mutex
	anchors map[releaseinventory.ReleaseChannel]appreleaseverify.ReleaseAnchor
}

func newReleaseValidationAnchor() *releaseValidationAnchor {
	return &releaseValidationAnchor{anchors: make(map[releaseinventory.ReleaseChannel]appreleaseverify.ReleaseAnchor)}
}

func (a *releaseValidationAnchor) LoadReleaseAnchor(
	ctx context.Context,
	channel releaseinventory.ReleaseChannel,
) (appreleaseverify.ReleaseAnchor, error) {
	if a == nil || ctx == nil || !channel.Valid() {
		return appreleaseverify.ReleaseAnchor{}, appreleaseverify.ErrReleaseAnchorIntegrity
	}
	if err := ctx.Err(); err != nil {
		return appreleaseverify.ReleaseAnchor{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	value, found := a.anchors[channel]
	if !found {
		return appreleaseverify.ReleaseAnchor{}, appreleaseverify.ErrReleaseAnchorNotFound
	}
	return value, nil
}

func (a *releaseValidationAnchor) CompareAndSwapReleaseAnchor(
	ctx context.Context,
	expected *appreleaseverify.ReleaseAnchor,
	next appreleaseverify.ReleaseAnchor,
) error {
	if a == nil || ctx == nil || !next.Channel().Valid() || next.Sequence() == 0 ||
		next.ManifestDigest().IsZero() || next.ReleaseID() == "" {
		return appreleaseverify.ErrReleaseAnchorIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, found := a.anchors[next.Channel()]
	if expected == nil {
		if found {
			return appreleaseverify.ErrReleaseAnchorConflict
		}
	} else if !found || !sameReleaseValidationAnchor(current, *expected) {
		return appreleaseverify.ErrReleaseAnchorConflict
	}
	a.anchors[next.Channel()] = next
	return nil
}

func sameReleaseValidationAnchor(left appreleaseverify.ReleaseAnchor, right appreleaseverify.ReleaseAnchor) bool {
	return left.Channel() == right.Channel() && left.Sequence() == right.Sequence() &&
		left.ManifestDigest().Equal(right.ManifestDigest()) && left.ReleaseID() == right.ReleaseID()
}

var _ appreleaseverify.AntiRollbackRepository = (*releaseValidationAnchor)(nil)
