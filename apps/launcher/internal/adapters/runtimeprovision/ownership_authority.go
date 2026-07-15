package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const explicitLocalEndpointContext = "explicit-local-endpoint"

// LinuxOwnershipAuthorityResolver converts a reverified signed Linux runtime
// authority into the bounded lifecycle facts stored by RuntimeOwnershipRecord.
type LinuxOwnershipAuthorityResolver struct {
	resolver runtimeport.AuthorityResolver
}

// NewLinuxOwnershipAuthorityResolver rejects an absent signed authority source.
func NewLinuxOwnershipAuthorityResolver(
	resolver runtimeport.AuthorityResolver,
) (*LinuxOwnershipAuthorityResolver, error) {
	if nilDependency(resolver) {
		return nil, ErrProvisionIntegrity
	}
	return &LinuxOwnershipAuthorityResolver{resolver: resolver}, nil
}

// ResolveRuntimeOwnershipAuthority re-resolves the exact catalog and host binding.
func (r *LinuxOwnershipAuthorityResolver) ResolveRuntimeOwnershipAuthority(
	ctx context.Context,
	canonicalPlan []byte,
) (runtimeinstall.RuntimeOwnershipAuthority, error) {
	if r == nil || ctx == nil || nilDependency(r.resolver) {
		return runtimeinstall.RuntimeOwnershipAuthority{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.RuntimeOwnershipAuthority{}, err
	}
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || plan.Platform() != runtimeinstall.PlatformLinux {
		return runtimeinstall.RuntimeOwnershipAuthority{}, ErrProvisionIntegrity
	}
	authority, err := r.resolver.ResolveLinuxAuthority(ctx, canonicalPlan)
	if err != nil || !authority.ValidFor(plan) {
		return runtimeinstall.RuntimeOwnershipAuthority{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	components := []string{
		"compose@" + authority.ComposeVersion(),
		"engine@" + authority.RuntimeVersion(),
	}
	for _, installedPackage := range authority.Packages() {
		components = append(components, "package:"+installedPackage.Name()+"@"+installedPackage.Version())
	}
	settings := []string{
		"endpoint:" + authority.Endpoint(),
		"repository:" + authority.Repository().ID(),
		"service:" + authority.ServiceID(),
		"subordinate-id-count:" + strconv.FormatUint(uint64(authority.SubordinateIDCount()), 10),
	}
	sort.Strings(components)
	sort.Strings(settings)
	repository := authority.Repository()
	return runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: authority.Endpoint(), Context: explicitLocalEndpointContext,
		Publisher: repository.ID() + ":" + repository.SigningKeyFingerprint(),
		PublisherDigest: combineDigests(
			repository.SigningKeyDigest(), repository.ConfigurationDigest(), repository.MetadataDigest(),
		),
		ArtifactDigest: authority.ArtifactDigest(), Components: components, Settings: settings,
	})
}

// DesktopOwnershipAuthorityResolver converts a reverified signed macOS or
// Windows Docker Desktop authority into the same host-neutral record contract.
type DesktopOwnershipAuthorityResolver struct {
	resolver runtimeport.DesktopAuthorityResolver
}

// NewDesktopOwnershipAuthorityResolver rejects an absent signed authority source.
func NewDesktopOwnershipAuthorityResolver(
	resolver runtimeport.DesktopAuthorityResolver,
) (*DesktopOwnershipAuthorityResolver, error) {
	if nilDependency(resolver) {
		return nil, ErrProvisionIntegrity
	}
	return &DesktopOwnershipAuthorityResolver{resolver: resolver}, nil
}

// ResolveRuntimeOwnershipAuthority re-resolves the exact catalog, publisher, and host binding.
func (r *DesktopOwnershipAuthorityResolver) ResolveRuntimeOwnershipAuthority(
	ctx context.Context,
	canonicalPlan []byte,
) (runtimeinstall.RuntimeOwnershipAuthority, error) {
	if r == nil || ctx == nil || nilDependency(r.resolver) {
		return runtimeinstall.RuntimeOwnershipAuthority{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.RuntimeOwnershipAuthority{}, err
	}
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || (plan.Platform() != runtimeinstall.PlatformDarwin &&
		plan.Platform() != runtimeinstall.PlatformWindows) {
		return runtimeinstall.RuntimeOwnershipAuthority{}, ErrProvisionIntegrity
	}
	authority, err := r.resolver.ResolveDesktopAuthority(ctx, canonicalPlan)
	if err != nil || !authority.ValidFor(plan) {
		return runtimeinstall.RuntimeOwnershipAuthority{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	components := []string{
		"compose@" + authority.ComposeVersion(),
		"docker-desktop@" + authority.RuntimeVersion(),
		"engine@" + authority.EngineVersion(),
	}
	settings := []string{
		"application:" + authority.Publisher().PackageIdentity(),
		"endpoint:" + authority.Endpoint(),
		"vendor-ui-mandatory:" + strconv.FormatBool(authority.VendorUIMandatory()),
	}
	for _, feature := range authority.WindowsFeatures() {
		settings = append(settings, "windows-feature:"+feature)
	}
	if authority.MinimumWSLVersion() != "" {
		settings = append(settings, "wsl-minimum-version:"+authority.MinimumWSLVersion())
	}
	if authority.WSLDistributionName() != "" {
		settings = append(settings, "wsl-distribution:"+authority.WSLDistributionName())
	}
	arguments, marshalError := json.Marshal(authority.InstallerArguments())
	if marshalError != nil {
		return runtimeinstall.RuntimeOwnershipAuthority{}, errors.Join(ErrProvisionIntegrity, marshalError)
	}
	settings = append(settings, "installer-arguments-sha256:"+runtimeinstall.Sum(arguments).String())
	sort.Strings(components)
	sort.Strings(settings)
	publisher := authority.Publisher()
	return runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: authority.Endpoint(), Context: explicitLocalEndpointContext,
		Publisher: publisher.Identity(), PublisherDigest: publisher.CertificateSHA256(),
		ArtifactDigest: authority.ArtifactSHA256(), Components: components, Settings: settings,
	})
}
