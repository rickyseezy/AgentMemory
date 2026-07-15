package launcher

import (
	"context"
	"runtime"

	agentconfigadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/agentconfigapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type nativeAgentConfigurationMerger struct {
	release         *nativeReleaseAuthority
	signedRelease   releaseinventory.SignedManifest
	planDigest      install.PlanDigest
	location        agentconfigport.ConfigLocation
	target          agentconfigdomain.Target
	backupDirectory string
}

func newNativeAgentConfigurationMerger(
	release *nativeReleaseAuthority,
	canonicalPlan []byte,
	backupDirectory string,
) (*nativeAgentConfigurationMerger, error) {
	plan, err := installplan.DecodeV1(canonicalPlan)
	bound, bindError := install.BindPlan(canonicalPlan)
	if release == nil || release.verifier() == nil || err != nil || bindError != nil ||
		!plan.Digest().Equal(bound) || backupDirectory == "" {
		return nil, errNativeInstallerIntegrity
	}
	projection := plan.AgentConfiguration()
	location, err := agentconfigport.NewConfigLocation(projection.ConfigLocation())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	target, err := agentconfigdomain.NewTargetForAgent(
		projection.AgentHost(),
		plan.InstallationID(),
		projection.EntryID(),
		projection.LauncherPath(),
		projection.LauncherDigest(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return newNativeAgentConfigurationMergerFromAuthority(
		release,
		plan.SignedRelease(),
		plan.Digest(),
		location,
		target,
		backupDirectory,
	)
}

func newNativeAgentConfigurationMergerFromAuthority(
	release *nativeReleaseAuthority,
	signedRelease releaseinventory.SignedManifest,
	planDigest install.PlanDigest,
	location agentconfigport.ConfigLocation,
	target agentconfigdomain.Target,
	backupDirectory string,
) (*nativeAgentConfigurationMerger, error) {
	if release == nil || release.verifier() == nil || planDigest.IsZero() || location.String() == "" ||
		target.Command() == "" || target.LauncherDigest().IsZero() || backupDirectory == "" {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeAgentConfigurationMerger{
		release: release, signedRelease: signedRelease, planDigest: planDigest,
		location: location, target: target, backupDirectory: backupDirectory,
	}, nil
}

func (a *nativeAgentConfigurationMerger) Merge(
	ctx context.Context,
	request agentconfigapp.MergeRequest,
) (agentconfigapp.MergeResult, error) {
	if a == nil || ctx == nil || a.release == nil || a.release.verifier() == nil ||
		request.Location.String() != a.location.String() || !sameNativeAgentTarget(request.Target, a.target) {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return agentconfigapp.MergeResult{}, err
	}
	inventory, err := a.release.verifier().Verify(ctx, a.signedRelease)
	if err != nil || inventory.ReleaseID() == "" || inventory.ManifestDigest().IsZero() ||
		!inventory.ManifestDigest().Equal(a.signedRelease.Manifest().Digest()) {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	resource, err := nativeLauncherResource(
		nativeVerifiedLauncherInventory{inventory: inventory},
		a.signedRelease.Manifest().Resources(),
		request.Target,
	)
	if err != nil {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	runner, err := newNativeLauncherRunner(a.release, resource, inventory.ManifestDigest(), a.planDigest, request.Target)
	if err != nil {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	verifier, err := agentconfigadapter.NewInvocationVerifier(runner)
	if err != nil {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	store, err := newNativeAgentConfigurationStore(a.backupDirectory)
	if err != nil {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrUnsupportedPlatform
	}
	application, err := agentconfigapp.New(store, verifier, agentconfigadapter.CodexPolicy{})
	if err != nil {
		return agentconfigapp.MergeResult{}, agentconfigport.ErrIntegrity
	}
	return application.Merge(ctx, request)
}

func sameNativeAgentTarget(left, right agentconfigdomain.Target) bool {
	if left.Host() != right.Host() || left.InstallationID() != right.InstallationID() ||
		left.EntryID() != right.EntryID() || left.Command() != right.Command() ||
		!left.LauncherDigest().Equal(right.LauncherDigest()) {
		return false
	}
	leftArguments, rightArguments := left.Arguments(), right.Arguments()
	if len(leftArguments) != len(rightArguments) {
		return false
	}
	for index := range leftArguments {
		if leftArguments[index] != rightArguments[index] {
			return false
		}
	}
	return true
}

func nativeLauncherResource(
	inventory nativeLauncherInventory,
	resources []releaseinventory.Resource,
	target agentconfigdomain.Target,
) (releaseinventory.Resource, error) {
	wanted, err := releaseinventory.NewPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	var selected releaseinventory.Resource
	count := 0
	for _, candidate := range resources {
		if candidate.Kind() != releaseinventory.ResourceKindLauncher ||
			candidate.Purpose() != releaseinventory.ResourcePurposeNativeLauncher ||
			candidate.MediaType() != releaseinventory.MediaTypeNativeExecutable ||
			candidate.Platform() != wanted || candidate.Digest() != releaseinventory.Digest(target.LauncherDigest()) {
			continue
		}
		if inventory == nil || !inventory.Authorizes(candidate) {
			return releaseinventory.Resource{}, errNativeInstallerIntegrity
		}
		selected = candidate
		count++
	}
	if count != 1 {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	return selected, nil
}

type nativeLauncherInventory interface {
	Authorizes(releaseinventory.Resource) bool
}

type nativeVerifiedLauncherInventory struct {
	inventory appreleaseverify.VerifiedInventory
}

func (i nativeVerifiedLauncherInventory) Authorizes(candidate releaseinventory.Resource) bool {
	verified, found := i.inventory.Resource(candidate.ID())
	return found && verified.Authorizes(candidate)
}

func newNativeLauncherRunner(
	release *nativeReleaseAuthority,
	resource releaseinventory.Resource,
	manifestDigest releaseinventory.Digest,
	planDigest install.PlanDigest,
	target agentconfigdomain.Target,
) (*process.Runner, error) {
	owner, publisherPolicy, publisherTrust, err := nativeLauncherExecutionPolicy(
		release,
		resource.ID(),
		[32]byte(manifestDigest),
	)
	if err != nil || owner == "" || publisherPolicy == "" || publisherTrust == [32]byte{} ||
		resource.NativePublisherIdentity() == "" {
		return nil, errNativeInstallerIntegrity
	}
	executionDigest, err := releaseinventory.ParseDigest(planDigest.String())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: resource.ID(), CanonicalPath: target.Command(), SHA256: [32]byte(target.LauncherDigest()),
		OwnerIdentity: owner, PublisherIdentity: resource.NativePublisherIdentity(),
		PublisherPolicyID: publisherPolicy, PublisherTrustDigest: publisherTrust,
		ReleaseManifestDigest: [32]byte(manifestDigest), RuntimePlanDigest: [32]byte(executionDigest),
		Role:     argvprocess.ExecutableRoleAgentMemoryLauncher,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	publisher, err := newNativeLauncherPublisherVerifier(authority)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	runner, err := process.NewRunner(authority, publisher)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return runner, nil
}
