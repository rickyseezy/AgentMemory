//go:build linux

package launcher

import (
	"context"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func newNativePlatformManagedRuntimeRemoval(
	ctx context.Context,
	composition *nativeComposition,
	release *nativeReleaseAuthority,
	verified nativeVerifiedRuntimeExecution,
) (managedRuntimeRemovalController, error) {
	if ctx == nil || composition == nil || release == nil ||
		verified.runtime.Platform() != runtimeinstall.PlatformLinux || !verified.signedCatalog.Valid() {
		return nil, errNativeInstallerIntegrity
	}
	authorityResolver, err := runtimeprovision.NewCatalogLinuxAuthorityResolver(
		verified.catalog, runtimeprovision.NewNativeLinuxHostBindingProvider(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	authority, err := authorityResolver.ResolveLinuxAuthority(ctx, verified.authority.Plan().CanonicalBytes())
	if err != nil || !authority.ValidFor(verified.authority.Plan()) {
		return nil, errNativeInstallerIntegrity
	}
	runners, err := newNativeLinuxRunnerSet(authority, verified.request.SignedRelease.Manifest().Digest())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	executors, err := dockercli.NewExecutors(runners.docker, runners.compose)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	scanner, err := dockercli.NewRuntimeDependencyScanner(
		executors, dockercli.NewNativeActiveRuntimeClientScanner(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	privilegeRunners, err := newNativeLinuxPrivilegeRunnerSet(
		authority, verified.request.SignedRelease.Manifest().Digest(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	packageState, err := runtimeprovision.NewNativePrivilegePackageStateProbe(privilegeRunners.query)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	presence, err := runtimeprovision.NewLinuxRuntimeRemovalPresenceVerifier(authorityResolver, packageState)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	artifactStager, err := runtimeprovision.NewCatalogPrivilegeArtifactStager(
		verified.catalog, composition.artifactStore, filepath.Join(authority.HomeDirectory(), ".agentmemory"),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	codec, helper, err := buildNativeLinuxPrivilegeCodec(
		ctx, release, verified, authority, artifactStager,
	)
	if err != nil || codec == nil || !helper.ValidFor(authority) {
		return nil, errNativeInstallerIntegrity
	}
	privilege, err := runtimeprovision.NewPolkitPrivilegeBroker(runners.privilege, codec)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	authenticator, err := runtimeprovision.NewProtectedEd25519PrivilegeReceiptAuthenticator(
		runtimeprovision.NewRootPrivilegeReceiptPublicKeySource(), helper.SHA256(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	replay, err := composition.newRuntimeReplayLedger(verified.authority.OperationID())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	remover, err := runtimeprovision.NewLinuxRuntimeRemover(
		runtimeprovision.LinuxRuntimeRemoverDependencies{
			Authority: authorityResolver, Privilege: privilege, Authenticator: authenticator,
			Replay: replay, Nonces: runtimeprovision.NewCryptoNonceSource(), Clock: setuphost.Clock{},
		},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	application, err := runtimeremovalapp.New(runtimeremovalapp.Dependencies{
		Operations: composition.runtimeRemoval, Ownership: composition.runtimeOwnership,
		Scanner: scanner, Consent: composition.removalConsentBroker, Presence: presence, Remover: remover,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	command, err := nativeRuntimeRemovalCommand(verified)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	controller, err := newNativeManagedRuntimeRemovalController(
		command, nativeRuntimeRemovalApplication{application: application}, composition.removalConsentBroker,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return controller, nil
}
