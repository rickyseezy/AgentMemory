//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func (f *nativePlatformRuntimeFactory) buildLinuxRuntimeApplication(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	if f == nil || f.composition == nil || f.release == nil || f.artifacts == nil || ctx == nil ||
		verified.runtime.Platform() != runtimeinstall.PlatformLinux ||
		verified.authority.BindingDigest().IsZero() || !verified.signedCatalog.Valid() {
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
	inspector, err := runtimeprovision.NewDockerInspector(
		runners.docker, runners.compose, runtimeprovision.NewNativeEndpointProbe(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	capabilities, err := runtimeprovision.NewDockerCapabilityProbe(runners.docker, runners.compose)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	artifacts, err := runtimeprovision.NewCatalogLinuxArtifactAcquirer(verified.catalog, f.artifacts)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	var artifactTrust *runtimeprovision.CatalogLinuxArtifactVerifier
	if runners.rpmkeys == nil {
		artifactTrust, err = runtimeprovision.NewCatalogLinuxArtifactVerifier(
			verified.catalog, f.composition.artifactStore, setuphost.Clock{},
		)
	} else {
		rpm, rpmError := runtimeprovision.NewRPMKeysPackageVerifier(runners.rpmkeys)
		if rpmError != nil {
			return nil, errNativeInstallerIntegrity
		}
		artifactTrust, err = runtimeprovision.NewCatalogLinuxArtifactVerifierWithRPMKeys(
			verified.catalog, f.composition.artifactStore, setuphost.Clock{}, rpm,
		)
	}
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	codec, helper, err := buildNativeLinuxPrivilegeCodec(ctx, f.release, verified, authority)
	if err != nil || codec == nil || !helper.ValidFor(authority) {
		return nil, errNativeInstallerIntegrity
	}
	privilege, err := runtimeprovision.NewPolkitPrivilegeBroker(runners.privilege, codec)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	authenticator, err := runtimeprovision.NewEd25519PrivilegeReceiptAuthenticator(
		f.release.runtimeHelperAuthenticationKey(), helper.SHA256(),
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	replay, err := f.composition.newRuntimeReplayLedger(verified.authority.OperationID())
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	provisioner, err := runtimeprovision.NewLinuxProvisioner(runtimeprovision.Dependencies{
		Authority: authorityResolver, Host: runtimeprovision.NewNativeHostProbe(), Runtime: inspector,
		Capabilities: capabilities, Consent: f.composition.consentBroker,
		ConsentAuth: f.composition.consentBroker, ConsentStore: f.composition.consentRepository,
		Artifacts: artifacts, ArtifactTrust: artifactTrust, Privilege: privilege,
		Authenticator: authenticator, Replay: replay, Nonces: runtimeprovision.NewCryptoNonceSource(),
		Clock: setuphost.Clock{}, RootlessTool: runners.rootless,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: f.composition.runtimeState,
		Host:       provisioner, Detector: provisioner, Catalog: provisioner, Consent: provisioner,
		Fetcher: provisioner, Verifier: provisioner, Prerequisites: provisioner,
		Installer: provisioner, Terms: provisioner, Controller: provisioner, Capabilities: provisioner,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return &managedNativeRuntimeApplication{application: application}, nil
}
