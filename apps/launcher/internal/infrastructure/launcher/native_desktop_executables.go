package launcher

import (
	"crypto/sha256"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type nativeDesktopRunnerPair struct {
	docker  *process.Runner
	compose *process.Runner
}

func newNativeDesktopRunnerPair(
	authority runtimeport.DesktopAuthority,
	release releaseinventory.Digest,
) (nativeDesktopRunnerPair, error) {
	if !authority.Valid() || release.IsZero() {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	publisher, err := newNativeDesktopExecutablePublisherVerifier()
	if err != nil || nilAny(publisher) {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	dockerAuthority, err := newNativeDesktopExecutableAuthority(
		authority, release, "docker-desktop-cli", authority.DockerCLIPath(),
		authority.DockerCLISHA256(), argvprocess.ExecutableRoleDockerCLI,
	)
	if err != nil {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	composeAuthority, err := newNativeDesktopExecutableAuthority(
		authority, release, "docker-desktop-compose", authority.ComposePluginPath(),
		authority.ComposePluginSHA256(), argvprocess.ExecutableRoleComposePlugin,
	)
	if err != nil || !dockerAuthority.SameSignedPlan(composeAuthority) {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	docker, err := process.NewRunner(dockerAuthority, publisher)
	if err != nil {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	compose, err := process.NewRunner(composeAuthority, publisher)
	if err != nil {
		return nativeDesktopRunnerPair{}, errNativeInstallerIntegrity
	}
	return nativeDesktopRunnerPair{docker: docker, compose: compose}, nil
}

func newNativeDesktopExecutableAuthority(
	desktop runtimeport.DesktopAuthority,
	release releaseinventory.Digest,
	canonicalID,
	path string,
	digest [sha256.Size]byte,
	role argvprocess.ExecutableRole,
) (argvprocess.ExecutableAuthority, error) {
	if !desktop.Valid() || release.IsZero() || path == "" || digest == [sha256.Size]byte{} ||
		(role != argvprocess.ExecutableRoleDockerCLI && role != argvprocess.ExecutableRoleComposePlugin) {
		return argvprocess.ExecutableAuthority{}, errors.New("desktop executable authority is incomplete")
	}
	publisherTrust := desktop.Publisher().CertificateSHA256()
	return argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: canonicalID, CanonicalPath: path, SHA256: digest,
		OwnerIdentity: desktop.ExecutableOwnerIdentity(), PublisherIdentity: desktop.ExecutablePublisherIdentity(),
		PublisherPolicyID: desktop.ExecutablePublisherPolicyID(), PublisherTrustDigest: publisherTrust,
		ReleaseManifestDigest: release, RuntimePlanDigest: desktop.PlanDigest(), Role: role,
		Platform: desktop.Platform().String(), Architecture: desktop.Architecture().String(),
	})
}
