package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeLinuxExecutableBinding struct {
	canonicalID string
	path        string
	digest      runtimeinstall.Hash
	publisher   string
	receipt     runtimeinstall.Hash
}

func newNativeLinuxExecutableAuthority(
	authority runtimeport.LinuxAuthority,
	release releaseinventory.Digest,
	role argvprocess.ExecutableRole,
) (argvprocess.ExecutableAuthority, error) {
	binding, err := nativeLinuxExecutableBindingFor(authority, role)
	if err != nil || release.IsZero() {
		return argvprocess.ExecutableAuthority{}, errors.New("linux executable authority is incomplete")
	}
	return argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: binding.canonicalID, CanonicalPath: binding.path, SHA256: binding.digest,
		OwnerIdentity: "uid:0", PublisherIdentity: binding.publisher,
		PublisherPolicyID: "linux:package-receipt:v1", PublisherTrustDigest: binding.receipt,
		ReleaseManifestDigest: release, RuntimePlanDigest: authority.PlanDigest(), Role: role,
		Platform: runtimeinstall.PlatformLinux.String(), Architecture: authority.Architecture().String(),
	})
}

func nativeLinuxExecutableBindingFor(
	authority runtimeport.LinuxAuthority,
	role argvprocess.ExecutableRole,
) (nativeLinuxExecutableBinding, error) {
	if !authority.Valid() {
		return nativeLinuxExecutableBinding{}, errors.New("linux runtime authority is invalid")
	}
	var binding nativeLinuxExecutableBinding
	var packageName string
	switch role {
	case argvprocess.ExecutableRoleDockerCLI:
		binding = nativeLinuxExecutableBinding{
			canonicalID: "docker-engine-cli", path: authority.DockerCLIPath(),
			digest: authority.DockerCLISHA256(), publisher: "package:docker-ce-cli",
		}
		packageName = "docker-ce-cli"
	case argvprocess.ExecutableRoleComposePlugin:
		binding = nativeLinuxExecutableBinding{
			canonicalID: "docker-compose-plugin", path: authority.ComposePluginPath(),
			digest: authority.ComposePluginSHA256(), publisher: "package:docker-compose-plugin",
		}
		packageName = "docker-compose-plugin"
	case argvprocess.ExecutableRoleRootlessSetup:
		binding = nativeLinuxExecutableBinding{
			canonicalID: "docker-rootless-setup", path: authority.RootlessToolPath(),
			digest: authority.RootlessToolDigest(), publisher: "package:docker-ce-rootless-extras",
		}
		packageName = "docker-ce-rootless-extras"
	case argvprocess.ExecutableRoleRPMKeys:
		if authority.PackageManager() != runtimeport.PackageManagerDNF {
			return nativeLinuxExecutableBinding{}, errors.New("rpmkeys is not authorized by this Linux cell")
		}
		binding = nativeLinuxExecutableBinding{
			canonicalID: "rpmkeys", path: authority.RPMKeysPath(), digest: authority.RPMKeysSHA256(),
			publisher: "package:rpm", receipt: authority.RPMKeysPackageReceiptDigest(),
		}
	case argvprocess.ExecutableRolePrivilegeBroker:
		binding = nativeLinuxExecutableBinding{
			canonicalID: "pkexec", path: authority.PrivilegeToolPath(), digest: authority.PrivilegeToolSHA256(),
			publisher: "package:" + authority.PrivilegeToolPackage(),
			receipt:   authority.PrivilegeToolPackageReceiptDigest(),
		}
	case argvprocess.ExecutableRoleAgentMemoryLauncher:
		return nativeLinuxExecutableBinding{}, errors.New("linux executable role is unsupported")
	default:
		return nativeLinuxExecutableBinding{}, errors.New("linux executable role is unknown")
	}
	if packageName != "" {
		pkg, present := nativeLinuxAuthorityPackage(authority, packageName)
		if !present {
			return nativeLinuxExecutableBinding{}, errors.New("signed Linux package receipt is unavailable")
		}
		binding.receipt = pkg.NativeReceiptDigest()
	}
	if binding.canonicalID == "" || binding.path == "" || binding.digest.IsZero() ||
		binding.publisher == "" || binding.receipt.IsZero() {
		return nativeLinuxExecutableBinding{}, errors.New("linux executable binding is incomplete")
	}
	return binding, nil
}

func nativeLinuxAuthorityPackage(
	authority runtimeport.LinuxAuthority,
	name string,
) (runtimeport.Package, bool) {
	for _, pkg := range authority.Packages() {
		if pkg.Name() == name {
			return pkg, true
		}
	}
	return runtimeport.Package{}, false
}

// nativeLinuxPackageReceiptVerifier re-joins process evidence to the signed
// catalog package receipt instead of trusting executable discovery, path, or
// root ownership as publisher evidence.
type nativeLinuxPackageReceiptVerifier struct {
	authority runtimeport.LinuxAuthority
	release   releaseinventory.Digest
}

func newNativeLinuxPackageReceiptVerifier(
	authority runtimeport.LinuxAuthority,
	release releaseinventory.Digest,
) (*nativeLinuxPackageReceiptVerifier, error) {
	if !authority.Valid() || release.IsZero() {
		return nil, errors.New("signed Linux package receipt authority is incomplete")
	}
	return &nativeLinuxPackageReceiptVerifier{authority: authority, release: release}, nil
}

func (v *nativeLinuxPackageReceiptVerifier) VerifyLinuxPackageReceipt(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence process.ExecutableEvidence,
) error {
	if ctx == nil {
		return argvprocess.ErrInvalidInvocation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || !v.authority.Valid() || v.release.IsZero() || !authority.Valid() {
		return argvprocess.ErrInvalidInvocation
	}
	expected, err := newNativeLinuxExecutableAuthority(v.authority, v.release, authority.Role())
	if err != nil || !expected.Equal(authority) || evidence.CanonicalID != expected.CanonicalID() ||
		evidence.Digest != expected.SHA256() || evidence.OwnerIdentity != expected.OwnerIdentity() ||
		evidence.ReleaseManifestDigest != expected.ReleaseManifestDigest() ||
		evidence.RuntimePlanDigest != expected.RuntimePlanDigest() || evidence.Role != expected.Role() {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

var _ process.LinuxPackageReceiptVerifier = (*nativeLinuxPackageReceiptVerifier)(nil)
