//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

const nativeLauncherPublisherPolicy = "linux:package-receipt:v1"

type nativeLauncherPackageReceipt struct {
	authority argvprocess.ExecutableAuthority
}

func (v nativeLauncherPackageReceipt) VerifyLinuxPackageReceipt(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence process.ExecutableEvidence,
) error {
	if ctx == nil || ctx.Err() != nil || !v.authority.Valid() || !authority.Equal(v.authority) ||
		evidence.CanonicalID != authority.CanonicalID() || evidence.Digest != authority.SHA256() ||
		evidence.OwnerIdentity != authority.OwnerIdentity() ||
		evidence.ReleaseManifestDigest != authority.ReleaseManifestDigest() ||
		evidence.RuntimePlanDigest != authority.RuntimePlanDigest() || evidence.Role != authority.Role() {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

func newNativeLauncherPublisherVerifier(
	authority argvprocess.ExecutableAuthority,
) (process.PublisherVerifier, error) {
	return process.NewNativePublisherVerifier(process.NativePublisherDependencies{
		LinuxPackageReceipt: nativeLauncherPackageReceipt{authority: authority},
	})
}

func nativeLauncherExecutionPolicy(
	_ *nativeReleaseAuthority,
	_ string,
	manifestDigest [32]byte,
) (string, string, [32]byte, error) {
	return "uid:0", nativeLauncherPublisherPolicy, manifestDigest, nil
}
