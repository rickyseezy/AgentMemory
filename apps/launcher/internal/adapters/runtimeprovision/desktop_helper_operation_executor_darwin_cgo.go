//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"os"
	"path/filepath"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeDesktopMutationBackend struct{ runner DesktopMutationCommandRunner }

func newNativeDesktopMutationBackend(
	runner DesktopMutationCommandRunner,
	_ DesktopMutationReleaseArtifactSource,
) desktopMutationNativeBackend {
	return nativeDesktopMutationBackend{runner: runner}
}

func (b nativeDesktopMutationBackend) ExecuteNativeDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	installer DesktopMutationArtifactBinding,
	present bool,
	_ DesktopMutationAuthorityEvidence,
) (uint32, error) {
	authority := request.Authority()
	if ctx == nil || nilArtifactDependency(b.runner) || authority.Platform() != runtimeinstall.PlatformDarwin ||
		request.Operation() != runtimeport.DesktopMutationInstallRuntime || !present ||
		installer.SHA256() != authority.ArtifactSHA256() || installer.Size() != authority.ArtifactBytes() ||
		!assessDarwinTarget(ctx, installer.Path(), "open") {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	mount, err := attachDarwinDesktopMutationImage(ctx, installer.Path(), authority.HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	detach := func() error { return detachDarwinDiskImage(context.WithoutCancel(ctx), mount.mountPoint) }
	application := filepath.Join(mount.mountPoint, "Docker.app")
	version, verified := darwinDockerApplicationVersion(
		ctx, application, authority.Publisher().CertificateSHA256(),
	)
	executable := filepath.Join(application, "Contents", "MacOS", "install")
	if !verified || version != authority.RuntimeVersion() || !safeDarwinDesktopMutationExecutable(executable) {
		_ = detach()
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	command, err := newDesktopMutationCommand(
		executable, authority.InstallerArguments(),
		[]string{"HOME=" + authority.HomeDirectory(), "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"},
		"/",
	)
	if err != nil {
		_ = detach()
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	exitCode, runError := b.runner.RunDesktopMutationCommand(ctx, command)
	detachError := detach()
	if runError != nil || detachError != nil {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return exitCode, nil
}

func attachDarwinDesktopMutationImage(
	ctx context.Context,
	path string,
	home string,
) (darwinDiskImageMount, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return darwinDiskImageMount{}, runtimeport.ErrDesktopMutationIntegrity
	}
	output, err := runDarwinNativeTool(
		ctx, "/usr/bin/hdiutil",
		[]string{"attach", path, "-readonly", "-nobrowse", "-noautoopen", "-plist"},
		home, nil,
	)
	if err != nil {
		return darwinDiskImageMount{}, err
	}
	mountPoint, err := parseHdiutilMountPoint(output)
	if err != nil || !safeMountPoint(mountPoint) {
		return darwinDiskImageMount{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return darwinDiskImageMount{mountPoint: mountPoint}, nil
}

func safeDarwinDesktopMutationExecutable(path string) bool {
	info, err := os.Lstat(path)
	status, ok := infoSyscallStat(info)
	return err == nil && ok && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 &&
		info.Mode().Perm()&0o100 != 0 && status.Nlink == 1 &&
		(status.Uid == 0 || status.Uid == uint32(os.Getuid()))
}

var _ desktopMutationNativeBackend = nativeDesktopMutationBackend{}
