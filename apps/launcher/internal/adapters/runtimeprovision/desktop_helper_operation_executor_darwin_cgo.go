//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

type nativeDesktopMutationBackend struct {
	runner             DesktopMutationCommandRunner
	applicationVersion func(context.Context, string, runtimeinstall.Hash) (string, bool)
	safeExecutable     func(string) bool
	assessTarget       func(context.Context, string, string) bool
	moveApplication    func(context.Context, runtimeport.DesktopMutationRequest, string) error
	attachImage        func(context.Context, string, string) (darwinDiskImageMount, error)
	detachImage        func(context.Context, string) error
}

func newNativeDesktopMutationBackend(
	runner DesktopMutationCommandRunner,
	_ DesktopMutationReleaseArtifactSource,
) desktopMutationNativeBackend {
	return nativeDesktopMutationBackend{
		runner: runner, applicationVersion: darwinDockerApplicationVersion,
		safeExecutable: safeDarwinDesktopMutationExecutable, assessTarget: assessDarwinTarget,
		moveApplication: moveDarwinDesktopApplicationToTrash,
		attachImage:     attachDarwinDesktopMutationImage, detachImage: detachDarwinDiskImage,
	}
}

func (b nativeDesktopMutationBackend) ExecuteNativeDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	installer DesktopMutationArtifactBinding,
	present bool,
	_ DesktopMutationAuthorityEvidence,
) (uint32, error) {
	authority := request.Authority()
	if ctx == nil || nilArtifactDependency(b.runner) || b.applicationVersion == nil || b.safeExecutable == nil ||
		b.assessTarget == nil || b.moveApplication == nil || b.attachImage == nil || b.detachImage == nil ||
		authority.Platform() != runtimeinstall.PlatformDarwin {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	switch request.Operation() {
	case runtimeport.DesktopMutationInstallRuntime:
		return b.installDarwinDesktopRuntime(ctx, authority, installer, present)
	case runtimeport.DesktopMutationRemoveRuntime:
		return b.removeDarwinDesktopRuntime(ctx, request, installer, present)
	case runtimeport.DesktopMutationInstallPrerequisites:
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	return 0, runtimeport.ErrDesktopMutationIntegrity
}

func (b nativeDesktopMutationBackend) installDarwinDesktopRuntime(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
	installer DesktopMutationArtifactBinding,
	present bool,
) (uint32, error) {
	if !present || installer.SHA256() != authority.ArtifactSHA256() ||
		installer.Size() != authority.ArtifactBytes() || !b.assessTarget(ctx, installer.Path(), "open") {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	mount, err := b.attachImage(ctx, installer.Path(), authority.HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	detach := func() error { return b.detachImage(context.WithoutCancel(ctx), mount.mountPoint) }
	application := filepath.Join(mount.mountPoint, "Docker.app")
	version, verified := b.applicationVersion(
		ctx, application, authority.Publisher().CertificateSHA256(),
	)
	executable := filepath.Join(application, "Contents", "MacOS", "install")
	if !verified || version != authority.RuntimeVersion() || !b.safeExecutable(executable) {
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

func (b nativeDesktopMutationBackend) removeDarwinDesktopRuntime(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	installer DesktopMutationArtifactBinding,
	present bool,
) (uint32, error) {
	authority := request.Authority()
	uninstaller, trashTarget, err := darwinDesktopRemovalPaths(request)
	if err != nil || present || installer.Path() != "" || !installer.SHA256().IsZero() || installer.Size() != 0 ||
		request.ArtifactDigest() != authority.ArtifactSHA256() {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	version, verified := b.applicationVersion(
		ctx, authority.ApplicationPath(), authority.Publisher().CertificateSHA256(),
	)
	if !verified || version != authority.RuntimeVersion() || !b.safeExecutable(uninstaller) ||
		!b.assessTarget(ctx, uninstaller, "execute") {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	command, err := newDesktopMutationCommand(
		uninstaller, nil,
		[]string{"HOME=" + authority.HomeDirectory(), "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"},
		"/",
	)
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	exitCode, runError := b.runner.RunDesktopMutationCommand(ctx, command)
	if runError != nil {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	if exitCode != 0 {
		return exitCode, nil
	}
	if err := b.moveApplication(ctx, request, trashTarget); err != nil {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return 0, nil
}

func darwinDesktopRemovalPaths(
	request runtimeport.DesktopMutationRequest,
) (string, string, error) {
	authority := request.Authority()
	if request.Digest().IsZero() || request.Operation() != runtimeport.DesktopMutationRemoveRuntime ||
		authority.Platform() != runtimeinstall.PlatformDarwin || authority.ApplicationPath() != "/Applications/Docker.app" ||
		!filepath.IsAbs(authority.HomeDirectory()) || filepath.Clean(authority.HomeDirectory()) != authority.HomeDirectory() {
		return "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	uninstaller := filepath.Join(authority.ApplicationPath(), "Contents", "MacOS", "uninstall")
	trash := filepath.Join(
		authority.HomeDirectory(), ".Trash", "Docker.app.agentmemory-"+request.Digest().String(),
	)
	return uninstaller, trash, nil
}

func moveDarwinDesktopApplicationToTrash(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	target string,
) error {
	authority := request.Authority()
	uid, ok := darwinDesktopMutationPrincipalUID(authority.PrincipalID())
	trash := filepath.Dir(target)
	if ctx == nil || !ok || os.Geteuid() != 0 || trash != filepath.Join(authority.HomeDirectory(), ".Trash") {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureDarwinDesktopTrashDirectory(trash, uid); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	version, verified := darwinDockerApplicationVersion(
		ctx, authority.ApplicationPath(), authority.Publisher().CertificateSHA256(),
	)
	if !verified || version != authority.RuntimeVersion() {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := unix.RenameatxNp(
		unix.AT_FDCWD, authority.ApplicationPath(), unix.AT_FDCWD, target, unix.RENAME_EXCL,
	); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	movedVersion, movedVerified := darwinDockerApplicationVersion(
		ctx, target, authority.Publisher().CertificateSHA256(),
	)
	if !movedVerified || movedVersion != authority.RuntimeVersion() {
		_ = unix.RenameatxNp(unix.AT_FDCWD, target, unix.AT_FDCWD, authority.ApplicationPath(), unix.RENAME_EXCL)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if syncPrivilegeProtectedDirectory(trash) != nil || syncPrivilegeProtectedDirectory("/Applications") != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func ensureDarwinDesktopTrashDirectory(path string, uid uint32) error {
	if uid == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := os.Mkdir(path, 0o700); err == nil {
		// #nosec G302 -- this is a user-private directory, not a created file.
		if os.Chown(path, int(uid), -1) != nil || os.Chmod(path, 0o700) != nil {
			return runtimeport.ErrDesktopMutationIntegrity
		}
	} else if !errors.Is(err, os.ErrExist) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	info, err := os.Lstat(path)
	status, ok := infoSyscallStat(info)
	returnError := err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || status.Uid != uid
	if returnError {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
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
	// #nosec G115 -- Darwin uid_t is uint32 and Getuid is non-negative.
	currentUID := uint32(os.Getuid())
	return err == nil && ok && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 &&
		info.Mode().Perm()&0o100 != 0 && status.Nlink == 1 &&
		(status.Uid == 0 || status.Uid == currentUID)
}

var _ desktopMutationNativeBackend = nativeDesktopMutationBackend{}
