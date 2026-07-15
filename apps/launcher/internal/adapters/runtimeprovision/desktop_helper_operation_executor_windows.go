//go:build windows

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

type nativeDesktopMutationBackend struct {
	runner DesktopMutationCommandRunner
	source DesktopMutationReleaseArtifactSource
}

func newNativeDesktopMutationBackend(
	runner DesktopMutationCommandRunner,
	source DesktopMutationReleaseArtifactSource,
) desktopMutationNativeBackend {
	return nativeDesktopMutationBackend{runner: runner, source: source}
}

func (b nativeDesktopMutationBackend) ExecuteNativeDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	installer DesktopMutationArtifactBinding,
	present bool,
	evidence DesktopMutationAuthorityEvidence,
) (uint32, error) {
	authority := request.Authority()
	if ctx == nil || nilArtifactDependency(b.runner) || nilArtifactDependency(b.source) ||
		authority.Platform() != runtimeinstall.PlatformWindows || !evidence.Authority().Valid() ||
		evidence.Authority().Digest() != authority.Digest() {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	switch request.Operation() {
	case runtimeport.DesktopMutationInstallPrerequisites:
		if present || !request.ArtifactDigest().IsZero() {
			return 0, runtimeport.ErrDesktopMutationIntegrity
		}
		exitCode, err := b.enableWindowsDesktopFeatures(ctx, authority)
		if err != nil || exitCode != 0 {
			return exitCode, err
		}
		return b.installWindowsDesktopPrerequisites(ctx, request, evidence)
	case runtimeport.DesktopMutationInstallRuntime:
		if !present || installer.SHA256() != authority.ArtifactSHA256() ||
			installer.Size() != authority.ArtifactBytes() {
			return 0, runtimeport.ErrDesktopMutationIntegrity
		}
		return b.installWindowsDesktopRuntime(ctx, authority, installer)
	default:
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
}

func (b nativeDesktopMutationBackend) installWindowsDesktopPrerequisites(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	evidence DesktopMutationAuthorityEvidence,
) (uint32, error) {
	resources := evidence.PrerequisiteResources()
	if len(resources) != 2 {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	var installerResource, distributionResource releaseinventory.Resource
	for _, resource := range resources {
		switch resource.Kind() {
		case releaseinventory.ResourceKindRuntimeInstaller:
			installerResource = resource
		case releaseinventory.ResourceKindRuntimeDistribution:
			distributionResource = resource
		default:
			return 0, runtimeport.ErrDesktopMutationIntegrity
		}
	}
	msi, err := b.materializeWindowsDesktopPrerequisite(ctx, request, installerResource)
	if err != nil || !verifyWindowsDesktopPrerequisiteMSI(ctx, installerResource, msi, evidence) {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	distribution, err := b.materializeWindowsDesktopPrerequisite(ctx, request, distributionResource)
	if err != nil || !windowsDesktopMutationArtifactMatches(
		ctx, distribution.Path(), distribution.SHA256(), distribution.Size(),
	) {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	msiexec := filepath.Join(systemDirectory, "msiexec.exe")
	if !verifyWindowsNativeTool(msiexec) {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	environment, directory, err := windowsDesktopMutationEnvironment(msiexec, request.Authority().HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	command, err := newDesktopMutationCommand(
		msiexec, []string{"/i", msi.Path(), "/quiet", "/norestart"}, environment, directory,
	)
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	exitCode, err := b.runner.RunDesktopMutationCommand(ctx, command)
	if err != nil || exitCode != 0 && !slices.Contains(request.Authority().RebootExitCodes(), exitCode) {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	if exitCode != 0 {
		return exitCode, nil
	}
	wsl := filepath.Join(systemDirectory, "wsl.exe")
	if !verifyWindowsNativeTool(wsl) {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	environment, directory, err = windowsDesktopMutationEnvironment(wsl, request.Authority().HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	command, err = newDesktopMutationCommand(
		wsl, []string{"--install", "--from-file", distribution.Path(), "--no-launch"}, environment, directory,
	)
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	exitCode, err = b.runner.RunDesktopMutationCommand(ctx, command)
	if err != nil || exitCode != 0 && !slices.Contains(request.Authority().RebootExitCodes(), exitCode) {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return exitCode, nil
}

func (b nativeDesktopMutationBackend) materializeWindowsDesktopPrerequisite(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	resource releaseinventory.Resource,
) (DesktopMutationArtifactBinding, error) {
	target, err := windowsDesktopPrerequisiteTarget(request, resource)
	if ctx == nil || err != nil || nilArtifactDependency(b.source) || resource.Size() > math.MaxInt64 {
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	digest := runtimeinstall.Hash(resource.Digest())
	if windowsDesktopMutationArtifactMatches(ctx, target, digest, resource.Size()) {
		return NewDesktopMutationArtifactBinding(target, digest, resource.Size())
	}
	requestRoot := filepath.Dir(target)
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(
		ctx, `C:\ProgramData\AgentMemory\runtime-helper`, requestRoot,
	); err != nil {
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	source, err := b.source.OpenResource(ctx, resource)
	if err != nil || source == nil {
		return DesktopMutationArtifactBinding{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	temporary := filepath.Join(requestRoot, ".resource."+digest.String()+".partial")
	if err := removeWindowsDesktopMutationTemporary(ctx, temporary); err != nil {
		_ = source.Close()
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	targetFile, err := windowssecurity.CreatePrivateFile(ctx, temporary)
	if err != nil {
		_ = source.Close()
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	committed := false
	defer func() {
		_ = targetFile.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, copyError := io.CopyN(io.MultiWriter(targetFile, hasher), source, int64(resource.Size())) // #nosec G115 -- release size is bounded above.
	var extra [1]byte
	extraCount, extraError := source.Read(extra[:])
	closeSourceError := source.Close()
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	if copyError != nil || uint64(written) != resource.Size() || extraCount != 0 ||
		!errors.Is(extraError, io.EOF) || closeSourceError != nil || actual != digest || ctx.Err() != nil ||
		targetFile.Sync() != nil || targetFile.Close() != nil {
		return DesktopMutationArtifactBinding{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, temporary, target)
	if err != nil || !published && !windowsDesktopMutationArtifactMatches(ctx, target, digest, resource.Size()) {
		return DesktopMutationArtifactBinding{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	committed = published
	if !windowsDesktopMutationArtifactMatches(ctx, target, digest, resource.Size()) {
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return NewDesktopMutationArtifactBinding(target, digest, resource.Size())
}

func windowsDesktopPrerequisiteTarget(
	request runtimeport.DesktopMutationRequest,
	resource releaseinventory.Resource,
) (string, error) {
	if request.Digest().IsZero() || request.Authority().Platform() != runtimeinstall.PlatformWindows ||
		resource.ID() == "" || resource.Digest().IsZero() || resource.Size() == 0 {
		return "", runtimeport.ErrDesktopMutationIntegrity
	}
	name := ""
	switch resource.Kind() {
	case releaseinventory.ResourceKindRuntimeInstaller:
		name = "wsl-installer.msi"
	case releaseinventory.ResourceKindRuntimeDistribution:
		name = "distribution.wsl"
	default:
		return "", runtimeport.ErrDesktopMutationIntegrity
	}
	return filepath.Join(windowsDesktopMutationTransactionRoot, request.Digest().String(), name), nil
}

func verifyWindowsDesktopPrerequisiteMSI(
	ctx context.Context,
	resource releaseinventory.Resource,
	binding DesktopMutationArtifactBinding,
	evidence DesktopMutationAuthorityEvidence,
) bool {
	expectedCertificate := evidence.PrerequisiteCertificate(resource.ID())
	if ctx == nil || resource.Kind() != releaseinventory.ResourceKindRuntimeInstaller ||
		binding.SHA256() != runtimeinstall.Hash(resource.Digest()) || binding.Size() != resource.Size() ||
		expectedCertificate.IsZero() || !windowsDesktopMutationArtifactMatches(
		ctx, binding.Path(), binding.SHA256(), binding.Size(),
	) || !verifyWindowsAuthenticode(binding.Path()) {
		return false
	}
	certificate, err := windowssecurity.AuthenticodeLeafCertificateSHA256(ctx, binding.Path())
	return err == nil && runtimeinstall.Hash(certificate) == expectedCertificate
}

func (b nativeDesktopMutationBackend) enableWindowsDesktopFeatures(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (uint32, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	dism := filepath.Join(systemDirectory, "dism.exe")
	if !verifyWindowsNativeTool(dism) {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	environment, directory, err := windowsDesktopMutationEnvironment(dism, authority.HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	rebootCode := uint32(0)
	for _, feature := range authority.WindowsFeatures() {
		command, err := newDesktopMutationCommand(
			dism,
			[]string{"/Online", "/Enable-Feature", "/FeatureName:" + feature, "/All", "/NoRestart", "/English"},
			environment, directory,
		)
		if err != nil {
			return 0, runtimeport.ErrDesktopMutationIntegrity
		}
		exitCode, runError := b.runner.RunDesktopMutationCommand(ctx, command)
		if runError != nil || exitCode != 0 && !slices.Contains(authority.RebootExitCodes(), exitCode) {
			return 0, desktopMutationHelperContextOrIntegrity(ctx)
		}
		if exitCode != 0 {
			rebootCode = exitCode
		}
	}
	return rebootCode, nil
}

func (b nativeDesktopMutationBackend) installWindowsDesktopRuntime(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
	installer DesktopMutationArtifactBinding,
) (uint32, error) {
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, installer.Path(), false)
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	digest, read, err := digestWindowsDesktopArtifact(ctx, file, installer.Size())
	if err != nil || read != installer.Size() || digest != installer.SHA256() ||
		!verifyWindowsAuthenticode(installer.Path()) {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	certificate, err := windowssecurity.AuthenticodeLeafCertificateSHA256(ctx, installer.Path())
	if err != nil || runtimeinstall.Hash(certificate) != authority.Publisher().CertificateSHA256() {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	after, afterRead, err := digestWindowsDesktopArtifact(ctx, file, installer.Size())
	if err != nil || afterRead != installer.Size() || after != digest {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	environment, directory, err := windowsDesktopMutationEnvironment(installer.Path(), authority.HomeDirectory())
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	command, err := newDesktopMutationCommand(
		installer.Path(), authority.InstallerArguments(), environment, directory,
	)
	if err != nil {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	exitCode, err := b.runner.RunDesktopMutationCommand(ctx, command)
	if err != nil {
		return 0, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return exitCode, nil
}

func windowsDesktopMutationEnvironment(executable, home string) ([]string, string, error) {
	windowsDirectory, err := windows.GetWindowsDirectory()
	if err != nil || !filepath.IsAbs(executable) || !filepath.IsAbs(home) ||
		strings.ContainsAny(home, "\x00\r\n") {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	return []string{
		"LANG=C", "LC_ALL=C", "PATH=" + filepath.Dir(executable), "SystemRoot=" + windowsDirectory,
		"USERPROFILE=" + home, "WINDIR=" + windowsDirectory,
	}, windowsDirectory, nil
}

var _ desktopMutationNativeBackend = nativeDesktopMutationBackend{}
