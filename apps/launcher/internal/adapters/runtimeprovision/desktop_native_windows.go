//go:build windows

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

const allWindowsProcessorGroups = uint16(0xffff)

const (
	windowsDesktopVolumePathCharacters = 32768
	windowsDesktopFilesystemCharacters = 32
)

var (
	desktopKernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	desktopGlobalMemoryStatusExProc = desktopKernel32.NewProc("GlobalMemoryStatusEx")
	desktopVersionDLL               = windows.NewLazySystemDLL("version.dll")
	desktopGetFileVersionInfoSize   = desktopVersionDLL.NewProc("GetFileVersionInfoSizeW")
	desktopGetFileVersionInfo       = desktopVersionDLL.NewProc("GetFileVersionInfoW")
	desktopVerQueryValue            = desktopVersionDLL.NewProc("VerQueryValueW")
)

type desktopWindowsMemoryStatus struct {
	Length            uint32
	MemoryLoad        uint32
	TotalPhysical     uint64
	AvailablePhysical uint64
	TotalPageFile     uint64
	AvailablePageFile uint64
	TotalVirtual      uint64
	AvailableVirtual  uint64
	AvailableExtended uint64
}

type desktopWindowsFixedFileInfo struct {
	Signature        uint32
	StructureVersion uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type nativeDesktopHostProbe struct {
	encryption runtimeport.DesktopWindowsEncryptionAttestor
}

// NewNativeDesktopHostProbe constructs the Windows host/WSL/BitLocker probe.
func NewNativeDesktopHostProbe(dependencies DesktopHostProbeDependencies) (runtimeport.DesktopHostProbe, error) {
	if desktopNilDependency(dependencies.WindowsEncryption) {
		return nil, ErrProvisionIntegrity
	}
	return &nativeDesktopHostProbe{encryption: dependencies.WindowsEncryption}, nil
}

func (p *nativeDesktopHostProbe) ProbeDesktopHost(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.Platform() != runtimeinstall.PlatformWindows || authority.Architecture() != runtimeinstall.ArchitectureAMD64 ||
		runtime.GOARCH != "amd64" {
		return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
	}
	_, sid, err := windowssecurity.CurrentUserSID(ctx)
	if err != nil || authority.PrincipalID() != "sid:"+sid {
		return runtimeport.DesktopHostEvidence{}, ErrProvisionIntegrity
	}
	machineGUID, err := windowssecurity.MachineGUID(ctx)
	if err != nil || runtimeinstall.Sum([]byte(machineGUID)) != authority.MachineDigest() {
		return runtimeport.DesktopHostEvidence{}, ErrProvisionIntegrity
	}
	home, err := os.UserHomeDir()
	if err != nil || !strings.EqualFold(home, authority.HomeDirectory()) {
		return runtimeport.DesktopHostEvidence{}, ErrProvisionIntegrity
	}
	version := windows.RtlGetVersion()
	if version == nil || version.MajorVersion != 10 || version.BuildNumber < 22000 {
		return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
	}
	memory, ok := windowsDesktopMemory()
	cpus := windows.GetActiveProcessorCount(allWindowsProcessorGroups)
	freeDisk, local, diskError := windowsDesktopFilesystem(home)
	if !ok || cpus == 0 || cpus > math.MaxUint16 || diskError != nil || !local ||
		!windows.IsProcessorFeaturePresent(windows.PF_VIRT_FIRMWARE_ENABLED) ||
		p.encryption.AttestWindowsVolumeEncryption(ctx, home) != nil {
		return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
	}
	features, featureError := queryWindowsDesktopFeatures(ctx, authority)
	wslVersion, wslError := queryWindowsWSLVersion(ctx, authority)
	if featureError != nil || wslError != nil {
		return runtimeport.DesktopHostEvidence{}, ErrProbeFailed
	}
	return runtimeport.NewDesktopHostEvidence(runtimeport.DesktopHostEvidenceInput{
		Platform: runtimeinstall.PlatformWindows, Architecture: runtimeinstall.ArchitectureAMD64,
		OSProduct: "windows-11", OSVersion: "10.0.0", Build: version.BuildNumber,
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(), CPUs: uint16(cpus),
		TotalMemory: memory.TotalPhysical, AvailableMemory: memory.AvailablePhysical, FreeDisk: freeDisk,
		Virtualization: true, LocalFilesystem: true, AtRestEncryption: true,
		EnabledWindowsFeatures: features, WSLVersion: wslVersion,
	})
}

func windowsDesktopMemory() (desktopWindowsMemoryStatus, bool) {
	status := desktopWindowsMemoryStatus{Length: uint32(unsafe.Sizeof(desktopWindowsMemoryStatus{}))}
	result, _, _ := desktopGlobalMemoryStatusExProc.Call(uintptr(unsafe.Pointer(&status))) // #nosec G103 -- exact GlobalMemoryStatusEx ABI structure.
	return status, result != 0 && status.TotalPhysical != 0 && status.AvailablePhysical <= status.TotalPhysical
}

func windowsDesktopFilesystem(path string) (uint64, bool, error) {
	volumePath := make([]uint16, windowsDesktopVolumePathCharacters)
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil || windows.GetVolumePathName(pathPointer, &volumePath[0], windowsDesktopVolumePathCharacters) != nil {
		return 0, false, ErrProbeFailed
	}
	root := windows.UTF16ToString(volumePath)
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(rootPointer) != windows.DRIVE_FIXED {
		return 0, false, ErrProbeFailed
	}
	filesystem := make([]uint16, windowsDesktopFilesystemCharacters)
	if err := windows.GetVolumeInformation(
		rootPointer, nil, 0, nil, nil, nil, &filesystem[0], windowsDesktopFilesystemCharacters,
	); err != nil {
		return 0, false, err
	}
	typeName := windows.UTF16ToString(filesystem)
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(pathPointer, &available, &total, &free); err != nil || available == 0 {
		return 0, false, ErrProbeFailed
	}
	return available, typeName == "NTFS" || typeName == "ReFS", nil
}

func queryWindowsDesktopFeatures(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) ([]string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, ErrProbeFailed
	}
	dism := filepath.Join(systemDirectory, "dism.exe")
	if !verifyWindowsNativeTool(dism) {
		return nil, ErrProvisionIntegrity
	}
	enabled := make([]string, 0, len(authority.WindowsFeatures()))
	for _, feature := range authority.WindowsFeatures() {
		output, runError := runWindowsNativeTool(
			ctx, dism, []string{"/Online", "/Get-FeatureInfo", "/FeatureName:" + feature, "/English"}, authority.HomeDirectory(),
		)
		if runError != nil {
			return nil, runError
		}
		state, parseError := parseDISMFeatureState(output)
		if parseError != nil {
			return nil, parseError
		}
		if state {
			enabled = append(enabled, feature)
		}
	}
	return enabled, nil
}

func parseDISMFeatureState(output []byte) (bool, error) {
	text := normalizeWindowsToolText(output)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 || strings.TrimSpace(fields[0]) != "State" {
			continue
		}
		switch strings.TrimSpace(fields[1]) {
		case "Enabled":
			return true, nil
		case "Disabled", "Enable Pending", "Disable Pending":
			return false, nil
		default:
			return false, ErrProvisionIntegrity
		}
	}
	return false, ErrProvisionIntegrity
}

func queryWindowsWSLVersion(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", ErrProbeFailed
	}
	wsl := filepath.Join(systemDirectory, "wsl.exe")
	if _, statError := os.Lstat(wsl); errors.Is(statError, os.ErrNotExist) {
		return "", nil
	}
	if !verifyWindowsNativeTool(wsl) {
		return "", ErrProvisionIntegrity
	}
	output, err := runWindowsNativeTool(ctx, wsl, []string{"--version"}, authority.HomeDirectory())
	if err != nil {
		return "", err
	}
	return parseWSLVersion(output)
}

func parseWSLVersion(output []byte) (string, error) {
	text := normalizeWindowsToolText(output)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 || strings.TrimSpace(fields[0]) != "WSL version" {
			continue
		}
		value := strings.TrimSpace(fields[1])
		parts := strings.Split(value, ".")
		if len(parts) < 3 || len(parts) > 4 {
			return "", ErrProvisionIntegrity
		}
		for _, part := range parts {
			if _, err := strconv.ParseUint(part, 10, 16); err != nil {
				return "", ErrProvisionIntegrity
			}
		}
		return strings.Join(parts[:3], "."), nil
	}
	return "", nil
}

func normalizeWindowsToolText(input []byte) string {
	if len(input) >= 2 && input[0] == 0xff && input[1] == 0xfe {
		input = input[2:]
	}
	if bytes.IndexByte(input, 0) >= 0 {
		characters := make([]uint16, 0, len(input)/2)
		for index := 0; index+1 < len(input); index += 2 {
			characters = append(characters, uint16(input[index])|uint16(input[index+1])<<8)
		}
		return strings.ReplaceAll(windows.UTF16ToString(characters), "\r\n", "\n")
	}
	return strings.ReplaceAll(string(input), "\r\n", "\n")
}

func runWindowsNativeTool(
	ctx context.Context,
	executable string,
	arguments []string,
	home string,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(executable) || !verifyWindowsNativeTool(executable) {
		return nil, ErrProvisionIntegrity
	}
	windowsDirectory, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- verified system binary and closed argv.
	command.Env = []string{
		"LANG=C", "LC_ALL=C", "PATH=" + filepath.Dir(executable), "SystemRoot=" + windowsDirectory,
		"USERPROFILE=" + home, "WINDIR=" + windowsDirectory,
	}
	command.Dir = windowsDirectory
	stdout := &windowsBoundedBuffer{maximum: maximumDesktopNativeToolOutput}
	stderr := &windowsBoundedBuffer{maximum: maximumDesktopNativeToolOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded {
		return nil, ErrProbeFailed
	}
	return stdout.bytes(), nil
}

func verifyWindowsNativeTool(path string) bool {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil || !strings.EqualFold(filepath.Dir(path), systemDirectory) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && verifyWindowsAuthenticode(path)
}

type windowsBoundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (b *windowsBoundedBuffer) Write(value []byte) (int, error) {
	if b.exceeded {
		return len(value), nil
	}
	remaining := b.maximum - b.buffer.Len()
	if len(value) > remaining {
		b.exceeded = true
		if remaining > 0 {
			_, _ = b.buffer.Write(value[:remaining])
		}
		return len(value), nil
	}
	return b.buffer.Write(value)
}

func (b *windowsBoundedBuffer) bytes() []byte { return append([]byte(nil), b.buffer.Bytes()...) }

type nativeDesktopArtifactVerifier struct {
	provenance runtimeport.DesktopArtifactAcquirer
	signer     runtimeport.DesktopWindowsSignerIdentityVerifier
}

// NewNativeDesktopArtifactVerifier constructs WinVerifyTrust plus exact signer verification.
func NewNativeDesktopArtifactVerifier(
	dependencies DesktopArtifactVerifierDependencies,
) (runtimeport.DesktopArtifactVerifier, error) {
	if desktopNilDependency(dependencies.Provenance) || desktopNilDependency(dependencies.WindowsSigner) {
		return nil, ErrProvisionIntegrity
	}
	return &nativeDesktopArtifactVerifier{provenance: dependencies.Provenance, signer: dependencies.WindowsSigner}, nil
}

func (v *nativeDesktopArtifactVerifier) VerifyDesktopArtifact(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.Platform() != runtimeinstall.PlatformWindows || authority.Publisher().Kind() != runtimeport.DesktopPublisherAuthenticode {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	provenance, err := v.provenance.AcquireDesktopArtifact(ctx, authority)
	if err != nil || !provenance.AcquiredFor(authority) {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, authority.ArtifactPath(), false)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	defer func() { _ = file.Close() }()
	digest, bytesRead, err := digestWindowsDesktopArtifact(ctx, file, authority.ArtifactBytes())
	if err != nil || digest != authority.ArtifactSHA256() || bytesRead != authority.ArtifactBytes() ||
		!verifyWindowsAuthenticode(authority.ArtifactPath()) {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	certificate, err := v.signer.VerifyWindowsDesktopSigner(ctx, authority)
	if err != nil || certificate != authority.Publisher().CertificateSHA256() {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	publisher := authority.Publisher()
	return runtimeport.NewDesktopArtifactEvidence(runtimeport.DesktopArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), Path: authority.ArtifactPath(), SHA256: digest, Bytes: bytesRead,
		SourceURL: authority.ArtifactSourceURL(), TLSVerified: true, PublisherKind: publisher.Kind(),
		PublisherIdentity: publisher.Identity(), CertificateSHA256: certificate, NativeVerified: true,
	})
}

func digestWindowsDesktopArtifact(
	ctx context.Context,
	file *os.File,
	expected uint64,
) (runtimeinstall.Hash, uint64, error) {
	if ctx == nil {
		return runtimeinstall.Hash{}, 0, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, 0, err
	}
	if file == nil || expected == 0 || expected > math.MaxInt64 {
		return runtimeinstall.Hash{}, 0, ErrProvisionIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return runtimeinstall.Hash{}, 0, err
	}
	hasher := sha256.New()
	limited := io.LimitReader(file, int64(expected)+1) // #nosec G115 -- bounded by MaxInt64 above.
	written, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: limited}, make([]byte, 1024*1024))
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return runtimeinstall.Hash{}, 0, contextError
		}
		return runtimeinstall.Hash{}, 0, ErrProvisionIntegrity
	}
	if written < 0 || uint64(written) != expected {
		return runtimeinstall.Hash{}, 0, ErrProvisionIntegrity
	}
	var digest runtimeinstall.Hash
	copy(digest[:], hasher.Sum(nil))
	return digest, uint64(written), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(value []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(value)
}

func verifyWindowsAuthenticode(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fileInfo := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: pointer}
	data := &windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo), // #nosec G103 -- exact WinTrust ABI union pointer.
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_DISABLE_MD2_MD4,
		UIContext:                       windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyError := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeError := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	runtime.KeepAlive(fileInfo)
	runtime.KeepAlive(pointer)
	return verifyError == nil && closeError == nil
}

type nativeDesktopInstalledApplicationProbe struct {
	signer runtimeport.DesktopWindowsApplicationSignerIdentityVerifier
}

// NewNativeDesktopInstalledApplicationProbe constructs the installed Windows
// executable, fixed file-version, Authenticode, and exact signer probe.
func NewNativeDesktopInstalledApplicationProbe(
	dependencies DesktopInstalledApplicationProbeDependencies,
) (runtimeport.DesktopInstalledApplicationProbe, error) {
	if desktopNilDependency(dependencies.WindowsSigner) {
		return nil, ErrProvisionIntegrity
	}
	return &nativeDesktopInstalledApplicationProbe{signer: dependencies.WindowsSigner}, nil
}

func (p *nativeDesktopInstalledApplicationProbe) ProbeDesktopInstalledApplication(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.Platform() != runtimeinstall.PlatformWindows {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	applicationInfo, applicationError := os.Lstat(authority.ApplicationPath())
	executableInfo, executableError := os.Lstat(authority.ApplicationExecutable())
	if errors.Is(applicationError, os.ErrNotExist) && errors.Is(executableError, os.ErrNotExist) {
		return runtimeport.NewDesktopInstalledApplicationEvidence(runtimeport.DesktopInstalledApplicationEvidenceInput{
			AuthorityDigest: authority.Digest(),
		})
	}
	if applicationError != nil || executableError != nil || !applicationInfo.IsDir() ||
		applicationInfo.Mode()&os.ModeSymlink != 0 || !executableInfo.Mode().IsRegular() ||
		executableInfo.Mode()&os.ModeSymlink != 0 {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, authority.ApplicationExecutable(), false)
	if err != nil {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	defer func() { _ = file.Close() }()
	if !verifyWindowsAuthenticode(authority.ApplicationExecutable()) {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	certificate, err := p.signer.VerifyWindowsDesktopApplicationSigner(ctx, authority)
	if err != nil || certificate != authority.Publisher().CertificateSHA256() {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	version, err := windowsDesktopFileVersion(authority.ApplicationExecutable())
	if err != nil || version != authority.RuntimeVersion() {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	if _, err := windowssecurity.VerifyOpened(ctx, file, false, false); err != nil ||
		!verifyWindowsAuthenticode(authority.ApplicationExecutable()) {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	publisher := authority.Publisher()
	return runtimeport.NewDesktopInstalledApplicationEvidence(runtimeport.DesktopInstalledApplicationEvidenceInput{
		AuthorityDigest: authority.Digest(), Present: true, RuntimeVersion: version,
		PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
		CertificateSHA256: certificate, NativeVerified: true,
	})
}

func windowsDesktopFileVersion(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", ErrProvisionIntegrity
	}
	var ignored uint32
	size, _, _ := desktopGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&ignored)), // #nosec G103 -- exact version.dll ABI pointers.
	)
	if size == 0 || size > maximumDesktopNativeToolOutput {
		return "", ErrProvisionIntegrity
	}
	buffer := make([]byte, size)
	result, _, _ := desktopGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pointer)), // #nosec G103 -- exact version.dll UTF-16 path pointer.
		0, size,
		uintptr(unsafe.Pointer(&buffer[0])), // #nosec G103 -- exact version.dll ABI buffer.
	)
	if result == 0 {
		return "", ErrProvisionIntegrity
	}
	root, err := windows.UTF16PtrFromString(`\`)
	if err != nil {
		return "", ErrProvisionIntegrity
	}
	var fixed *desktopWindowsFixedFileInfo
	var length uint32
	result, _, _ = desktopVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buffer[0])), // #nosec G103 -- exact version.dll input buffer.
		uintptr(unsafe.Pointer(root)),       // #nosec G103 -- exact version.dll UTF-16 query pointer.
		uintptr(unsafe.Pointer(&fixed)),     // #nosec G103 -- version.dll writes a retained fixed-info pointer.
		uintptr(unsafe.Pointer(&length)),    // #nosec G103 -- version.dll writes the bounded result length.
	)
	if result == 0 || fixed == nil || length < uint32(unsafe.Sizeof(desktopWindowsFixedFileInfo{})) ||
		fixed.Signature != 0xFEEF04BD {
		return "", ErrProvisionIntegrity
	}
	parts := []uint32{
		fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xffff,
		fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xffff,
	}
	count := len(parts)
	if parts[count-1] == 0 {
		count--
	}
	if count < 3 {
		return "", ErrProvisionIntegrity
	}
	values := make([]string, count)
	for index := range count {
		values[index] = strconv.FormatUint(uint64(parts[index]), 10)
	}
	runtime.KeepAlive(buffer)
	runtime.KeepAlive(pointer)
	return strings.Join(values, "."), nil
}

type nativeDesktopRuntimeLauncher struct{}

// NewNativeDesktopRuntimeLauncher constructs the exact Windows application launcher.
func NewNativeDesktopRuntimeLauncher() (runtimeport.DesktopRuntimeLauncher, error) {
	return nativeDesktopRuntimeLauncher{}, nil
}

func (nativeDesktopRuntimeLauncher) LaunchDesktopRuntime(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != runtimeinstall.PlatformWindows ||
		filepath.Dir(authority.ApplicationExecutable()) != authority.ApplicationPath() {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	if !verifyWindowsAuthenticode(authority.ApplicationExecutable()) {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	command := exec.CommandContext(ctx, authority.ApplicationExecutable()) // #nosec G204 -- exact authority-bound executable.
	command.Env = []string{"USERPROFILE=" + authority.HomeDirectory()}
	command.Dir = authority.ApplicationPath()
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Start(); err != nil {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	if err := command.Process.Release(); err != nil {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	return runtimeinstall.Sum([]byte("launch\x00" + authority.Digest().String())), nil
}

var (
	_ runtimeport.DesktopHostProbe                 = (*nativeDesktopHostProbe)(nil)
	_ runtimeport.DesktopArtifactVerifier          = (*nativeDesktopArtifactVerifier)(nil)
	_ runtimeport.DesktopInstalledApplicationProbe = (*nativeDesktopInstalledApplicationProbe)(nil)
	_ runtimeport.DesktopRuntimeLauncher           = nativeDesktopRuntimeLauncher{}
)
