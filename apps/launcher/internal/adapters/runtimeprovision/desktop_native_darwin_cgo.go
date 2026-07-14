//go:build darwin && cgo

package runtimeprovision

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework DiskArbitration -framework IOKit -framework ApplicationServices -framework Foundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <Security/SecCertificate.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>

static int am_verify_docker_application(
	const char *path,
	const unsigned char *expected_certificate_hash,
	char *version,
	size_t version_length
) {
	int result = 0;
	CFURLRef url = NULL;
	CFStringRef requirement_string = NULL;
	SecRequirementRef requirement = NULL;
	SecStaticCodeRef code = NULL;
	CFDictionaryRef information = NULL;
	CFErrorRef error = NULL;
	const char *requirement_text =
		"identifier \"com.docker.docker\" and anchor apple generic and "
		"certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
		"certificate leaf[field.1.2.840.113635.100.6.1.13] exists and "
		"certificate leaf[subject.OU] = \"9BNSXJN65R\"";

	url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), true);
	requirement_string = CFStringCreateWithCString(kCFAllocatorDefault, requirement_text, kCFStringEncodingUTF8);
	if (url == NULL || requirement_string == NULL) goto cleanup;
	if (SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &requirement) != errSecSuccess) goto cleanup;
	if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess) goto cleanup;
	SecCSFlags flags = kSecCSCheckAllArchitectures | kSecCSStrictValidate |
		kSecCSCheckGatekeeperArchitectures | kSecCSRestrictSymlinks;
	if (SecStaticCodeCheckValidityWithErrors(code, flags, requirement, &error) != errSecSuccess || error != NULL) goto cleanup;
	if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) != errSecSuccess || information == NULL) goto cleanup;
	CFArrayRef certificates = (CFArrayRef)CFDictionaryGetValue(information, kSecCodeInfoCertificates);
	if (certificates == NULL || CFGetTypeID(certificates) != CFArrayGetTypeID() || CFArrayGetCount(certificates) < 1) goto cleanup;
	SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, 0);
	CFDataRef certificate_data = SecCertificateCopyData(leaf);
	if (certificate_data == NULL) goto cleanup;
	unsigned char observed[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(CFDataGetBytePtr(certificate_data), (CC_LONG)CFDataGetLength(certificate_data), observed);
	if (memcmp(observed, expected_certificate_hash, CC_SHA256_DIGEST_LENGTH) != 0) {
		CFRelease(certificate_data);
		goto cleanup;
	}
	CFRelease(certificate_data);
	CFDictionaryRef plist = (CFDictionaryRef)CFDictionaryGetValue(information, kSecCodeInfoPList);
	if (plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID()) goto cleanup;
	CFTypeRef version_value = CFDictionaryGetValue(plist, CFSTR("CFBundleShortVersionString"));
	if (version_value == NULL || CFGetTypeID(version_value) != CFStringGetTypeID() ||
		!CFStringGetCString((CFStringRef)version_value, version, (CFIndex)version_length, kCFStringEncodingUTF8)) goto cleanup;
	result = 1;
cleanup:
	if (error != NULL) CFRelease(error);
	if (information != NULL) CFRelease(information);
	if (code != NULL) CFRelease(code);
	if (requirement != NULL) CFRelease(requirement);
	if (requirement_string != NULL) CFRelease(requirement_string);
	if (url != NULL) CFRelease(url);
	return result;
}

static int am_disk_encrypted(const char *path) {
	int result = 0;
	CFStringRef path_string = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
	if (path_string == NULL) return 0;
	CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path_string, kCFURLPOSIXPathStyle, true);
	CFRelease(path_string);
	if (url == NULL) return 0;
	DASessionRef session = DASessionCreate(kCFAllocatorDefault);
	if (session == NULL) { CFRelease(url); return 0; }
	DADiskRef disk = DADiskCreateFromVolumePath(kCFAllocatorDefault, session, url);
	CFRelease(url);
	if (disk == NULL) { CFRelease(session); return 0; }
	CFDictionaryRef description = DADiskCopyDescription(disk);
	if (description != NULL) {
		CFTypeRef encrypted = CFDictionaryGetValue(description, kDADiskDescriptionMediaEncryptedKey);
		CFTypeRef internal = CFDictionaryGetValue(description, kDADiskDescriptionDeviceInternalKey);
		CFTypeRef removable = CFDictionaryGetValue(description, kDADiskDescriptionMediaRemovableKey);
		if (encrypted != NULL && CFGetTypeID(encrypted) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)encrypted) &&
			internal != NULL && CFGetTypeID(internal) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)internal) &&
			removable != NULL && CFGetTypeID(removable) == CFBooleanGetTypeID() && !CFBooleanGetValue((CFBooleanRef)removable)) result = 1;
		CFRelease(description);
	}
	CFRelease(disk);
	CFRelease(session);
	return result;
}

static int am_platform_uuid(char *buffer, size_t length) {
	int result = 0;
	io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
	if (service == IO_OBJECT_NULL) return 0;
	CFTypeRef value = IORegistryEntryCreateCFProperty(service, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
	if (value != NULL && CFGetTypeID(value) == CFStringGetTypeID()) {
		result = CFStringGetCString((CFStringRef)value, buffer, (CFIndex)length, kCFStringEncodingUTF8) ? 1 : 0;
		CFRelease(value);
	}
	IOObjectRelease(service);
	return result;
}

static uint64_t am_available_memory(void) {
	vm_statistics64_data_t statistics;
	mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
	if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&statistics, &count) != KERN_SUCCESS) return 0;
	vm_size_t page_size = 0;
	if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS || page_size == 0) return 0;
	return ((uint64_t)statistics.free_count + (uint64_t)statistics.inactive_count +
		(uint64_t)statistics.speculative_count) * (uint64_t)page_size;
}
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

type nativeDesktopHostProbe struct{}

// NewNativeDesktopHostProbe returns the production macOS host evidence adapter.
func NewNativeDesktopHostProbe(dependencies DesktopHostProbeDependencies) (runtimeport.DesktopHostProbe, error) {
	if !desktopNilDependency(dependencies.WindowsEncryption) {
		return nil, ErrProvisionIntegrity
	}
	return nativeDesktopHostProbe{}, nil
}

func (nativeDesktopHostProbe) ProbeDesktopHost(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != runtimeinstall.PlatformDarwin ||
		(runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || runtime.GOARCH != authority.Architecture().String() {
		return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
	}
	uid := os.Geteuid()
	if uid <= 0 || authority.PrincipalID() != "uid:"+strconv.Itoa(uid) {
		return runtimeport.DesktopHostEvidence{}, ErrProvisionIntegrity
	}
	home, err := os.UserHomeDir()
	if err != nil || home != authority.HomeDirectory() {
		return runtimeport.DesktopHostEvidence{}, ErrProvisionIntegrity
	}
	version, versionError := unix.Sysctl("kern.osproductversion")
	cpu, cpuError := unix.SysctlUint32("hw.physicalcpu")
	total, totalError := unix.SysctlUint64("hw.memsize")
	hypervisor, hypervisorError := unix.SysctlUint32("kern.hv_support")
	available := uint64(C.am_available_memory())
	build, buildError := numericDesktopBuild(version)
	machine, machineError := nativeDarwinMachineDigest()
	freeDisk, localFilesystem, diskError := darwinDesktopFilesystem(home)
	encrypted := nativeDarwinEncrypted(home)
	if versionError != nil || cpuError != nil || totalError != nil || hypervisorError != nil ||
		buildError != nil || machineError != nil || diskError != nil || cpu == 0 || cpu > math.MaxUint16 ||
		total == 0 || available == 0 || available > total || hypervisor != 1 || !encrypted || !localFilesystem {
		return runtimeport.DesktopHostEvidence{}, ErrUnsupportedHost
	}
	architecture := runtimeinstall.ArchitectureARM64
	if runtime.GOARCH == "amd64" {
		architecture = runtimeinstall.ArchitectureAMD64
	}
	return runtimeport.NewDesktopHostEvidence(runtimeport.DesktopHostEvidenceInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: architecture, OSProduct: "macos",
		OSVersion: version, Build: build, PrincipalID: authority.PrincipalID(), MachineDigest: machine,
		CPUs: uint16(cpu), TotalMemory: total, AvailableMemory: available, FreeDisk: freeDisk,
		Virtualization: true, LocalFilesystem: true, AtRestEncryption: true,
	})
}

func nativeDarwinMachineDigest() (runtimeinstall.Hash, error) {
	buffer := make([]byte, 128)
	if C.am_platform_uuid((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))) != 1 {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	length := bytes.IndexByte(buffer, 0)
	if length <= 0 {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	value := string(buffer[:length])
	if len(value) != 36 {
		return runtimeinstall.Hash{}, ErrProbeFailed
	}
	return runtimeinstall.Sum([]byte(value)), nil
}

func nativeDarwinEncrypted(path string) bool {
	cPath := C.CString(path)
	if cPath == nil {
		return false
	}
	defer C.free(unsafe.Pointer(cPath))
	return C.am_disk_encrypted(cPath) == 1
}

func nativeDarwinAvailableMemory() uint64 { return uint64(C.am_available_memory()) }

func darwinDesktopFilesystem(path string) (uint64, bool, error) {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil || filesystem.Bsize <= 0 || filesystem.Bavail == 0 {
		return 0, false, ErrProbeFailed
	}
	blockSize := uint64(filesystem.Bsize)
	if filesystem.Bavail > math.MaxUint64/blockSize {
		return 0, false, ErrProbeFailed
	}
	typeName := unix.ByteSliceToString(filesystem.Fstypename[:])
	local := filesystem.Flags&unix.MNT_LOCAL != 0 && (typeName == "apfs" || typeName == "hfs")
	return filesystem.Bavail * blockSize, local, nil
}

func numericDesktopBuild(version string) (uint32, error) {
	parts := strings.Split(version, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return 0, ErrProbeFailed
	}
	values := [3]uint64{}
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil || value > 999 {
			return 0, ErrProbeFailed
		}
		values[index] = value
	}
	build := values[0]*1000 + values[1]*100 + values[2]
	if build == 0 || build > math.MaxUint32 {
		return 0, ErrProbeFailed
	}
	return uint32(build), nil
}

type nativeDesktopArtifactVerifier struct {
	provenance runtimeport.DesktopArtifactAcquirer
}

// NewNativeDesktopArtifactVerifier constructs the macOS digest, Gatekeeper,
// Developer ID, notarization, and leaf-certificate verifier.
func NewNativeDesktopArtifactVerifier(
	dependencies DesktopArtifactVerifierDependencies,
) (runtimeport.DesktopArtifactVerifier, error) {
	if desktopNilDependency(dependencies.Provenance) || !desktopNilDependency(dependencies.WindowsSigner) {
		return nil, ErrProvisionIntegrity
	}
	return &nativeDesktopArtifactVerifier{provenance: dependencies.Provenance}, nil
}

func (v *nativeDesktopArtifactVerifier) VerifyDesktopArtifact(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.Platform() != runtimeinstall.PlatformDarwin || authority.Publisher().Kind() != runtimeport.DesktopPublisherAppleNotarized {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	provenance, err := v.provenance.AcquireDesktopArtifact(ctx, authority)
	if err != nil || !provenance.AcquiredFor(authority) {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	file, err := openDarwinDesktopArtifact(authority)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, err
	}
	defer func() { _ = file.Close() }()
	digest, bytesRead, err := digestBoundedDesktopArtifact(ctx, file, authority.ArtifactBytes())
	if err != nil || digest != authority.ArtifactSHA256() || bytesRead != authority.ArtifactBytes() {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	if !assessDarwinDiskImage(ctx, authority.ArtifactPath()) {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	mount, err := attachDarwinDiskImage(ctx, authority)
	if err != nil {
		return runtimeport.DesktopArtifactEvidence{}, err
	}
	attached := true
	defer func() {
		if attached {
			_ = detachDarwinDiskImage(context.WithoutCancel(ctx), mount.mountPoint)
		}
	}()
	application := filepath.Join(mount.mountPoint, "Docker.app")
	publisher := authority.Publisher()
	if !verifyDarwinDockerApplication(ctx, application, publisher.CertificateSHA256()) {
		return runtimeport.DesktopArtifactEvidence{}, ErrProvisionIntegrity
	}
	if err := detachDarwinDiskImage(context.WithoutCancel(ctx), mount.mountPoint); err != nil {
		return runtimeport.DesktopArtifactEvidence{}, err
	}
	attached = false
	return runtimeport.NewDesktopArtifactEvidence(runtimeport.DesktopArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), Path: authority.ArtifactPath(), SHA256: digest,
		Bytes: bytesRead, SourceURL: authority.ArtifactSourceURL(), TLSVerified: true,
		PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
		CertificateSHA256: publisher.CertificateSHA256(), NativeVerified: true,
	})
}

func openDarwinDesktopArtifact(authority runtimeport.DesktopAuthority) (*os.File, error) {
	info, err := os.Lstat(authority.ArtifactPath())
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || uint64(info.Size()) != authority.ArtifactBytes() ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrProvisionIntegrity
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	if !ok || uid <= 0 || status.Uid != uint32(uid) || status.Nlink != 1 { // #nosec G115 -- positive Darwin UID.
		return nil, ErrProvisionIntegrity
	}
	file, err := os.Open(authority.ArtifactPath())
	if err != nil {
		return nil, err
	}
	opened, statError := file.Stat()
	if statError != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, ErrProvisionIntegrity
	}
	return file, nil
}

func digestBoundedDesktopArtifact(
	ctx context.Context,
	file *os.File,
	expected uint64,
) (runtimeinstall.Hash, uint64, error) {
	if file == nil || expected == 0 || expected > math.MaxInt64 {
		return runtimeinstall.Hash{}, 0, ErrProvisionIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return runtimeinstall.Hash{}, 0, err
	}
	hasher := sha256.New()
	buffer := make([]byte, 1024*1024)
	var total uint64
	for total <= expected {
		if err := ctx.Err(); err != nil {
			return runtimeinstall.Hash{}, 0, err
		}
		read, err := file.Read(buffer)
		if read > 0 {
			total += uint64(read)
			if total > expected {
				return runtimeinstall.Hash{}, 0, ErrProvisionIntegrity
			}
			_, _ = hasher.Write(buffer[:read])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return runtimeinstall.Hash{}, 0, err
		}
	}
	var digest runtimeinstall.Hash
	copy(digest[:], hasher.Sum(nil))
	return digest, total, nil
}

func assessDarwinDiskImage(ctx context.Context, path string) bool {
	return assessDarwinTarget(ctx, path, "open")
}

func verifyDarwinDockerApplication(ctx context.Context, path string, expected runtimeinstall.Hash) bool {
	_, verified := darwinDockerApplicationVersion(ctx, path, expected)
	return verified
}

func darwinDockerApplicationVersion(
	ctx context.Context,
	path string,
	expected runtimeinstall.Hash,
) (string, bool) {
	cPath := C.CString(path)
	if cPath == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cPath))
	version := make([]byte, 129)
	if C.am_verify_docker_application(
		cPath,
		(*C.uchar)(unsafe.Pointer(&expected[0])),
		(*C.char)(unsafe.Pointer(&version[0])),
		C.size_t(len(version)),
	) != 1 || !assessDarwinTarget(ctx, path, "execute") {
		return "", false
	}
	length := bytes.IndexByte(version, 0)
	if length <= 0 {
		return "", false
	}
	return string(version[:length]), true
}

func assessDarwinTarget(ctx context.Context, path string, assessmentType string) bool {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsAny(path, "\x00\r\n") || (assessmentType != "open" && assessmentType != "execute") {
		return false
	}
	_, err := runDarwinNativeTool(
		ctx, "/usr/sbin/spctl",
		[]string{"--assess", "--type", assessmentType, "--context", "context:primary-signature", path},
		"/var/empty", nil,
	)
	return err == nil
}

type darwinDiskImageMount struct{ mountPoint string }

func attachDarwinDiskImage(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (darwinDiskImageMount, error) {
	output, err := runDarwinNativeTool(
		ctx, "/usr/bin/hdiutil",
		[]string{"attach", authority.ArtifactPath(), "-readonly", "-nobrowse", "-noautoopen", "-plist"},
		authority.HomeDirectory(), nil,
	)
	if err != nil {
		return darwinDiskImageMount{}, err
	}
	mountPoint, err := parseHdiutilMountPoint(output)
	if err != nil || !strings.HasPrefix(mountPoint, "/Volumes/") || !safeMountPoint(mountPoint) {
		return darwinDiskImageMount{}, ErrProvisionIntegrity
	}
	return darwinDiskImageMount{mountPoint: mountPoint}, nil
}

func detachDarwinDiskImage(ctx context.Context, mountPoint string) error {
	if !safeMountPoint(mountPoint) {
		return ErrProvisionIntegrity
	}
	_, err := runDarwinNativeTool(ctx, "/usr/bin/hdiutil", []string{"detach", mountPoint}, "/var/empty", nil)
	return err
}

func safeMountPoint(value string) bool {
	return strings.HasPrefix(value, "/Volumes/") && !strings.Contains(value, "//") &&
		!strings.ContainsAny(value, "\x00\r\n") && filepath.Clean(value) == value && value != "/Volumes"
}

func runDarwinNativeTool(
	ctx context.Context,
	executable string,
	arguments []string,
	home string,
	standardInput []byte,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil ||
		(executable != "/usr/bin/hdiutil" && executable != "/usr/bin/open" && executable != "/usr/sbin/spctl") ||
		!safeNativeTool(executable) {
		return nil, ErrProvisionIntegrity
	}
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- exact root-owned OS tool and closed caller arguments.
	command.Env = []string{"HOME=" + home, "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Dir = "/"
	if len(standardInput) != 0 {
		command.Stdin = bytes.NewReader(standardInput)
	}
	stdout := &boundedNativeBuffer{maximum: maximumDesktopNativeToolOutput}
	stderr := &boundedNativeBuffer{maximum: maximumDesktopNativeToolOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded {
		return nil, ErrProbeFailed
	}
	return stdout.bytes(), nil
}

func safeNativeTool(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && status.Uid == 0 && status.Gid == 0
}

type boundedNativeBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (b *boundedNativeBuffer) Write(value []byte) (int, error) {
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

func (b *boundedNativeBuffer) bytes() []byte { return append([]byte(nil), b.buffer.Bytes()...) }

func parseHdiutilMountPoint(input []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(input))
	wantValue := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", ErrProvisionIntegrity
		}
		if value, ok := token.(xml.StartElement); ok {
			if value.Name.Local == "key" {
				var key string
				if decoder.DecodeElement(&key, &value) != nil {
					return "", ErrProvisionIntegrity
				}
				wantValue = key == "mount-point"
			} else if wantValue && value.Name.Local == "string" {
				var mount string
				if decoder.DecodeElement(&mount, &value) != nil || mount == "" {
					return "", ErrProvisionIntegrity
				}
				return mount, nil
			}
		}
	}
	return "", ErrProvisionIntegrity
}

type nativeDesktopInstalledApplicationProbe struct{}

// NewNativeDesktopInstalledApplicationProbe constructs the installed macOS
// application path, signed Info.plist version, Developer ID, and notarization probe.
func NewNativeDesktopInstalledApplicationProbe(
	dependencies DesktopInstalledApplicationProbeDependencies,
) (runtimeport.DesktopInstalledApplicationProbe, error) {
	if !desktopNilDependency(dependencies.WindowsSigner) {
		return nil, ErrProvisionIntegrity
	}
	return nativeDesktopInstalledApplicationProbe{}, nil
}

func (nativeDesktopInstalledApplicationProbe) ProbeDesktopInstalledApplication(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != runtimeinstall.PlatformDarwin {
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
	publisher := authority.Publisher()
	version, verified := darwinDockerApplicationVersion(ctx, authority.ApplicationPath(), publisher.CertificateSHA256())
	if !verified || version != authority.RuntimeVersion() {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	evidence, err := runtimeport.NewDesktopInstalledApplicationEvidence(runtimeport.DesktopInstalledApplicationEvidenceInput{
		AuthorityDigest: authority.Digest(), Present: true, RuntimeVersion: version,
		PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
		CertificateSHA256: publisher.CertificateSHA256(), NativeVerified: true,
	})
	if err != nil {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	// Revalidate after reading signed metadata so replacement cannot turn the
	// observation into authority between native verification and return.
	recheckedVersion, rechecked := darwinDockerApplicationVersion(ctx, authority.ApplicationPath(), publisher.CertificateSHA256())
	if !rechecked || recheckedVersion != version {
		return runtimeport.DesktopInstalledApplicationEvidence{}, ErrProvisionIntegrity
	}
	return evidence, nil
}

type nativeDesktopRuntimeLauncher struct{}

// NewNativeDesktopRuntimeLauncher returns the exact LaunchServices-backed macOS launcher.
func NewNativeDesktopRuntimeLauncher() (runtimeport.DesktopRuntimeLauncher, error) {
	return nativeDesktopRuntimeLauncher{}, nil
}

func (nativeDesktopRuntimeLauncher) LaunchDesktopRuntime(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	if !authority.Valid() || authority.Platform() != runtimeinstall.PlatformDarwin ||
		authority.ApplicationPath() != "/Applications/Docker.app" {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	if _, err := runDarwinNativeTool(
		ctx, "/usr/bin/open", []string{"-a", authority.ApplicationPath()}, authority.HomeDirectory(), nil,
	); err != nil {
		return runtimeinstall.Hash{}, err
	}
	return runtimeinstall.Sum([]byte("launch\x00" + authority.Digest().String())), nil
}

var (
	_ runtimeport.DesktopHostProbe                 = nativeDesktopHostProbe{}
	_ runtimeport.DesktopArtifactVerifier          = (*nativeDesktopArtifactVerifier)(nil)
	_ runtimeport.DesktopInstalledApplicationProbe = nativeDesktopInstalledApplicationProbe{}
	_ runtimeport.DesktopRuntimeLauncher           = nativeDesktopRuntimeLauncher{}
)
