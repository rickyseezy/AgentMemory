//go:build darwin && cgo

package runtimeprovision

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -ldl
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef CFTypeRef (*am_helper_assessment_create_fn)(CFURLRef, uint64_t, CFDictionaryRef, CFErrorRef *);
typedef CFDictionaryRef (*am_helper_assessment_result_fn)(CFTypeRef, uint64_t, CFErrorRef *);

static int am_verify_agentmemory_helper(
	const char *path,
	const char *team_id,
	const unsigned char *expected_certificate_hash
) {
	int result = 0;
	CFURLRef url = NULL;
	CFStringRef requirement_string = NULL;
	SecRequirementRef requirement = NULL;
	SecStaticCodeRef code = NULL;
	CFDictionaryRef information = NULL;
	CFErrorRef error = NULL;
	CFTypeRef assessment = NULL;
	CFDictionaryRef assessment_result = NULL;
	void *security = NULL;
	char requirement_text[1024];

	int count = snprintf(
		requirement_text, sizeof(requirement_text),
		"identifier \"com.rickyseezy.agentmemory.runtime-helper\" and anchor apple generic and "
		"certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
		"certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"%s\"",
		team_id
	);
	if (count <= 0 || (size_t)count >= sizeof(requirement_text)) goto cleanup;
	url = CFURLCreateFromFileSystemRepresentation(
		kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
	requirement_string = CFStringCreateWithCString(
		kCFAllocatorDefault, requirement_text, kCFStringEncodingUTF8);
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
	CFRelease(certificate_data);
	if (memcmp(observed, expected_certificate_hash, CC_SHA256_DIGEST_LENGTH) != 0) goto cleanup;

	security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
	if (security == NULL) goto cleanup;
	am_helper_assessment_create_fn create_assessment =
		(am_helper_assessment_create_fn)dlsym(security, "SecAssessmentCreate");
	am_helper_assessment_result_fn copy_result =
		(am_helper_assessment_result_fn)dlsym(security, "SecAssessmentCopyResult");
	CFStringRef *verdict_key = (CFStringRef *)dlsym(security, "kSecAssessmentAssessmentVerdict");
	if (create_assessment == NULL || copy_result == NULL || verdict_key == NULL || *verdict_key == NULL) goto cleanup;
	assessment = create_assessment(url, 0, NULL, &error);
	if (assessment == NULL || error != NULL) goto cleanup;
	assessment_result = copy_result(assessment, 0, &error);
	if (assessment_result == NULL || error != NULL) goto cleanup;
	if (CFDictionaryGetValue(assessment_result, *verdict_key) != kCFBooleanTrue) goto cleanup;
	result = 1;

cleanup:
	if (error != NULL) CFRelease(error);
	if (assessment_result != NULL) CFRelease(assessment_result);
	if (assessment != NULL) CFRelease(assessment);
	if (security != NULL) dlclose(security);
	if (information != NULL) CFRelease(information);
	if (code != NULL) CFRelease(code);
	if (requirement != NULL) CFRelease(requirement);
	if (requirement_string != NULL) CFRelease(requirement_string);
	if (url != NULL) CFRelease(url);
	return result;
}
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"io"
	"math"
	"os"
	"strings"
	"unsafe"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

func (v *NativeDesktopHelperExecutableVerifier) verifyDesktopHelperSelf(
	ctx context.Context,
	resource releaseinventory.Resource,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	certificate, err := v.expectedCertificate(resource, authority)
	teamID := strings.TrimPrefix(resource.NativePublisherIdentity(), "teamid:")
	if err != nil || ctx == nil || authority.Platform() != runtimeinstall.PlatformDarwin ||
		teamID == resource.NativePublisherIdentity() || !validDarwinDesktopHelperTeamID(teamID) ||
		resource.Size() > math.MaxInt64 {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, err
	}
	path := "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper"
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	file := os.NewFile(uintptr(descriptor), "agentmemory-runtime-helper")
	if file == nil {
		_ = unix.Close(descriptor)
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	var status unix.Stat_t
	if unix.Fstat(descriptor, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Uid != 0 || status.Gid != 0 || status.Nlink != 1 || status.Mode&0o022 != 0 ||
		status.Mode&0o100 == 0 || status.Size < 0 || uint64(status.Size) != resource.Size() {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	digest, err := digestDarwinDesktopHelper(file, status.Size)
	if err != nil || releaseinventory.Digest(digest) != resource.Digest() {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	pathCString := C.CString(path)
	teamCString := C.CString(teamID)
	defer C.free(unsafe.Pointer(pathCString))
	defer C.free(unsafe.Pointer(teamCString))
	if C.am_verify_agentmemory_helper(
		pathCString, teamCString, (*C.uchar)(unsafe.Pointer(&certificate[0])),
	) != 1 || ctx.Err() != nil {
		return runtimeinstall.Hash{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	after, err := digestDarwinDesktopHelper(file, status.Size)
	if err != nil || after != digest {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return digest, nil
}

func digestDarwinDesktopHelper(file *os.File, size int64) (runtimeinstall.Hash, error) {
	if file == nil || size <= 0 {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	hasher := sha256.New()
	written, err := io.CopyN(hasher, file, size)
	var extra [1]byte
	extraCount, extraError := file.Read(extra[:])
	if err != nil || written != size || extraCount != 0 || extraError != io.EOF {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	var digest runtimeinstall.Hash
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func validDarwinDesktopHelperTeamID(value string) bool {
	if len(value) != 10 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'A' || character > 'Z' {
				return false
			}
		}
	}
	return true
}
