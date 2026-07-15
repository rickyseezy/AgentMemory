//go:build darwin && cgo

package process

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -ldl
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef CFTypeRef (*am_assessment_create_fn)(CFURLRef, uint64_t, CFDictionaryRef, CFErrorRef *);
typedef CFDictionaryRef (*am_assessment_result_fn)(CFTypeRef, uint64_t, CFErrorRef *);

static int am_verify_apple_code(const char *path, const char *requirement_text) {
	int result = 0;
	CFURLRef url = NULL;
	CFStringRef requirement_string = NULL;
	SecRequirementRef requirement = NULL;
	SecStaticCodeRef code = NULL;
	CFErrorRef error = NULL;
	CFTypeRef assessment = NULL;
	CFDictionaryRef assessment_result = NULL;
	void *security = NULL;

	url = CFURLCreateFromFileSystemRepresentation(
		kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
	requirement_string = CFStringCreateWithCString(
		kCFAllocatorDefault, requirement_text, kCFStringEncodingUTF8);
	if (url == NULL || requirement_string == NULL) goto cleanup;
	if (SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &requirement) != errSecSuccess) goto cleanup;
	if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess) goto cleanup;
	SecCSFlags flags = kSecCSCheckAllArchitectures | kSecCSStrictValidate |
		kSecCSCheckGatekeeperArchitectures | kSecCSRestrictSymlinks;
	if (SecStaticCodeCheckValidityWithErrors(code, flags, requirement, &error) != errSecSuccess) goto cleanup;
	if (error != NULL) { CFRelease(error); error = NULL; }

	// Gatekeeper assessment is the native notarization-policy decision. These
	// Security.framework symbols are runtime-resolved because Apple does not
	// ship their declarations in every Command Line Tools SDK. Absence fails closed.
	security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
	if (security == NULL) goto cleanup;
	am_assessment_create_fn create_assessment =
		(am_assessment_create_fn)dlsym(security, "SecAssessmentCreate");
	am_assessment_result_fn copy_result =
		(am_assessment_result_fn)dlsym(security, "SecAssessmentCopyResult");
	CFStringRef *verdict_key = (CFStringRef *)dlsym(security, "kSecAssessmentAssessmentVerdict");
	if (create_assessment == NULL || copy_result == NULL || verdict_key == NULL || *verdict_key == NULL) goto cleanup;
	assessment = create_assessment(url, 0, NULL, &error);
	if (assessment == NULL || error != NULL) goto cleanup;
	assessment_result = copy_result(assessment, 0, &error);
	if (assessment_result == NULL || error != NULL) goto cleanup;
	CFTypeRef verdict = CFDictionaryGetValue(assessment_result, *verdict_key);
	if (verdict != kCFBooleanTrue) goto cleanup;
	result = 1;

cleanup:
	if (error != NULL) CFRelease(error);
	if (assessment_result != NULL) CFRelease(assessment_result);
	if (assessment != NULL) CFRelease(assessment);
	if (security != NULL) dlclose(security);
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
	"fmt"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type nativePublisherVerifier struct{}

// NewNativePublisherVerifier returns macOS's native designated-requirement and
// Gatekeeper/notarization verifier. No ambient keychain identity is accepted.
func NewNativePublisherVerifier(NativePublisherDependencies) (PublisherVerifier, error) {
	return nativePublisherVerifier{}, nil
}

func (nativePublisherVerifier) VerifyExecutablePublisher(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	requirement, err := darwinPublisherRequirement(ctx, authority, evidence)
	if err != nil {
		return err
	}
	pathCString := C.CString(authority.CanonicalPath())
	requirementCString := C.CString(requirement)
	defer C.free(unsafe.Pointer(pathCString))
	defer C.free(unsafe.Pointer(requirementCString))
	if C.am_verify_apple_code(pathCString, requirementCString) != 1 || ctx.Err() != nil {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

func darwinPublisherRequirement(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) (string, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.PublisherPolicyID() != darwinPublisherPolicy || evidence.Digest != authority.SHA256() {
		return "", argvprocess.ErrInvalidInvocation
	}
	identifier, teamID := "", ""
	switch authority.Role() {
	case argvprocess.ExecutableRoleDockerCLI:
		identifier, teamID = "docker", strings.TrimPrefix(dockerPublisherIdentity, "teamid:")
	case argvprocess.ExecutableRoleComposePlugin:
		identifier, teamID = "docker-compose", strings.TrimPrefix(dockerPublisherIdentity, "teamid:")
	case argvprocess.ExecutableRoleRootlessSetup,
		argvprocess.ExecutableRoleRPMKeys,
		argvprocess.ExecutableRolePrivilegeBroker,
		argvprocess.ExecutableRoleAPTTransaction,
		argvprocess.ExecutableRoleDNFTransaction,
		argvprocess.ExecutableRoleDPKGQuery,
		argvprocess.ExecutableRoleRPMQuery,
		argvprocess.ExecutableRoleLoginCTL,
		argvprocess.ExecutableRoleSystemCTL:
		// Rootless Engine setup is never authorized by Docker Desktop's
		// macOS code-signing identity.
		return "", argvprocess.ErrInvalidInvocation
	case argvprocess.ExecutableRoleAgentMemoryLauncher:
		identifier = agentMemoryDarwinIdentifier
		teamID = strings.TrimPrefix(authority.PublisherIdentity(), "teamid:")
	default:
		return "", argvprocess.ErrInvalidInvocation
	}
	if authority.PublisherIdentity() != "teamid:"+teamID || !validDarwinTeamID(teamID) {
		return "", argvprocess.ErrInvalidInvocation
	}
	return fmt.Sprintf(
		`identifier %q and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = %q`,
		identifier, teamID,
	), nil
}

func validDarwinTeamID(value string) bool {
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
