//go:build windows

package process

import (
	"crypto/sha256"
	"os"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"golang.org/x/sys/windows"
)

func testExecutableAuthority(t *testing.T, path string) argvprocess.ExecutableAuthority {
	t.Helper()
	contents, err := os.ReadFile(path) // #nosec G304 -- test path is os.Executable or an isolated fixture.
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatal("test executable security descriptor is unavailable")
	}
	owner, defaulted, err := descriptor.Owner()
	if err != nil || owner == nil || defaulted || !owner.IsValid() {
		t.Fatal("test executable owner SID is unavailable")
	}
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID:           "test-executable",
		CanonicalPath:         path,
		SHA256:                sha256.Sum256(contents),
		OwnerIdentity:         "sid:" + owner.String(),
		PublisherIdentity:     "test-publisher",
		PublisherPolicyID:     "test-policy",
		PublisherTrustDigest:  sha256.Sum256([]byte("test-publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("test-release-manifest")),
		RuntimePlanDigest:     sha256.Sum256([]byte("test-runtime-plan")),
		Role:                  argvprocess.ExecutableRoleDockerCLI,
		Platform:              runtime.GOOS,
		Architecture:          runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
