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
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal("test executable owner SID is unavailable")
	}
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID:           "test-executable",
		CanonicalPath:         path,
		SHA256:                sha256.Sum256(contents),
		OwnerIdentity:         "sid:" + user.User.Sid.String(),
		PublisherIdentity:     "test-publisher",
		PublisherPolicyID:     "test-policy",
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
