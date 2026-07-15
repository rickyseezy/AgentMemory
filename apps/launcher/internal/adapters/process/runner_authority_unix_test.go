//go:build darwin || linux

package process

import (
	"crypto/sha256"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func testExecutableAuthority(t *testing.T, path string) argvprocess.ExecutableAuthority {
	t.Helper()
	contents, err := os.ReadFile(path) // #nosec G304 -- test path is os.Executable or an isolated fixture.
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test executable has no Unix identity")
	}
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID:           "test-executable",
		CanonicalPath:         path,
		SHA256:                sha256.Sum256(contents),
		OwnerIdentity:         "uid:" + strconv.FormatUint(uint64(status.Uid), 10),
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
