//go:build linux

package dockercli

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// removeInheritedTestACL makes a test fixture satisfy the same ACL-free
// contract required of production Compose inputs. GitHub-hosted Linux runners
// may create temporary files below a directory carrying a default POSIX ACL.
func removeInheritedTestACL(t *testing.T, path string, directory bool) {
	t.Helper()
	attributes := []string{"system.posix_acl_access"}
	if directory {
		attributes = append(attributes, "system.posix_acl_default")
	}
	for _, attribute := range attributes {
		err := unix.Removexattr(path, attribute)
		if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			t.Fatalf("remove inherited test ACL %q from %q: %v", attribute, path, err)
		}
	}
}
