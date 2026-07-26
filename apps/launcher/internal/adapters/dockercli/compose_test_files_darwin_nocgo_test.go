//go:build darwin && !cgo

package dockercli

import "testing"

func secureComposeTestRoot(t *testing.T) string {
	t.Helper()
	t.Skip("operation runtime requires native macOS ACL verification")
	return ""
}
