//go:build darwin && !cgo

package dockercli

import "testing"

func TestPF001DarwinNoCGOComposeACLProofFailsClosed(t *testing.T) {
	t.Parallel()
	if composeACLFree("") || composeACLFreeOpened(nil) {
		t.Fatal("Compose ACL proof passed without the native cgo capability")
	}
}
