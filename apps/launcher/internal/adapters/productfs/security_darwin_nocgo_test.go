//go:build darwin && !cgo

package productfs

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

func TestPF001DarwinNoCGOProductFilesystemSecurityFailsClosed(t *testing.T) {
	t.Parallel()
	if err := verifyNativeACL(nil); !errors.Is(err, productinstall.ErrUnsupported) {
		t.Fatalf("no-cgo ACL proof error=%v", err)
	}
	if err := syncNativeFile(nil); !errors.Is(err, productinstall.ErrUnsupported) {
		t.Fatalf("no-cgo durable sync error=%v", err)
	}
}
