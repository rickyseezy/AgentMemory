//go:build darwin && !cgo

package process

import (
	"context"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001DarwinNoCGOExecutableBoundaryFailsClosed(t *testing.T) {
	t.Parallel()
	if executableACLFree(nil) {
		t.Fatal("executable ACL proof passed without cgo")
	}
	if identity, err := platformExecutableIdentity(nil); identity != "" || err == nil {
		t.Fatalf("no-cgo executable identity=%q error=%v", identity, err)
	}
	if platformExecutablePathSupported(
		argvprocess.ExecutableAuthority{}, nil, nil, 0, true,
	) {
		t.Fatal("no-cgo executable path was accepted")
	}
	command, err := platformExecutableCommand(context.Background(), nil, []string{"--version"})
	if command != nil || !os.IsPermission(err) {
		t.Fatalf("no-cgo command=%+v error=%v", command, err)
	}
}
