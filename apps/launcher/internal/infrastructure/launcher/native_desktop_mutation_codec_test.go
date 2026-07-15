package launcher

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001NativeDesktopMutationHelperSelectionIsExactAndUnambiguous(t *testing.T) {
	t.Parallel()
	digest := releaseinventory.DigestBytes([]byte("release"))
	darwin := nativeDesktopHelperResource(t, "darwin", "arm64")
	windows := nativeDesktopHelperResource(t, "windows", "amd64")
	selected, err := nativeDesktopMutationHelperResourceID(
		digest, []releaseinventory.Resource{windows, darwin},
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64,
	)
	if err != nil || selected != darwin.ID() {
		t.Fatalf("selected=%q error=%v", selected, err)
	}
	for name, resources := range map[string][]releaseinventory.Resource{
		"missing":   {windows},
		"duplicate": {darwin, darwin},
		"zero":      {releaseinventory.Resource{}},
	} {
		if selected, selectionError := nativeDesktopMutationHelperResourceID(
			digest, resources, runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64,
		); selected != "" || !errors.Is(selectionError, errNativeInstallerIntegrity) {
			t.Fatalf("%s selected=%q error=%v", name, selected, selectionError)
		}
	}
	if selected, selectionError := nativeDesktopMutationHelperResourceID(
		releaseinventory.Digest{}, []releaseinventory.Resource{darwin},
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64,
	); selected != "" || !errors.Is(selectionError, errNativeInstallerIntegrity) {
		t.Fatalf("zero manifest selected=%q error=%v", selected, selectionError)
	}
	if selected, selectionError := nativeDesktopMutationHelperResourceID(
		digest, []releaseinventory.Resource{darwin},
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureARM64,
	); selected != "" || !errors.Is(selectionError, errNativeInstallerIntegrity) {
		t.Fatalf("foreign platform selected=%q error=%v", selected, selectionError)
	}
	if codec, buildError := buildNativeDesktopMutationEncoder(nativeVerifiedRuntimeExecution{}); codec != nil ||
		!errors.Is(buildError, errNativeInstallerIntegrity) {
		t.Fatalf("zero verified runtime codec=%T error=%v", codec, buildError)
	}
}
