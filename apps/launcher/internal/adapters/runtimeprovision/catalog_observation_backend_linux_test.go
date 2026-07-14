//go:build linux

package runtimeprovision

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxCatalogObservationAcceptsOnlyExactRootlessPrincipal(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		if _, _, _, err := linuxCatalogPrincipal("unix:///run/user/0/docker.sock"); !errors.Is(err, ErrUnsupportedHost) {
			t.Fatalf("root principal error=%v", err)
		}
		return
	}
	expected := "unix:///run/user/" + strconv.Itoa(os.Geteuid()) + "/docker.sock"
	uid, gid, endpoint, err := linuxCatalogPrincipal(expected)
	if err != nil || uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) || // #nosec G115 -- test runs only after the production positive-ID check.
		endpoint != "/run/user/"+strconv.Itoa(os.Geteuid())+"/docker.sock" { // #nosec G115 -- same bounded native identity.
		t.Fatalf("principal=%d/%d/%q error=%v", uid, gid, endpoint, err)
	}
	if _, _, _, err := linuxCatalogPrincipal("unix:///tmp/docker.sock"); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("foreign endpoint error=%v", err)
	}
	if architecture, err := linuxCatalogArchitecture(runtimecatalog.ArchitectureX8664); err != nil || architecture != runtimeinstall.ArchitectureAMD64 {
		t.Fatalf("amd64 architecture=%s error=%v", architecture, err)
	}
	if architecture, err := linuxCatalogArchitecture(runtimecatalog.ArchitectureARM64); err != nil || architecture != runtimeinstall.ArchitectureARM64 {
		t.Fatalf("arm64 architecture=%s error=%v", architecture, err)
	}
}

func TestLinuxRuntimeSurfaceObservationDistinguishesCleanAndConflictingHosts(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("rootless surface policy rejects uid/gid zero")
	}
	root := t.TempDir()
	endpoint := filepath.Join(root, "docker.sock")
	rootful := []string{filepath.Join(root, "rootful.sock"), filepath.Join(root, "var-rootful.sock")}
	candidates := []string{filepath.Join(root, "docker"), filepath.Join(root, "dockerd")}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- positive native IDs are bounded by the kernel ABI.
	present, endpointPresent, err := observeLinuxRuntimeSurfaces(t.Context(), uid, gid, endpoint, rootful, candidates)
	if err != nil || present || endpointPresent {
		t.Fatalf("clean surfaces=%t/%t error=%v", present, endpointPresent, err)
	}
	if err := os.WriteFile(candidates[0], []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, endpointPresent, err = observeLinuxRuntimeSurfaces(t.Context(), uid, gid, endpoint, rootful, candidates)
	if err != nil || !present || endpointPresent {
		t.Fatalf("candidate surfaces=%t/%t error=%v", present, endpointPresent, err)
	}
	if err := os.WriteFile(endpoint, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeLinuxRuntimeSurfaces(t.Context(), uid, gid, endpoint, rootful, candidates); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("regular endpoint error=%v", err)
	}
}
