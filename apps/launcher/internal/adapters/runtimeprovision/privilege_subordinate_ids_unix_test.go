//go:build darwin || linux

package runtimeprovision

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestPF006NativePrivilegeSubordinateIDsAllocateCollisionFreeAndReplayIdempotently(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureSubordinateIDs)
	manager, uidPath, gidPath := privilegeSubIDTestManager(t)
	if err := os.WriteFile(uidPath, []byte("foreign:100000:65536\n"), 0o644); err != nil { // #nosec G306 -- mirrors system subuid mode.
		t.Fatal(err)
	}
	if err := os.WriteFile(gidPath, []byte("foreign:200000:65536\n"), 0o644); err != nil { // #nosec G306 -- mirrors system subgid mode.
		t.Fatal(err)
	}
	changed, err := manager.EnsurePrivilegeSubordinateIDs(t.Context(), request)
	if err != nil || !changed {
		t.Fatalf("changed=%t error=%v", changed, err)
	}
	changed, err = manager.EnsurePrivilegeSubordinateIDs(t.Context(), request)
	if err != nil || changed {
		t.Fatalf("replay changed=%t error=%v", changed, err)
	}
	uidStart, gidStart, count, digest, err := manager.ObservePrivilegeSubordinateIDState(t.Context(), authority)
	if err != nil || uidStart != 165536 || gidStart != 100000 || count != authority.SubordinateIDCount() || digest.IsZero() {
		t.Fatalf("uid=%d gid=%d count=%d digest=%s error=%v", uidStart, gidStart, count, digest, err)
	}
	assertPrivilegeSubIDFileContainsOnce(t, uidPath, authority.AccountName()+":165536:65536")
	assertPrivilegeSubIDFileContainsOnce(t, gidPath, authority.AccountName()+":100000:65536")
}

func TestPF006NativePrivilegeSubordinateIDsSerializeConcurrentReplay(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureSubordinateIDs)
	manager, uidPath, gidPath := privilegeSubIDTestManager(t)
	if err := os.WriteFile(uidPath, nil, 0o644); err != nil { // #nosec G306 -- mirrors system subuid mode.
		t.Fatal(err)
	}
	if err := os.WriteFile(gidPath, nil, 0o644); err != nil { // #nosec G306 -- mirrors system subgid mode.
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := manager.EnsurePrivilegeSubordinateIDs(t.Context(), request)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertPrivilegeSubIDFileContainsOnce(t, uidPath, authority.AccountName()+":100000:65536")
	assertPrivilegeSubIDFileContainsOnce(t, gidPath, authority.AccountName()+":100000:65536")
}

func TestPF006NativePrivilegeSubordinateIDsRejectUnsafeOrAmbiguousState(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureSubordinateIDs)
	for name, contents := range map[string]struct {
		uid string
		gid string
	}{
		"overlap": {
			uid: "first:100000:65536\nsecond:120000:65536\n", gid: "foreign:200000:65536\n",
		},
		"wrong current count": {
			uid: authority.AccountName() + ":100000:32768\n", gid: "foreign:200000:65536\n",
		},
		"duplicate current identity": {
			uid: authority.AccountName() + ":100000:65536\n" +
				strconv.FormatUint(uint64(authority.InvokingUID()), 10) + ":200000:65536\n",
			gid: "foreign:300000:65536\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager, uidPath, gidPath := privilegeSubIDTestManager(t)
			if err := os.WriteFile(uidPath, []byte(contents.uid), 0o644); err != nil { // #nosec G306 -- mirrors system subuid mode.
				t.Fatal(err)
			}
			if err := os.WriteFile(gidPath, []byte(contents.gid), 0o644); err != nil { // #nosec G306 -- mirrors system subgid mode.
				t.Fatal(err)
			}
			if changed, err := manager.EnsurePrivilegeSubordinateIDs(t.Context(), request); changed ||
				!errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
				t.Fatalf("changed=%t error=%v", changed, err)
			}
		})
	}

	manager, uidPath, gidPath := privilegeSubIDTestManager(t)
	target := filepath.Join(filepath.Dir(uidPath), "foreign")
	if err := os.WriteFile(target, nil, 0o644); err != nil { // #nosec G306 -- inert symlink target fixture.
		t.Fatal(err)
	}
	if err := os.Symlink(target, uidPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gidPath, nil, 0o644); err != nil { // #nosec G306 -- mirrors system subgid mode.
		t.Fatal(err)
	}
	if changed, err := manager.EnsurePrivilegeSubordinateIDs(t.Context(), request); changed ||
		!errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("symlink changed=%t error=%v", changed, err)
	}
}

func TestPF006NativePrivilegeSubordinateIDsAcceptExactNumericUIDIdentity(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureSubordinateIDs)
	manager, uidPath, gidPath := privilegeSubIDTestManager(t)
	numeric := strconv.FormatUint(uint64(authority.InvokingUID()), 10) + ":100000:65536\n"
	if err := os.WriteFile(uidPath, []byte(numeric), 0o644); err != nil { // #nosec G306 -- mirrors system subuid mode.
		t.Fatal(err)
	}
	if err := os.WriteFile(gidPath, []byte(numeric), 0o644); err != nil { // #nosec G306 -- mirrors system subgid mode.
		t.Fatal(err)
	}
	changed, err := manager.EnsurePrivilegeSubordinateIDs(t.Context(), request)
	if err != nil || changed {
		t.Fatalf("numeric identity changed=%t error=%v", changed, err)
	}
}

func privilegeSubIDTestManager(
	t testing.TB,
) (*NativePrivilegeSubordinateIDManager, string, string) {
	t.Helper()
	root := t.TempDir()
	uidPath, gidPath := filepath.Join(root, "subuid"), filepath.Join(root, "subgid")
	uid, gid := privilegeSubIDTestOwner(t)
	manager, err := newNativePrivilegeSubordinateIDManager(
		uidPath, gidPath, filepath.Join(root, ".lock"), uid, gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager, uidPath, gidPath
}

func privilegeSubIDTestOwner(t testing.TB) (uint32, uint32) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 || gid < 0 || uint64(uid) > math.MaxUint32 || uint64(gid) > math.MaxUint32 {
		t.Fatal("test owner is out of range")
	}
	return uint32(uid), uint32(gid) // #nosec G115 -- ranges are proven above.
}

func assertPrivilegeSubIDFileContainsOnce(t testing.TB, path string, entry string) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- path is test-owned.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), entry+"\n") != 1 {
		t.Fatalf("entry %q count in %q", entry, raw)
	}
}
