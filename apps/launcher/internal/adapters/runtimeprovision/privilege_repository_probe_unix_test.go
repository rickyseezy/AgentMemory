//go:build darwin || linux

package runtimeprovision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativePrivilegeRepositoryProbeReprovesExactProtectedFiles(t *testing.T) {
	t.Parallel()
	_, original := adapterAuthority(t)
	configuration, err := renderAPTPrivilegeRepository(
		original, "/etc/apt/keyrings/agentmemory-docker-stable.gpg",
	)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("exact signed key")
	input := original.TransportInput()
	input.Repository.ConfigurationDigest = runtimeinstall.Sum(configuration)
	input.Repository.SigningKeyDigest = runtimeinstall.Sum(key)
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	uid, gid := privilegeSubIDTestOwner(t)
	probe, err := newNativePrivilegeRepositoryStateProbe(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	configurationPath, keyPath, _, err := renderPrivilegeRepository(authority)
	if err != nil {
		t.Fatal(err)
	}
	writePrivilegeRepositoryProbeFile(t, filepath.Join(root, configurationPath), configuration)
	writePrivilegeRepositoryProbeFile(t, filepath.Join(root, keyPath), key)
	if matches, matchError := probe.PrivilegeRepositoryStateMatches(t.Context(), authority); matchError != nil || !matches {
		t.Fatalf("matches=%t error=%v", matches, matchError)
	}
	if err := os.WriteFile(filepath.Join(root, keyPath), []byte("foreign"), 0o644); err != nil { // #nosec G306 -- mirrors system repository mode.
		t.Fatal(err)
	}
	if matches, matchError := probe.PrivilegeRepositoryStateMatches(t.Context(), authority); matchError != nil || matches {
		t.Fatalf("substituted matches=%t error=%v", matches, matchError)
	}
}

func TestPF006NativePrivilegeRepositoryProbeRejectsSymlinkAndTreatsAbsenceAsState(t *testing.T) {
	t.Parallel()
	_, original := adapterAuthority(t)
	configuration, err := renderAPTPrivilegeRepository(
		original, "/etc/apt/keyrings/agentmemory-docker-stable.gpg",
	)
	if err != nil {
		t.Fatal(err)
	}
	input := original.TransportInput()
	input.Repository.ConfigurationDigest = runtimeinstall.Sum(configuration)
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	uid, gid := privilegeSubIDTestOwner(t)
	probe, err := newNativePrivilegeRepositoryStateProbe(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if matches, matchError := probe.PrivilegeRepositoryStateMatches(t.Context(), authority); matchError != nil || matches {
		t.Fatalf("absent matches=%t error=%v", matches, matchError)
	}
	configurationPath, _, _, err := renderPrivilegeRepository(authority)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	writePrivilegeRepositoryProbeFile(t, target, configuration)
	path := filepath.Join(root, configurationPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if matches, matchError := probe.PrivilegeRepositoryStateMatches(t.Context(), authority); !errors.Is(matchError, runtimeport.ErrPrivilegeIntegrity) || matches {
		t.Fatalf("symlink matches=%t error=%v", matches, matchError)
	}
}

func writePrivilegeRepositoryProbeFile(t testing.TB, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil { // #nosec G306 -- mirrors system repository mode.
		t.Fatal(err)
	}
}
