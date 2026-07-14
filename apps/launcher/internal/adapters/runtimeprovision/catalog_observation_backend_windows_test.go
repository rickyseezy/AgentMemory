//go:build windows

package runtimeprovision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsRuntimeSurfaceObservationDistinguishesCleanAndConflictingHosts(t *testing.T) {
	root := t.TempDir()
	application := filepath.Join(root, "Docker")
	executable := filepath.Join(application, "Docker Desktop.exe")
	pipe := func(path string) (bool, error) {
		if path != catalogWindowsDockerPipe {
			return false, ErrProvisionIntegrity
		}
		return false, nil
	}
	applicationPresent, executablePresent, endpointPresent, err := observeWindowsRuntimeSurfaces(
		t.Context(), application, executable, catalogWindowsDockerPipe, pipe,
	)
	if err != nil || applicationPresent || executablePresent || endpointPresent {
		t.Fatalf("clean surfaces=%t/%t/%t error=%v", applicationPresent, executablePresent, endpointPresent, err)
	}
	if err := os.Mkdir(application, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	applicationPresent, executablePresent, endpointPresent, err = observeWindowsRuntimeSurfaces(
		t.Context(), application, executable, catalogWindowsDockerPipe,
		func(string) (bool, error) { return true, nil },
	)
	if err != nil || !applicationPresent || !executablePresent || !endpointPresent {
		t.Fatalf("installed surfaces=%t/%t/%t error=%v", applicationPresent, executablePresent, endpointPresent, err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(executable, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := observeWindowsRuntimeSurfaces(
		t.Context(), application, executable, catalogWindowsDockerPipe, pipe,
	); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("directory executable error=%v", err)
	}
}

func TestWindowsRuntimeSurfaceObservationRejectsUntrustedAuthority(t *testing.T) {
	root := t.TempDir()
	if _, _, _, err := observeWindowsRuntimeSurfaces(
		t.Context(), filepath.Join(root, "Docker"), filepath.Join(root, "Docker.exe"),
		`\\server\pipe\docker_engine`, func(string) (bool, error) { return false, nil },
	); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("foreign pipe error=%v", err)
	}
}
