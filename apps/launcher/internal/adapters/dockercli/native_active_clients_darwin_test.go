//go:build darwin && cgo

package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

func TestPF001DarwinActiveRuntimeClientScannerBindsUniquePeerPairs(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("unix:///Users/test/.docker/run/docker.sock")
	scanner := &NativeActiveRuntimeClientScanner{inspect: func(string) (darwinSocketSnapshot, error) {
		return darwinSocketSnapshot{
			listener: 10,
			pairs:    []darwinSocketPair{{left: 20, right: 30}, {left: 40, right: 50}},
		}, nil
	}}
	observation, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint)
	if err != nil || observation.Count != 2 || observation.EvidenceDigest.IsZero() {
		t.Fatalf("observation = %+v/%v", observation, err)
	}
}

func TestPF001DarwinActiveRuntimeClientScannerRejectsIncompleteNativeEvidence(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("unix:///Users/test/.docker/run/docker.sock")
	for name, snapshot := range map[string]darwinSocketSnapshot{
		"listener": {},
		"ordering": {listener: 10, pairs: []darwinSocketPair{{left: 30, right: 20}}},
		"duplicate": {listener: 10, pairs: []darwinSocketPair{
			{left: 20, right: 30}, {left: 20, right: 30},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			scanner := &NativeActiveRuntimeClientScanner{inspect: func(string) (darwinSocketSnapshot, error) {
				return snapshot, nil
			}}
			if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
				t.Fatal("incomplete native evidence was accepted")
			}
		})
	}
	scanner := &NativeActiveRuntimeClientScanner{inspect: func(string) (darwinSocketSnapshot, error) {
		return darwinSocketSnapshot{}, errors.New("denied")
	}}
	if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
		t.Fatal("native scan error was accepted")
	}
}

func TestPF001DarwinActiveRuntimeClientScannerReadsLiveDockerSocketWhenPresent(t *testing.T) {
	endpoint, err := containerengine.NewEndpoint("unix://" + liveDarwinDockerSocket(t))
	if err != nil {
		t.Skip("Docker Desktop socket is not present")
	}
	observation, err := NewNativeActiveRuntimeClientScanner().ScanActiveRuntimeClients(t.Context(), endpoint)
	if err != nil || observation.EvidenceDigest.IsZero() {
		t.Fatalf("live observation = %+v/%v", observation, err)
	}
}

func liveDarwinDockerSocket(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("home directory is unavailable")
	}
	path := filepath.Join(home, ".docker", "run", "docker.sock")
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Skip("Docker Desktop socket is not present")
	}
	return path
}
