//go:build darwin && !cgo

package dockercli

import (
	"context"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

func TestPF001DarwinNoCGOActiveClientScanFailsClosed(t *testing.T) {
	t.Parallel()
	scanner := NewNativeActiveRuntimeClientScanner()
	if scanner == nil {
		t.Fatal("no-cgo active-client scanner constructor returned nil")
	}
	endpoint, err := containerengine.NewEndpoint("unix:///Users/test/.docker/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint)
	if err == nil || observation.Count != 0 || !observation.EvidenceDigest.IsZero() {
		t.Fatalf("no-cgo observation=%+v error=%v", observation, err)
	}
}
