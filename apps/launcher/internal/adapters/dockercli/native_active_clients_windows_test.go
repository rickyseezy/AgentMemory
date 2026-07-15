//go:build windows

package dockercli

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

func TestPF001WindowsActiveRuntimeClientScannerSubtractsOnlyItsObservationInstance(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("npipe:////./pipe/docker_engine")
	scanner := &NativeActiveRuntimeClientScanner{inspect: func(path string) (windowsPipeSnapshot, error) {
		if path != `\\.\pipe\docker_engine` {
			t.Fatalf("pipe path = %q", path)
		}
		return windowsPipeSnapshot{State: 1, CurrentInstances: 3, MaximumInstances: 255}, nil
	}}
	observation, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint)
	if err != nil || observation.Count != 2 || observation.EvidenceDigest.IsZero() {
		t.Fatalf("observation = %+v/%v", observation, err)
	}
}

func TestPF001WindowsActiveRuntimeClientScannerFailsClosedOnAmbiguousInstanceCount(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("npipe:////./pipe/docker_engine")
	for name, snapshot := range map[string]windowsPipeSnapshot{
		"zero":     {},
		"overflow": {CurrentInstances: 2, MaximumInstances: 1},
	} {
		t.Run(name, func(t *testing.T) {
			scanner := &NativeActiveRuntimeClientScanner{inspect: func(string) (windowsPipeSnapshot, error) {
				return snapshot, nil
			}}
			if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
				t.Fatal("ambiguous named-pipe state was accepted")
			}
		})
	}
	scanner := &NativeActiveRuntimeClientScanner{inspect: func(string) (windowsPipeSnapshot, error) {
		return windowsPipeSnapshot{}, errors.New("denied")
	}}
	if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
		t.Fatal("named-pipe error was accepted")
	}
}
