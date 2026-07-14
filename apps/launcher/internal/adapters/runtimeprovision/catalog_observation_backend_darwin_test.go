//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDarwinCatalogObservationBackendBindsHostAndCleanRuntimeEvidence(t *testing.T) {
	t.Parallel()
	catalog := verifiedObservationCatalog(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	host := observationHost(t)
	backend := nativeCatalogObservationBackend{
		host: func(CatalogObservationInput) (runtimeinstall.HostCapabilities, string, error) {
			return host, "15.5.0", nil
		},
		runtime: func(_ context.Context, _ CatalogObservationInput, application, endpoint string) (runtimeinstall.RuntimeDiscovery, bool, bool, error) {
			if application != catalogDockerApplicationPath || endpoint != "/Users/test/.docker/run/docker.sock" {
				return runtimeinstall.RuntimeDiscovery{}, false, false, ErrProbeFailed
			}
			return runtimeinstall.NewAbsentRuntimeDiscovery(), false, false, nil
		},
	}
	result, err := backend.ObserveCatalogRuntime(t.Context(), CatalogObservationInput{
		Catalog: catalog, CertifiedRuntime: certified,
		HostStorageTarget:    "/Users/test/Library/Application Support/AgentMemory",
		RuntimeEndpoint:      "unix:///Users/test/.docker/run/docker.sock",
		NativePublisherTrust: runtimecatalog.DigestBytes([]byte("certificate")),
	})
	if err != nil || result.Evidence.IsZero() || result.Host.Platform() != runtimeinstall.PlatformDarwin ||
		result.Discovery != runtimeinstall.NewAbsentRuntimeDiscovery() {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestDarwinCatalogRuntimeReportsAbsentOnlyWhenApplicationAndEndpointAreAbsent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	input := CatalogObservationInput{
		RuntimeEndpoint:      "unix://" + filepath.Join(root, "docker.sock"),
		NativePublisherTrust: runtimecatalog.DigestBytes([]byte("certificate")),
	}
	discovery, application, endpoint, err := observeDarwinCatalogRuntime(
		t.Context(), input, filepath.Join(root, "Docker.app"), filepath.Join(root, "docker.sock"),
	)
	if err != nil || application || endpoint || discovery != runtimeinstall.NewAbsentRuntimeDiscovery() {
		t.Fatalf("discovery=%+v app=%t endpoint=%t error=%v", discovery, application, endpoint, err)
	}
	if err := os.Mkdir(filepath.Join(root, "Docker.app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := observeDarwinCatalogRuntime(
		t.Context(), input, filepath.Join(root, "Docker.app"), filepath.Join(root, "docker.sock"),
	); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("unverified application error=%v", err)
	}
}

func TestDarwinCatalogObservationBackendRejectsInvalidAuthority(t *testing.T) {
	t.Parallel()
	backend := nativeCatalogObservationBackend{}
	if result, err := backend.ObserveCatalogRuntime(t.Context(), CatalogObservationInput{}); !errors.Is(err, ErrProvisionIntegrity) || !result.Evidence.IsZero() {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}
