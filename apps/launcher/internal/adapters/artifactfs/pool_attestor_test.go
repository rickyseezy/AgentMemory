//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

func TestPF001PoolAttestorProbesHostEngineAndVolumeIndependently(t *testing.T) {
	t.Parallel()
	store, err := newStoreWithReservationAttestor(resolvedTempDir(t), func(*os.File) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	probe := &recordingDockerPoolProbe{}
	attestor, err := NewPoolAttestor(store, probe)
	if err != nil {
		t.Fatal(err)
	}
	host, err := attestor.Attest(context.Background(), artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS})
	if err != nil || host.ID() != store.filesystemID || probe.calls != 0 {
		t.Fatalf("host=%+v error=%v calls=%d", host, err, probe.calls)
	}
	engine, err := attestor.Attest(context.Background(), artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "engine"})
	if err != nil || engine.ID() != "docker-backing-pool" {
		t.Fatalf("engine=%+v error=%v", engine, err)
	}
	volume, err := attestor.Attest(context.Background(), artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: "volume"})
	if err != nil || volume.ID() != engine.ID() || probe.calls != 2 || probe.targets[0].Kind == probe.targets[1].Kind {
		t.Fatalf("volume=%+v error=%v calls=%d targets=%+v", volume, err, probe.calls, probe.targets)
	}
}

func TestPF001PoolAttestorFailsClosedAtEveryAuthorityBoundary(t *testing.T) {
	t.Parallel()

	if _, err := NewPoolAttestor(nil, valueDockerPoolProbe{}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("nil store error=%v", err)
	}
	unsafeStore, err := newStoreWithReservationAttestor(
		resolvedTempDir(t), func(*os.File) (bool, error) { return false, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unsafeStore.Close() })
	if _, err := NewPoolAttestor(unsafeStore, valueDockerPoolProbe{}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("unsafe store error=%v", err)
	}

	store, err := newStoreWithReservationAttestor(
		resolvedTempDir(t), func(*os.File) (bool, error) { return true, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var typedNil *recordingDockerPoolProbe
	if _, err := NewPoolAttestor(store, typedNil); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("typed-nil probe error=%v", err)
	}

	attestor, err := NewPoolAttestor(store, valueDockerPoolProbe{})
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves attestation fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := attestor.Attest(nil, artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := attestor.Attest(ctx, artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("cancelled context error=%v", err)
	}
	var absent *PoolAttestor
	if _, err := absent.Attest(context.Background(), artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("nil receiver error=%v", err)
	}
	if _, err := attestor.Attest(context.Background(), artifactapp.CapacityTarget{Kind: "foreign"}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("foreign target error=%v", err)
	}

	attestor.store.reservationSafe = false
	if _, err := attestor.Attest(context.Background(), artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("reservation-policy drift error=%v", err)
	}
}

func TestPF001PoolAttestorRejectsUnprovenDockerPool(t *testing.T) {
	t.Parallel()

	store, err := newStoreWithReservationAttestor(
		resolvedTempDir(t), func(*os.File) (bool, error) { return true, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, test := range []struct {
		name  string
		probe DockerPoolProbe
	}{
		{name: "probe error", probe: failingDockerPoolProbe{}},
		{name: "invalid pool", probe: invalidDockerPoolProbe{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			attestor, constructionError := NewPoolAttestor(store, test.probe)
			if constructionError != nil {
				t.Fatal(constructionError)
			}
			_, attestError := attestor.Attest(context.Background(), artifactapp.CapacityTarget{
				Kind: artifactapp.CapacityDockerEngine, Locator: "engine",
			})
			if !errors.Is(attestError, artifactapp.ErrReservationUnsupported) {
				t.Fatalf("Attest() error=%v", attestError)
			}
		})
	}
}

func TestPF001ProductionReservationRejectsSnapshotInvalidatedPoolBeforeSideEffects(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	safe, err := reservationFilesystemSafeDescriptor(store.rootDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if safe {
		t.Skip("host filesystem has non-CoW reservation semantics")
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	_, err = store.Reserve(context.Background(), fsReservationRequest(t, "cow-rejected", plan))
	if !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("Reserve() error=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".reservations"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("reservation side effects=%v error=%v", entries, err)
	}
	if _, err := NewPoolAttestor(store, &recordingDockerPoolProbe{}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("NewPoolAttestor() error=%v", err)
	}
}

type recordingDockerPoolProbe struct {
	calls   int
	targets []artifactapp.CapacityTarget
}

type valueDockerPoolProbe struct{}

func (valueDockerPoolProbe) AttestDockerPool(_ context.Context, target artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error) {
	return artifactacquisition.NewStoragePool("docker-backing-pool", target.Kind)
}

type failingDockerPoolProbe struct{}

func (failingDockerPoolProbe) AttestDockerPool(context.Context, artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error) {
	return artifactacquisition.StoragePool{}, errors.New("probe failed")
}

type invalidDockerPoolProbe struct{}

func (invalidDockerPoolProbe) AttestDockerPool(context.Context, artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error) {
	return artifactacquisition.StoragePool{}, nil
}

func (p *recordingDockerPoolProbe) AttestDockerPool(_ context.Context, target artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error) {
	p.calls++
	p.targets = append(p.targets, target)
	return artifactacquisition.NewStoragePool("docker-backing-pool", target.Kind)
}
