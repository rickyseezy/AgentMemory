//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// DockerPoolProbe is implemented by the runtime adapter that can inspect the
// engine's real data-root and named-volume backing allocation pool. It must
// return a stable non-path identity and fail when the daemon is remote, its
// backing store is snapshot-invalidated, or physical/quota charging cannot be
// proven.
type DockerPoolProbe interface {
	AttestDockerPool(context.Context, artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error)
}

// PoolAttestor combines the retained CAS descriptor proof with independent
// Docker engine/data-volume probes. It never assumes Docker's bytes are charged
// to the host path containing the launcher CAS.
type PoolAttestor struct {
	store  *Store
	docker DockerPoolProbe
}

// NewPoolAttestor binds host-CAS descriptor evidence and an independent
// Docker backing-pool capability.
func NewPoolAttestor(store *Store, docker DockerPoolProbe) (*PoolAttestor, error) {
	if store == nil || !store.valid() || !store.reservationSafe || nilPoolProbe(docker) {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return &PoolAttestor{store: store, docker: docker}, nil
}

// Attest returns the exact physical allocation pool for one closed capacity
// target, or fails when that pool cannot be proven.
func (a *PoolAttestor) Attest(ctx context.Context, target artifactapp.CapacityTarget) (artifactacquisition.StoragePool, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || a.store == nil || !a.store.beginOperation() {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationOperation
	}
	defer a.store.endOperation()
	if !a.store.reservationSafe || !a.store.valid() {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	switch target.Kind {
	case artifactapp.CapacityHostCAS:
		return artifactacquisition.NewStoragePool(a.store.filesystemID, artifactapp.CapacityHostCAS)
	case artifactapp.CapacityHostRelease:
		return attestHostReleasePool(target.Locator)
	case artifactapp.CapacityDockerEngine, artifactapp.CapacityDockerDataVolume:
		pool, err := a.docker.AttestDockerPool(ctx, target)
		if err != nil || !pool.Valid() {
			return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
		}
		return pool, nil
	default:
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
}

func nilPoolProbe(value DockerPoolProbe) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	return (r.Kind() == reflect.Pointer || r.Kind() == reflect.Interface || r.Kind() == reflect.Func || r.Kind() == reflect.Map || r.Kind() == reflect.Slice) && r.IsNil()
}

var _ artifactapp.CapacityPoolAttestor = (*PoolAttestor)(nil)
