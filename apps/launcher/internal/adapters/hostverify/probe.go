// Package hostverify contains PF-001's read-only platform-native host probe
// and its detached-signature trust adapter.
package hostverify

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

type collector interface {
	collect(context.Context, hostverification.Plan, string) (hostverification.ObservationInput, hostverification.FailureReason)
}

type closeableCollector interface {
	close(context.Context) error
}

// NativeProbe gathers host evidence using only fixed platform APIs and paths.
type NativeProbe struct{ collector collector }

// NewNativeProbe constructs the production build-tag-selected collector.
func NewNativeProbe() *NativeProbe { return &NativeProbe{collector: newNativeCollector()} }

// Close releases any platform worker owned by the probe. Callers must close a
// probe before replacing it or shutting down the installer process.
func (p *NativeProbe) Close(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if p == nil || p.collector == nil {
		return errors.New("native host probe is not initialized")
	}
	closer, ok := p.collector.(closeableCollector)
	if !ok {
		return ctx.Err()
	}
	return closer.close(ctx)
}

// ProbeHost returns a closed rejection whenever a native proof cannot be made.
func (p *NativeProbe) ProbeHost(
	ctx context.Context,
	plan hostverification.Plan,
	storageTarget string,
) (hostverification.ProbeResult, error) {
	if ctx == nil {
		return hostverification.ProbeResult{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return hostverification.ProbeResult{}, err
	}
	if p == nil || p.collector == nil || !plan.Valid() || storageTarget == "" {
		return hostverification.ProbeResult{}, errors.New("native host probe is not initialized")
	}
	if plan.StorageTargetMode() == hostverification.StorageTargetExact && storageTarget != plan.StorageTarget() {
		return hostverification.ProbeResult{}, errors.New("native host probe target is unauthorized")
	}
	input, reason := p.collector.collect(ctx, plan, storageTarget)
	if err := ctx.Err(); err != nil {
		return hostverification.ProbeResult{}, err
	}
	if reason != hostverification.FailureNone {
		return hostverification.NewRejectedResult(reason)
	}
	observation, err := hostverification.NewObservation(input)
	if err != nil {
		return hostverification.NewRejectedResult(hostverification.FailurePlatformProofUnavailable)
	}
	return hostverification.NewObservedResult(observation)
}

var _ hostverifyapp.NativeHostProbe = (*NativeProbe)(nil)
