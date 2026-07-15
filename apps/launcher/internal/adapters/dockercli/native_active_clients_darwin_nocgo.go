//go:build darwin && !cgo

package dockercli

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

// NativeActiveRuntimeClientScanner is unavailable without the release's cgo native boundary.
type NativeActiveRuntimeClientScanner struct{}

// NewNativeActiveRuntimeClientScanner returns a fail-closed observer.
func NewNativeActiveRuntimeClientScanner() *NativeActiveRuntimeClientScanner {
	return &NativeActiveRuntimeClientScanner{}
}

// ScanActiveRuntimeClients refuses removal because native completeness cannot be proven.
func (*NativeActiveRuntimeClientScanner) ScanActiveRuntimeClients(
	context.Context,
	containerengine.Endpoint,
) (ActiveClientObservation, error) {
	return ActiveClientObservation{}, errors.New("macOS native active-client scan requires cgo")
}
