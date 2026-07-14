//go:build !linux

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// NativeEndpointProbe is a fail-closed placeholder on non-Linux build hosts.
type NativeEndpointProbe struct{}

// NewNativeEndpointProbe constructs a non-Linux fail-closed endpoint probe.
func NewNativeEndpointProbe() *NativeEndpointProbe { return &NativeEndpointProbe{} }

// ProbeLinuxEndpoint refuses Linux socket authority on a non-Linux host.
func (*NativeEndpointProbe) ProbeLinuxEndpoint(
	ctx context.Context,
	_ runtimeport.LinuxAuthority,
) (EndpointEvidence, error) {
	if ctx == nil {
		return EndpointEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return EndpointEvidence{}, err
	}
	return EndpointEvidence{}, ErrUnsupportedHost
}

var _ EndpointProbe = (*NativeEndpointProbe)(nil)
