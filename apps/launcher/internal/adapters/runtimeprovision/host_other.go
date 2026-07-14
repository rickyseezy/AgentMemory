//go:build !linux

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// NativeHostProbe is a fail-closed placeholder on non-Linux build hosts.
type NativeHostProbe struct{}

// NewNativeHostProbe constructs a non-Linux fail-closed host probe.
func NewNativeHostProbe() *NativeHostProbe { return &NativeHostProbe{} }

// ProbeLinuxHost refuses Linux authority on a non-Linux host.
func (*NativeHostProbe) ProbeLinuxHost(
	ctx context.Context,
	_ runtimeport.LinuxAuthority,
) (HostEvidence, error) {
	if ctx == nil {
		return HostEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return HostEvidence{}, err
	}
	return HostEvidence{}, ErrUnsupportedHost
}

var _ HostProbe = (*NativeHostProbe)(nil)
