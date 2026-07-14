//go:build !linux

package runtimeprovision

import (
	"context"
	"errors"
	"testing"
)

func TestNonLinuxNativeAdaptersAndClosedHelpersFailClosed(t *testing.T) {
	t.Parallel()
	_, authority := adapterAuthority(t)
	host := NewNativeHostProbe()
	if _, err := host.ProbeLinuxHost(context.Background(), authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("non-Linux host probe error = %v", err)
	}
	endpoint := NewNativeEndpointProbe()
	if _, err := endpoint.ProbeLinuxEndpoint(context.Background(), authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("non-Linux endpoint probe error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := host.ProbeLinuxHost(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled host probe error = %v", err)
	}
	if _, err := endpoint.ProbeLinuxEndpoint(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled endpoint probe error = %v", err)
	}
	var nilContext context.Context
	if _, err := host.ProbeLinuxHost(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil host context error = %v", err)
	}
	if _, err := endpoint.ProbeLinuxEndpoint(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil endpoint context error = %v", err)
	}
	if _, err := prepareNativeProbeWorkspace(context.Background(), authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("non-Linux workspace error = %v", err)
	}
	if _, err := prepareNativeProbeWorkspace(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil workspace context error = %v", err)
	}
	if _, err := prepareNativeProbeWorkspace(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled workspace error = %v", err)
	}
}
