package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestUnsignedReleaseAndMissingNativeHelperFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := (UnavailableSignedAuthority{}).ResolveLinuxAuthority(context.Background(), []byte("plan")); !errors.Is(err, runtimeport.ErrAuthorityUnavailable) {
		t.Fatalf("unavailable authority error = %v", err)
	}
	if _, err := (UnavailablePrivilegeBroker{}).Execute(context.Background(), runtimeport.PrivilegeRequest{}); !errors.Is(err, runtimeport.ErrPrivilegeUnavailable) {
		t.Fatalf("unavailable privilege broker error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (UnavailableSignedAuthority{}).ResolveLinuxAuthority(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled authority error = %v", err)
	}
	var nilContext context.Context
	if _, err := (UnavailablePrivilegeBroker{}).Execute(nilContext, runtimeport.PrivilegeRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil broker context error = %v", err)
	}
}
