//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"testing"
)

func TestNativeLinuxHostBindingProviderRejectsMissingOrCancelledContext(t *testing.T) {
	t.Parallel()
	provider := NewNativeLinuxHostBindingProvider()
	var nilContext context.Context
	if _, err := provider.CurrentLinuxHostBinding(nilContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := provider.CurrentLinuxHostBinding(cancelledAuthorityContext()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}
