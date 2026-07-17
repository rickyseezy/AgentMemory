//go:build darwin && !cgo

package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001DarwinNoCGODesktopHostBindingFailsClosed(t *testing.T) {
	t.Parallel()
	provider := NewNativeDesktopHostBindingProvider()
	if provider == nil {
		t.Fatal("no-cgo desktop host binding provider returned nil")
	}
	var nilContext context.Context
	if binding, err := provider.CurrentDesktopHostBinding(nilContext, runtimecatalog.Digest{}, ""); !errors.Is(err, ErrUnsupportedHost) || binding.HomeDirectory() != "" {
		t.Fatalf("nil-context binding=%+v error=%v", binding, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if binding, err := provider.CurrentDesktopHostBinding(cancelled, runtimecatalog.Digest{}, ""); !errors.Is(err, context.Canceled) || binding.HomeDirectory() != "" {
		t.Fatalf("cancelled binding=%+v error=%v", binding, err)
	}
	if binding, err := provider.CurrentDesktopHostBinding(context.Background(), runtimecatalog.Digest{}, ""); !errors.Is(err, ErrUnsupportedHost) || binding.HomeDirectory() != "" {
		t.Fatalf("unsupported binding=%+v error=%v", binding, err)
	}
}
