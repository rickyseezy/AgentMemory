//go:build darwin && !cgo

package runtimeprovision

import (
	"context"
	"errors"
	"testing"
)

func TestPF001DarwinNoCGOCatalogObservationFailsClosed(t *testing.T) {
	t.Parallel()
	backend := newNativeCatalogObservationBackend()
	if backend == nil {
		t.Fatal("no-cgo catalog observation backend returned nil")
	}
	result, err := backend.ObserveCatalogRuntime(context.Background(), CatalogObservationInput{})
	if !errors.Is(err, ErrProvisionIntegrity) || !result.Evidence.IsZero() {
		t.Fatalf("no-cgo catalog observation=%+v error=%v", result, err)
	}
}
