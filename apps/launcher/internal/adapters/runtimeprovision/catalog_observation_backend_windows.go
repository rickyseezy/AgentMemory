//go:build windows

package runtimeprovision

import "context"

type unavailableCatalogObservationBackend struct{}

func newNativeCatalogObservationBackend() catalogObservationBackend {
	return unavailableCatalogObservationBackend{}
}

func (unavailableCatalogObservationBackend) ObserveCatalogRuntime(context.Context, CatalogObservationInput) (CatalogObservationResult, error) {
	return CatalogObservationResult{}, ErrProvisionIntegrity
}
