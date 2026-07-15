package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

//lint:ignore U1000 platform-specific native host probes call this function
func privilegedDesktopCatalogContextOrUnavailable(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimecatalogapp.ErrDependencyUnavailable
}
