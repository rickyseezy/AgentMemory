package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

func privilegedDesktopCatalogContextOrUnavailable(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimecatalogapp.ErrDependencyUnavailable
}
