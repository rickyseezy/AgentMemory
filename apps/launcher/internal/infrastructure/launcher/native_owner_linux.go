//go:build linux

package launcher

import (
	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
)

func newPlatformOwnerBindingSource() (bootstrapport.OwnerBindingSource, error) {
	return bootstrapadapter.NewLinuxOwnerBindingSource(), nil
}
