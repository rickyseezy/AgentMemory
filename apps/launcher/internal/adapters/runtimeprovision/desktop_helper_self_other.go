//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func (*NativeDesktopHelperExecutableVerifier) verifyDesktopHelperSelf(
	context.Context,
	releaseinventory.Resource,
	runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return runtimeinstall.Hash{}, ErrUnsupportedHost
}
