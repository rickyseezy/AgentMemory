//go:build linux

package launcher

import (
	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
)

func newPlatformJournalProvider(
	locator *bootstrapadapter.OperationLocator,
) (filesystem.OperationJournalProvider, error) {
	owners := bootstrapadapter.NewLinuxOwnerBindingSource()
	keys, err := filesystem.NewLinuxFileOperationKeySource(locator, owners)
	if err != nil {
		return nil, err
	}
	anchors, err := filesystem.NewLinuxFileRollbackAnchorStore(locator, keys, owners)
	if err != nil {
		return nil, err
	}
	return filesystem.NewLinuxOperationJournalProvider(locator, keys, owners, anchors)
}
