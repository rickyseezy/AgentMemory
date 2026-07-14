//go:build darwin

package launcher

import (
	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
)

func newPlatformJournalProvider(
	locator *bootstrapadapter.OperationLocator,
) (filesystem.OperationJournalProvider, error) {
	owners, err := bootstrapadapter.NewDarwinOwnerBindingSource()
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewDarwinKeychainOperationKeySource(owners)
	if err != nil {
		return nil, err
	}
	anchors, err := filesystem.NewDarwinFileRollbackAnchorStore(locator, keys, owners)
	if err != nil {
		return nil, err
	}
	return filesystem.NewDarwinOperationJournalProvider(locator, keys, owners, anchors)
}
