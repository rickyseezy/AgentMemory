//go:build windows

package launcher

import (
	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsent"
)

func newPlatformJournalProvider(
	locator *bootstrapadapter.OperationLocator,
) (filesystem.OperationJournalProvider, error) {
	owners, err := bootstrapadapter.NewWindowsOwnerBindingSource()
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewWindowsDPAPIOperationKeySource(locator, owners)
	if err != nil {
		return nil, err
	}
	anchors, err := filesystem.NewWindowsFileRollbackAnchorStore(locator, keys, owners)
	if err != nil {
		return nil, err
	}
	return filesystem.NewWindowsOperationJournalProvider(locator, keys, owners, anchors)
}

func newPlatformConsentSigner(
	locator *bootstrapadapter.OperationLocator,
) (*runtimeconsent.ProtectedSigner, error) {
	owners, err := bootstrapadapter.NewWindowsOwnerBindingSource()
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewWindowsDPAPIOperationKeySource(locator, owners)
	if err != nil {
		return nil, err
	}
	return runtimeconsent.NewProtectedSigner(owners, keys)
}
