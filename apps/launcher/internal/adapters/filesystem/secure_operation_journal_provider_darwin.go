//go:build darwin

package filesystem

import (
	"context"
	"errors"
	"path/filepath"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// DarwinOperationJournalProvider resolves one digest-located, invoking-user,
// device, and Keychain-bound anchored journal per operation.
type DarwinOperationJournalProvider struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	anchors bootstrapport.RollbackAnchorStore
}

var _ OperationJournalProvider = (*DarwinOperationJournalProvider)(nil)

// NewDarwinOperationJournalProvider creates the native macOS journal factory.
func NewDarwinOperationJournalProvider(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
	anchors bootstrapport.RollbackAnchorStore,
) (*DarwinOperationJournalProvider, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) || nilInterface(anchors) {
		return nil, errors.New("macOS journal provider requires locator, key source, owner source, and rollback anchor")
	}
	return &DarwinOperationJournalProvider{locator: locator, keys: keys, owners: owners, anchors: anchors}, nil
}

// JournalFor proves the controlled directory hierarchy, provisions or resolves
// the operation Keychain item, and returns the rollback-anchored journal.
func (p *DarwinOperationJournalProvider) JournalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	owner, err := p.owners.Current(ctx)
	if err != nil {
		return nil, err
	}
	journalPath, err := p.locator.JournalPath(operationID)
	if err != nil {
		return nil, journalport.NewError(journalport.ErrorInvalidSnapshot, "locate", err)
	}
	operationDirectory, err := p.locator.OperationDirectory(operationID)
	if err != nil || filepath.Dir(journalPath) != operationDirectory {
		return nil, journalport.NewError(journalport.ErrorInvalidSnapshot, "locate", err)
	}
	if err := ensureDarwinOperationDirectory(ctx, p.locator.Root(), operationDirectory); err != nil {
		return nil, err
	}
	keyRef, err := p.keys.Ensure(ctx, operationID, owner)
	if err != nil {
		return nil, err
	}
	journal := &darwinOperationKeyJournal{
		configRoot:         p.locator.Root(),
		operationDirectory: operationDirectory,
		path:               journalPath,
		keys:               p.keys,
		keyRef:             keyRef,
		operationID:        operationID,
		owner:              owner,
	}
	if err := journal.validateKeyAccess(ctx); err != nil {
		return nil, err
	}
	return bootstrapadapter.NewAnchoredJournal(journal, p.anchors, keyRef, operationID, owner)
}
