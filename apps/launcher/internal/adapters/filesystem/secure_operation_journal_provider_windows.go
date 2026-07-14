//go:build windows

package filesystem

import (
	"context"
	"errors"
	"path/filepath"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// WindowsOperationJournalProvider creates owner/SID/DPAPI-bound anchored
// journals under the fixed digest-only operation path.
type WindowsOperationJournalProvider struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	anchors bootstrapport.RollbackAnchorStore
}

var _ OperationJournalProvider = (*WindowsOperationJournalProvider)(nil)

// NewWindowsOperationJournalProvider creates the Windows journal factory.
func NewWindowsOperationJournalProvider(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
	anchors bootstrapport.RollbackAnchorStore,
) (*WindowsOperationJournalProvider, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) || nilInterface(anchors) {
		return nil, errors.New("windows journal provider requires locator, key source, owner source, and rollback anchor")
	}
	return &WindowsOperationJournalProvider{locator: locator, keys: keys, owners: owners, anchors: anchors}, nil
}

// JournalFor validates the owner and complete protected tree before resolving
// an operation-specific key and exposing only the anchored journal.
func (p *WindowsOperationJournalProvider) JournalFor(
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
		return nil, journalport.NewError(journalport.ErrorInvalidSnapshot, "locate", errors.New("journal escaped operation directory"))
	}
	if err := windowssecurity.EnsureOperationDirectory(ctx, p.locator.Root(), operationDirectory); err != nil {
		return nil, err
	}
	keyRef, err := p.keys.Ensure(ctx, operationID, owner)
	if err != nil {
		return nil, err
	}
	journal := &windowsOperationKeyJournal{
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
