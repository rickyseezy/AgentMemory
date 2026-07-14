//go:build linux

package filesystem

import (
	"context"
	"errors"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// LinuxOperationJournalProvider resolves one digest-located, owner/key-bound
// anchored journal per operation. Callers acquire the machine-global install
// lock before repository access. No equivalent macOS or Windows security
// claim exists.
type LinuxOperationJournalProvider struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	anchors bootstrapport.RollbackAnchorStore
}

var _ OperationJournalProvider = (*LinuxOperationJournalProvider)(nil)

// NewLinuxOperationJournalProvider creates the Linux journal factory.
func NewLinuxOperationJournalProvider(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
	anchors bootstrapport.RollbackAnchorStore,
) (*LinuxOperationJournalProvider, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) || nilInterface(anchors) {
		return nil, errors.New("linux journal provider requires locator, key source, owner source, and rollback anchor")
	}
	return &LinuxOperationJournalProvider{locator: locator, keys: keys, owners: owners, anchors: anchors}, nil
}

// JournalFor verifies current owner binding, resolves the operation-specific
// key, and constructs the HMAC journal at its fixed digest path.
func (p *LinuxOperationJournalProvider) JournalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	owner, err := p.owners.Current(ctx)
	if err != nil {
		return nil, err
	}
	keyRef, err := p.keys.Ensure(ctx, operationID, owner)
	if err != nil {
		return nil, err
	}
	journalPath, err := p.locator.JournalPath(operationID)
	if err != nil {
		return nil, journalport.NewError(journalport.ErrorInvalidSnapshot, "locate", err)
	}
	journal := &linuxOperationKeyJournal{
		path:        journalPath,
		keys:        p.keys,
		keyRef:      keyRef,
		operationID: operationID,
		owner:       owner,
	}
	if err := journal.validateKeyAccess(ctx); err != nil {
		return nil, err
	}
	return bootstrapadapter.NewAnchoredJournal(journal, p.anchors, keyRef, operationID, owner)
}
