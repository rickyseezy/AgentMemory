//go:build linux

package filesystem

import (
	"context"
	"errors"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// linuxOperationKeyJournal resolves key material only for the duration of one
// journal call. It prevents the provider from retaining a protected key copy
// in a long-lived journal value.
type linuxOperationKeyJournal struct {
	path        string
	keys        bootstrapport.OperationKeySource
	keyRef      install.BootstrapKeyRef
	operationID install.OperationID
	owner       install.OwnerBinding
}

var _ journalport.Journal = (*linuxOperationKeyJournal)(nil)

func (j *linuxOperationKeyJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.Append(ctx, expectedPreviousRevision, snapshot)
	})
}

func (j *linuxOperationKeyJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	var result journalport.Snapshot
	err := j.withJournal(ctx, func(inner *InstallJournal) error {
		loaded, loadError := inner.LoadLatest(ctx)
		result = loaded
		return loadError
	})
	return result, err
}

func (j *linuxOperationKeyJournal) ConfirmDurable(
	ctx context.Context,
	operationID string,
	revision uint64,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.ConfirmDurable(ctx, operationID, revision)
	})
}

func (j *linuxOperationKeyJournal) validateKeyAccess(ctx context.Context) error {
	return j.withJournal(ctx, func(*InstallJournal) error { return nil })
}

func (j *linuxOperationKeyJournal) withJournal(
	ctx context.Context,
	consumer func(*InstallJournal) error,
) error {
	if consumer == nil {
		return errors.New("linux operation journal consumer is required")
	}
	invoked := false
	err := j.keys.UseHMACKey(ctx, j.keyRef, j.operationID, j.owner, func(key []byte) error {
		if invoked {
			return errors.New("linux operation key source invoked its consumer more than once")
		}
		invoked = true
		inner, createError := NewInstallJournal(j.path, key)
		if createError != nil {
			return createError
		}
		defer clear(inner.key)
		return consumer(inner)
	})
	if err != nil {
		return err
	}
	if !invoked {
		return errors.New("linux operation key source did not provide key access")
	}
	return nil
}
