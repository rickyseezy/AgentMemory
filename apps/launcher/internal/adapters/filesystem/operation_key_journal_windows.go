//go:build windows

package filesystem

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var errWindowsOperationKeyNotProvided = errors.New("windows operation key source did not provide key access")

type windowsOperationKeyJournal struct {
	configRoot         string
	operationDirectory string
	path               string
	keys               bootstrapport.OperationKeySource
	keyRef             install.BootstrapKeyRef
	operationID        install.OperationID
	owner              install.OwnerBinding
}

var _ journalport.Journal = (*windowsOperationKeyJournal)(nil)

func (j *windowsOperationKeyJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.Append(ctx, expectedPreviousRevision, snapshot)
	})
}

func (j *windowsOperationKeyJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	var result journalport.Snapshot
	err := j.withJournal(ctx, func(inner *InstallJournal) error {
		loaded, loadError := inner.LoadLatest(ctx)
		result = loaded
		return loadError
	})
	return result, err
}

func (j *windowsOperationKeyJournal) ConfirmDurable(
	ctx context.Context,
	operationID string,
	revision uint64,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.ConfirmDurable(ctx, operationID, revision)
	})
}

func (j *windowsOperationKeyJournal) validateKeyAccess(ctx context.Context) error {
	return j.withJournal(ctx, func(*InstallJournal) error { return nil })
}

func (j *windowsOperationKeyJournal) withJournal(
	ctx context.Context,
	consumer func(*InstallJournal) error,
) error {
	if consumer == nil {
		return errors.New("windows operation journal consumer is required")
	}
	return windowssecurity.WithOperationDirectory(ctx, j.configRoot, j.operationDirectory, false, func() error {
		invoked := false
		err := j.keys.UseHMACKey(ctx, j.keyRef, j.operationID, j.owner, func(key []byte) error {
			if invoked {
				return errors.New("windows operation key source invoked its consumer more than once")
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
			return errWindowsOperationKeyNotProvided
		}
		return nil
	})
}
