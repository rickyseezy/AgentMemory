//go:build darwin

package filesystem

import (
	"context"
	"errors"
	"fmt"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var errDarwinOperationKeyNotProvided = errors.New("macOS operation key source did not provide key access")

// darwinOperationKeyJournal resolves Keychain material only during a single
// journal method and re-proves the controlled directory chain before access.
type darwinOperationKeyJournal struct {
	configRoot         string
	operationDirectory string
	path               string
	keys               bootstrapport.OperationKeySource
	keyRef             install.BootstrapKeyRef
	operationID        install.OperationID
	owner              install.OwnerBinding
}

var _ journalport.Journal = (*darwinOperationKeyJournal)(nil)

func (j *darwinOperationKeyJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.Append(ctx, expectedPreviousRevision, snapshot)
	})
}

func (j *darwinOperationKeyJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	var result journalport.Snapshot
	err := j.withJournal(ctx, func(inner *InstallJournal) error {
		loaded, loadError := inner.LoadLatest(ctx)
		result = loaded
		return loadError
	})
	return result, err
}

func (j *darwinOperationKeyJournal) ConfirmDurable(
	ctx context.Context,
	operationID string,
	revision uint64,
) error {
	return j.withJournal(ctx, func(inner *InstallJournal) error {
		return inner.ConfirmDurable(ctx, operationID, revision)
	})
}

func (j *darwinOperationKeyJournal) validateKeyAccess(ctx context.Context) error {
	return j.withJournal(ctx, func(*InstallJournal) error { return nil })
}

func (j *darwinOperationKeyJournal) withJournal(
	ctx context.Context,
	consumer func(*InstallJournal) error,
) error {
	if consumer == nil {
		return errors.New("macOS operation journal consumer is required")
	}
	if err := verifyDarwinOperationDirectory(ctx, j.configRoot, j.operationDirectory); err != nil {
		if errors.Is(err, bootstrapport.ErrNotFound) {
			return fmt.Errorf("%w: macOS operation directory disappeared", bootstrapport.ErrIntegrity)
		}
		return err
	}
	invoked := false
	err := j.keys.UseHMACKey(ctx, j.keyRef, j.operationID, j.owner, func(key []byte) error {
		if invoked {
			return errors.New("macOS operation key source invoked its consumer more than once")
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
		return errDarwinOperationKeyNotProvided
	}
	return nil
}
