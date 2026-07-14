//go:build windows

// Package agentconfigadapter implements owner-bound Windows filesystem
// semantics for the host-neutral JSON MCP configuration contract.
package agentconfigadapter

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	windowsLockIdentityPrefix = "agentmemory:pf001:agent-config-store:v1:"
	maximumMetadataLen        = 16 << 10
)

type faultStage uint8

const (
	faultAfterBackup faultStage = iota + 1
	faultBeforeReplace
	faultAfterExchange
	faultAfterReplace
	faultBeforeRestoreReplace
	faultAfterRestoreExchange
	faultAfterRestoreQuarantine
	faultAfterRestoreJournal
)

// WindowsStore is the protected-DACL, reparse-resistant, receipt-driven
// Windows implementation of the agent configuration Store port.
type WindowsStore struct {
	backupDirectory string
	processLock     chan struct{}
	fault           func(faultStage) error
}

// NewWindowsStore validates the local backup location without creating state.
func NewWindowsStore(backupDirectory string) (*WindowsStore, error) {
	if windowssecurity.ValidateLocalPath(backupDirectory) != nil || filepath.Clean(backupDirectory) != backupDirectory ||
		filepath.Dir(backupDirectory) == backupDirectory {
		return nil, port.ErrInvalidArgument
	}
	processLock := make(chan struct{}, 1)
	processLock <- struct{}{}
	return &WindowsStore{backupDirectory: backupDirectory, processLock: processLock}, nil
}

// Detect observes only the explicitly addressed protected local file.
func (*WindowsStore) Detect(ctx context.Context, location port.ConfigLocation) (port.Detection, error) {
	if err := contextError(ctx); err != nil {
		return port.Detection{}, err
	}
	parent, target, err := openWindowsConfigParent(ctx, location, false)
	if errors.Is(err, port.ErrNotFound) {
		return port.NewDetection(false), nil
	}
	if err != nil {
		return port.Detection{}, err
	}
	defer func() { _ = parent.Close() }()
	_, _, err = readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
	if errors.Is(err, port.ErrNotFound) {
		return port.NewDetection(false), nil
	}
	if err != nil {
		return port.Detection{}, err
	}
	return port.NewDetection(true), nil
}

// Read returns exact bytes from an owner-only, single-link, ADS-free file.
func (*WindowsStore) Read(ctx context.Context, location port.ConfigLocation) (port.Snapshot, error) {
	if err := contextError(ctx); err != nil {
		return port.Snapshot{}, err
	}
	parent, target, err := openWindowsConfigParent(ctx, location, false)
	if err != nil {
		return port.Snapshot{}, err
	}
	defer func() { _ = parent.Close() }()
	content, _, err := readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
	if err != nil {
		return port.Snapshot{}, err
	}
	snapshot, err := port.NewSnapshot(true, content)
	if err != nil {
		return port.Snapshot{}, port.Wrap(port.ErrIntegrity, "read")
	}
	return snapshot, nil
}

// ApplyAtomic performs the receipt-bound backup and compare-and-swap mutation.
func (s *WindowsStore) ApplyAtomic(
	ctx context.Context,
	location port.ConfigLocation,
	plan domain.MergePlan,
) (port.ApplyReceipt, error) {
	if err := contextError(ctx); err != nil {
		return port.ApplyReceipt{}, err
	}
	if s == nil || !plan.Changed() || location.String() == "" || plan.AfterDigest().IsZero() {
		return port.ApplyReceipt{}, port.ErrInvalidArgument
	}
	after := plan.AfterContent()
	if err := domain.ValidateDocument(after); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := domain.VerifyManagedEntry(after, plan.Target()); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := s.acquireProcessLock(ctx); err != nil {
		return port.ApplyReceipt{}, err
	}
	defer s.releaseProcessLock()
	parent, target, err := openWindowsConfigParent(ctx, location, !plan.OriginalExisted())
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer func() { _ = parent.Close() }()
	backups, err := openWindowsDirectory(ctx, s.backupDirectory, true)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer func() { _ = backups.Close() }()
	mutex, err := s.acquireNativeLock(ctx)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer func() { _ = mutex.Release() }()

	current, currentIdentity, currentErr := readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
	currentExists := currentErr == nil
	if currentErr != nil && !errors.Is(currentErr, port.ErrNotFound) {
		return port.ApplyReceipt{}, currentErr
	}
	metadata := newWindowsTransactionMetadata(location, plan)
	prepared, committed, err := windowsTransactionState(ctx, s.backupDirectory, metadata)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	if currentExists && domain.DigestBytes(current).Equal(plan.AfterDigest()) {
		if !prepared && !committed {
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply replay")
		}
		if err := s.ensureWindowsBackup(ctx, location, plan); err != nil {
			return port.ApplyReceipt{}, err
		}
		if err := proveWindowsReplacement(ctx, filepath.Dir(target), metadata, currentIdentity); err != nil {
			return port.ApplyReceipt{}, err
		}
		if !committed {
			if err := syncWindowsPath(ctx, target, false); err != nil {
				return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply replay sync")
			}
			if err := markWindowsCommitted(ctx, s.backupDirectory, metadata); err != nil {
				return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply replay commit")
			}
		}
		if err := cleanupWindowsApplyArtifacts(ctx, filepath.Dir(target), metadata, plan); err != nil {
			return port.ApplyReceipt{}, err
		}
		return windowsApplyReceipt(s.backupDirectory, location, plan)
	}
	if currentExists != plan.OriginalExisted() ||
		(currentExists && !domain.DigestBytes(current).Equal(plan.BeforeDigest())) {
		return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply compare")
	}
	if committed {
		if err := resetCommittedWindowsTransaction(ctx, filepath.Dir(target), s.backupDirectory, metadata, plan); err != nil {
			return port.ApplyReceipt{}, err
		}
	}
	if err := s.ensureWindowsBackup(ctx, location, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := ensureWindowsPrepared(ctx, s.backupDirectory, metadata); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := s.inject(faultAfterBackup, port.ErrIO); err != nil {
		return port.ApplyReceipt{}, err
	}
	parentPath := filepath.Dir(target)
	if err := cleanupWindowsApplyArtifacts(ctx, parentPath, metadata, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	replacement := filepath.Join(parentPath, metadata.newName())
	if err := writeWindowsExact(ctx, replacement, after, domain.MaxDocumentBytes); err != nil {
		return port.ApplyReceipt{}, err
	}
	replacementIdentity, err := windowsFileIdentity(ctx, replacement)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := ensureWindowsReplacementProof(ctx, parentPath, metadata, replacementIdentity, currentIdentity); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := s.inject(faultBeforeReplace, port.ErrIO); err != nil {
		return port.ApplyReceipt{}, err
	}
	if plan.OriginalExisted() {
		displaced := filepath.Join(parentPath, metadata.oldName())
		if err := windowssecurity.AtomicExchange(ctx, replacement, target, displaced); err != nil {
			return port.ApplyReceipt{}, sanitizedWindowsError(err, port.ErrIO, "apply exchange")
		}
		if err := s.inject(faultAfterExchange, port.ErrDurabilityAmbiguous); err != nil {
			return port.ApplyReceipt{}, err
		}
		old, oldIdentity, oldErr := readWindowsOwned(ctx, displaced, domain.MaxDocumentBytes)
		if oldErr != nil || !domain.DigestBytes(old).Equal(plan.BeforeDigest()) || oldIdentity != currentIdentity {
			if oldErr == nil {
				_ = exchangeBackWindows(
					ctx,
					target,
					displaced,
					filepath.Join(parentPath, metadata.newName()),
					plan.AfterDigest(),
					replacementIdentity,
					old,
					oldIdentity,
				)
			}
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply post-compare")
		}
		published, publishedIdentity, publishedErr := readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
		if publishedErr != nil || !domain.DigestBytes(published).Equal(plan.AfterDigest()) ||
			publishedIdentity != replacementIdentity {
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply published identity")
		}
		if err := archiveWindowsNamed(ctx, displaced, domain.MaxDocumentBytes); err != nil {
			return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply displaced journal")
		}
	} else {
		published, publishErr := windowssecurity.AtomicPublishNoReplace(ctx, replacement, target)
		if publishErr != nil {
			return port.ApplyReceipt{}, sanitizedWindowsError(publishErr, port.ErrIO, "apply create")
		}
		if !published {
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply create compare")
		}
	}
	if err := s.inject(faultAfterReplace, port.ErrDurabilityAmbiguous); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := syncWindowsPath(ctx, target, false); err != nil {
		return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply sync")
	}
	if err := markWindowsCommitted(ctx, s.backupDirectory, metadata); err != nil {
		return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply commit")
	}
	if err := cleanupWindowsApplyArtifacts(ctx, parentPath, metadata, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	return windowsApplyReceipt(s.backupDirectory, location, plan)
}

// RestoreBackup restores only when the current file and committed transaction
// still match the apply receipt. External changes are never overwritten.
func (s *WindowsStore) RestoreBackup(
	ctx context.Context,
	location port.ConfigLocation,
	receipt port.ApplyReceipt,
) (port.RestoreReceipt, error) {
	if err := contextError(ctx); err != nil {
		return port.RestoreReceipt{}, err
	}
	if s == nil || !receipt.Valid() || !receipt.Changed() || location.String() == "" {
		return port.RestoreReceipt{}, port.ErrInvalidArgument
	}
	if receipt.OriginalExisted() && receipt.BackupLocation() != filepath.Join(
		s.backupDirectory,
		windowsBackupName(location, receipt.BeforeDigest()),
	) {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore binding")
	}
	if err := s.acquireProcessLock(ctx); err != nil {
		return port.RestoreReceipt{}, err
	}
	defer s.releaseProcessLock()
	backups, err := openWindowsDirectory(ctx, s.backupDirectory, false)
	if err != nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore backup directory")
	}
	defer func() { _ = backups.Close() }()
	mutex, err := s.acquireNativeLock(ctx)
	if err != nil {
		return port.RestoreReceipt{}, err
	}
	defer func() { _ = mutex.Release() }()
	metadata := windowsMetadataFromReceipt(location, receipt)
	_, committed, err := windowsTransactionState(ctx, s.backupDirectory, metadata)
	if err != nil || !committed {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore transaction")
	}
	var before []byte
	if receipt.OriginalExisted() {
		before, _, err = readWindowsOwned(ctx, receipt.BackupLocation(), domain.MaxDocumentBytes)
		if err != nil || !domain.DigestBytes(before).Equal(receipt.BeforeDigest()) {
			return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore backup")
		}
	}
	parent, target, err := openWindowsConfigParent(ctx, location, false)
	if errors.Is(err, port.ErrNotFound) && !receipt.OriginalExisted() {
		return port.NewRestoreReceipt(false, domain.Digest{})
	}
	if err != nil {
		return port.RestoreReceipt{}, err
	}
	defer func() { _ = parent.Close() }()
	parentPath := filepath.Dir(target)
	current, currentIdentity, currentErr := readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
	if errors.Is(currentErr, port.ErrNotFound) && !receipt.OriginalExisted() {
		if err := cleanupWindowsRestoreArtifact(ctx, parentPath, metadata, receipt); err != nil {
			return port.RestoreReceipt{}, err
		}
		return port.NewRestoreReceipt(false, domain.Digest{})
	}
	if currentErr != nil {
		return port.RestoreReceipt{}, currentErr
	}
	currentDigest := domain.DigestBytes(current)
	if receipt.OriginalExisted() && currentDigest.Equal(receipt.BeforeDigest()) {
		if err := cleanupWindowsRestoreArtifact(ctx, parentPath, metadata, receipt); err != nil {
			return port.RestoreReceipt{}, err
		}
		return port.NewRestoreReceipt(true, receipt.BeforeDigest())
	}
	if !currentDigest.Equal(receipt.AfterDigest()) {
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore compare")
	}
	if receipt.OriginalExisted() {
		replacement := filepath.Join(parentPath, metadata.restoreName())
		if err := writeWindowsExact(ctx, replacement, before, domain.MaxDocumentBytes); err != nil {
			return port.RestoreReceipt{}, err
		}
		if err := s.inject(faultBeforeRestoreReplace, port.ErrIO); err != nil {
			return port.RestoreReceipt{}, err
		}
		replacementIdentity, err := windowsFileIdentity(ctx, replacement)
		if err != nil {
			return port.RestoreReceipt{}, err
		}
		displaced := filepath.Join(parentPath, metadata.restoreDisplacedName())
		if err := windowssecurity.AtomicExchange(ctx, replacement, target, displaced); err != nil {
			return port.RestoreReceipt{}, sanitizedWindowsError(err, port.ErrIO, "restore exchange")
		}
		if err := s.inject(faultAfterRestoreExchange, port.ErrDurabilityAmbiguous); err != nil {
			return port.RestoreReceipt{}, err
		}
		old, oldIdentity, oldErr := readWindowsOwned(ctx, displaced, domain.MaxDocumentBytes)
		if oldErr != nil || !domain.DigestBytes(old).Equal(receipt.AfterDigest()) || oldIdentity != currentIdentity {
			if oldErr == nil {
				_ = exchangeBackWindows(
					ctx,
					target,
					displaced,
					filepath.Join(parentPath, metadata.restoreName()),
					receipt.BeforeDigest(),
					replacementIdentity,
					old,
					oldIdentity,
				)
			}
			return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore post-compare")
		}
		restored, restoredIdentity, restoredErr := readWindowsOwned(ctx, target, domain.MaxDocumentBytes)
		if restoredErr != nil || !domain.DigestBytes(restored).Equal(receipt.BeforeDigest()) ||
			restoredIdentity != replacementIdentity {
			return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore published identity")
		}
		if err := archiveWindowsNamed(ctx, displaced, domain.MaxDocumentBytes); err != nil {
			return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore displaced journal")
		}
		return port.NewRestoreReceipt(true, receipt.BeforeDigest())
	}
	quarantine := filepath.Join(parentPath, metadata.restoreName())
	moved, moveErr := windowssecurity.AtomicPublishNoReplace(ctx, target, quarantine)
	if moveErr != nil {
		return port.RestoreReceipt{}, sanitizedWindowsError(moveErr, port.ErrIO, "restore remove")
	}
	if !moved {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore quarantine")
	}
	if err := s.inject(faultAfterRestoreQuarantine, port.ErrDurabilityAmbiguous); err != nil {
		return port.RestoreReceipt{}, err
	}
	removed, removedIdentity, removedErr := readWindowsOwned(ctx, quarantine, domain.MaxDocumentBytes)
	if removedErr != nil || !domain.DigestBytes(removed).Equal(receipt.AfterDigest()) ||
		removedIdentity != currentIdentity {
		if removedErr == nil {
			_ = publishBackWindows(ctx, quarantine, target, removed, removedIdentity)
		}
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore post-compare")
	}
	if err := s.inject(faultAfterRestoreJournal, port.ErrDurabilityAmbiguous); err != nil {
		return port.RestoreReceipt{}, err
	}
	if err := archiveWindowsNamed(ctx, quarantine, domain.MaxDocumentBytes); err != nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore quarantine journal")
	}
	if _, _, targetErr := readWindowsOwned(ctx, target, domain.MaxDocumentBytes); targetErr == nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore concurrent create")
	} else if !errors.Is(targetErr, port.ErrNotFound) {
		return port.RestoreReceipt{}, targetErr
	}
	return port.NewRestoreReceipt(false, domain.Digest{})
}

func (s *WindowsStore) acquireProcessLock(ctx context.Context) error {
	if s == nil || s.processLock == nil {
		return port.ErrInvalidArgument
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.processLock:
		return nil
	}
}

func (s *WindowsStore) releaseProcessLock() { s.processLock <- struct{}{} }

func (s *WindowsStore) acquireNativeLock(ctx context.Context) (*windowssecurity.OwnerMutex, error) {
	identity := windowsLockIdentityPrefix + strings.ToLower(filepath.Clean(s.backupDirectory))
	name, err := windowssecurity.OwnerMutexName(identity)
	if err != nil {
		return nil, port.Wrap(port.ErrInvalidArgument, "lock identity")
	}
	mutex, err := windowssecurity.AcquireOwnerMutex(ctx, name)
	if err != nil {
		return nil, sanitizedWindowsError(err, port.ErrUnsafePath, "acquire lock")
	}
	return mutex, nil
}

func (s *WindowsStore) ensureWindowsBackup(
	ctx context.Context,
	location port.ConfigLocation,
	plan domain.MergePlan,
) error {
	if !plan.OriginalExisted() {
		return nil
	}
	path := filepath.Join(s.backupDirectory, windowsBackupName(location, plan.BeforeDigest()))
	return ensureWindowsImmutable(ctx, path, plan.BeforeContent(), domain.MaxDocumentBytes)
}

func (s *WindowsStore) inject(stage faultStage, category error) error {
	if s.fault != nil && s.fault(stage) != nil {
		return port.Wrap(category, "injected agent configuration fault")
	}
	return nil
}

type windowsTransactionMetadata struct {
	LocationDigest     string `json:"location_sha256"`
	OriginalExisted    bool   `json:"original_existed"`
	BeforeDigest       string `json:"before_sha256"`
	AfterDigest        string `json:"after_sha256"`
	ManagedEntryDigest string `json:"managed_entry_sha256"`
}

func newWindowsTransactionMetadata(
	location port.ConfigLocation,
	plan domain.MergePlan,
) windowsTransactionMetadata {
	return windowsTransactionMetadata{
		LocationDigest:     windowsLocationDigest(location),
		OriginalExisted:    plan.OriginalExisted(),
		BeforeDigest:       plan.BeforeDigest().String(),
		AfterDigest:        plan.AfterDigest().String(),
		ManagedEntryDigest: plan.ManagedEntryDigest().String(),
	}
}

func windowsMetadataFromReceipt(
	location port.ConfigLocation,
	receipt port.ApplyReceipt,
) windowsTransactionMetadata {
	return windowsTransactionMetadata{
		LocationDigest:     windowsLocationDigest(location),
		OriginalExisted:    receipt.OriginalExisted(),
		BeforeDigest:       receipt.BeforeDigest().String(),
		AfterDigest:        receipt.AfterDigest().String(),
		ManagedEntryDigest: receipt.ManagedEntryDigest().String(),
	}
}

func (m windowsTransactionMetadata) anchorName() string {
	return "apply-v1-" + m.LocationDigest + "-" + m.AfterDigest + ".json"
}

func (m windowsTransactionMetadata) newName() string {
	return ".agentmemory-new-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) proofName() string {
	return ".agentmemory-proof-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) oldName() string {
	return ".agentmemory-old-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) rollbackName() string {
	return ".agentmemory-rollback-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) restoreRollbackName() string {
	return ".agentmemory-restore-rollback-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) restoreName() string {
	return ".agentmemory-restore-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m windowsTransactionMetadata) restoreDisplacedName() string {
	return ".agentmemory-restore-old-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

type windowsTransactionAnchor struct {
	SchemaVersion uint32                     `json:"schema_version"`
	State         string                     `json:"state"`
	Transaction   windowsTransactionMetadata `json:"transaction"`
}

func (m windowsTransactionMetadata) bytes(state string) []byte {
	encoded, _ := json.Marshal(windowsTransactionAnchor{SchemaVersion: 1, State: state, Transaction: m})
	return append(encoded, '\n')
}

func windowsTransactionState(
	ctx context.Context,
	directory string,
	metadata windowsTransactionMetadata,
) (bool, bool, error) {
	content, _, err := readWindowsOwned(ctx, filepath.Join(directory, metadata.anchorName()), maximumMetadataLen)
	if errors.Is(err, port.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	switch string(content) {
	case string(metadata.bytes("prepared")):
		return true, false, nil
	case string(metadata.bytes("committed")):
		return true, true, nil
	default:
		return false, false, port.Wrap(port.ErrIntegrity, "transaction anchor")
	}
}

func ensureWindowsPrepared(ctx context.Context, directory string, metadata windowsTransactionMetadata) error {
	prepared, committed, err := windowsTransactionState(ctx, directory, metadata)
	if err != nil || prepared || committed {
		return err
	}
	return ensureWindowsImmutable(
		ctx,
		filepath.Join(directory, metadata.anchorName()),
		metadata.bytes("prepared"),
		maximumMetadataLen,
	)
}

func markWindowsCommitted(ctx context.Context, directory string, metadata windowsTransactionMetadata) error {
	prepared, committed, err := windowsTransactionState(ctx, directory, metadata)
	if err != nil || committed {
		return err
	}
	if !prepared {
		return port.Wrap(port.ErrIntegrity, "missing prepared transaction")
	}
	target := filepath.Join(directory, metadata.anchorName())
	temporary := target + ".commit"
	if err := writeWindowsExact(ctx, temporary, metadata.bytes("committed"), maximumMetadataLen); err != nil {
		return err
	}
	displaced := target + ".prepared"
	if err := windowssecurity.AtomicExchange(ctx, temporary, target, displaced); err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "replace transaction anchor")
	}
	preparedBytes, _, err := readWindowsOwned(ctx, displaced, maximumMetadataLen)
	if err != nil || string(preparedBytes) != string(metadata.bytes("prepared")) {
		return port.Wrap(port.ErrIntegrity, "displaced transaction anchor")
	}
	return nil
}

type windowsReplacementProof struct {
	SchemaVersion        uint32 `json:"schema_version"`
	AfterDigest          string `json:"after_sha256"`
	VolumeSerial         uint32 `json:"volume_serial"`
	FileIndex            uint64 `json:"file_index"`
	OriginalExisted      bool   `json:"original_existed"`
	OriginalVolumeSerial uint32 `json:"original_volume_serial"`
	OriginalFileIndex    uint64 `json:"original_file_index"`
}

func ensureWindowsReplacementProof(
	ctx context.Context,
	directory string,
	metadata windowsTransactionMetadata,
	identity windowssecurity.FileIdentity,
	original windowssecurity.FileIdentity,
) error {
	proof := windowsReplacementProof{
		SchemaVersion:        1,
		AfterDigest:          metadata.AfterDigest,
		VolumeSerial:         identity.VolumeSerial,
		FileIndex:            identity.FileIndex,
		OriginalExisted:      metadata.OriginalExisted,
		OriginalVolumeSerial: original.VolumeSerial,
		OriginalFileIndex:    original.FileIndex,
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return port.Wrap(port.ErrIntegrity, "replacement proof")
	}
	return ensureWindowsImmutable(
		ctx,
		filepath.Join(directory, metadata.proofName()),
		append(encoded, '\n'),
		maximumMetadataLen,
	)
}

func proveWindowsReplacement(
	ctx context.Context,
	directory string,
	metadata windowsTransactionMetadata,
	identity windowssecurity.FileIdentity,
) error {
	encoded, _, err := readWindowsOwned(ctx, filepath.Join(directory, metadata.proofName()), maximumMetadataLen)
	var proof windowsReplacementProof
	if err != nil || json.Unmarshal(encoded, &proof) != nil || proof.SchemaVersion != 1 ||
		proof.AfterDigest != metadata.AfterDigest || proof.VolumeSerial != identity.VolumeSerial ||
		proof.FileIndex != identity.FileIndex || identity.Directory ||
		proof.OriginalExisted != metadata.OriginalExisted {
		return port.Wrap(port.ErrConflict, "apply replay proof")
	}
	if metadata.OriginalExisted {
		displacedPath := filepath.Join(directory, metadata.oldName())
		displaced, displacedIdentity, displacedErr := readWindowsOwned(
			ctx,
			displacedPath,
			domain.MaxDocumentBytes,
		)
		if errors.Is(displacedErr, port.ErrNotFound) {
			displacedPath = filepath.Join(
				directory,
				windowsArchiveName(metadata.oldName(), windowssecurity.FileIdentity{
					VolumeSerial: proof.OriginalVolumeSerial,
					FileIndex:    proof.OriginalFileIndex,
				}),
			)
			displaced, displacedIdentity, displacedErr = readWindowsOwned(
				ctx,
				displacedPath,
				domain.MaxDocumentBytes,
			)
		} else if displacedErr == nil {
			if archiveErr := archiveWindowsNamed(ctx, displacedPath, domain.MaxDocumentBytes); archiveErr != nil {
				return port.Wrap(port.ErrConflict, "apply replay displaced archive")
			}
		}
		if displacedErr != nil || domain.DigestBytes(displaced).String() != metadata.BeforeDigest ||
			displacedIdentity.VolumeSerial != proof.OriginalVolumeSerial ||
			displacedIdentity.FileIndex != proof.OriginalFileIndex || displacedIdentity.Directory {
			return port.Wrap(port.ErrConflict, "apply replay displaced proof")
		}
	}
	return nil
}

func cleanupWindowsApplyArtifacts(
	ctx context.Context,
	directory string,
	metadata windowsTransactionMetadata,
	plan domain.MergePlan,
) error {
	proofPath := filepath.Join(directory, metadata.proofName())
	proofBytes, _, proofErr := readWindowsOwned(ctx, proofPath, maximumMetadataLen)
	if proofErr == nil {
		var proof windowsReplacementProof
		if json.Unmarshal(proofBytes, &proof) != nil || proof.SchemaVersion != 1 ||
			proof.AfterDigest != metadata.AfterDigest || proof.OriginalExisted != metadata.OriginalExisted {
			return port.Wrap(port.ErrIntegrity, "transaction proof cleanup")
		}
	} else if !errors.Is(proofErr, port.ErrNotFound) {
		return proofErr
	}
	for _, artifact := range []struct {
		name    string
		digests []domain.Digest
	}{
		{name: metadata.newName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.oldName(), digests: []domain.Digest{plan.BeforeDigest()}},
		{name: metadata.rollbackName(), digests: []domain.Digest{plan.AfterDigest(), plan.BeforeDigest()}},
	} {
		path := filepath.Join(directory, artifact.name)
		if err := validateWindowsAllowed(ctx, path, artifact.digests); err != nil && !errors.Is(err, port.ErrNotFound) {
			return err
		}
	}
	return syncWindowsPath(ctx, directory, true)
}

func cleanupWindowsRestoreArtifact(
	ctx context.Context,
	directory string,
	metadata windowsTransactionMetadata,
	receipt port.ApplyReceipt,
) error {
	for _, name := range []string{
		metadata.restoreName(),
		metadata.restoreDisplacedName(),
		metadata.restoreRollbackName(),
	} {
		err := archiveWindowsAllowed(
			ctx,
			filepath.Join(directory, name),
			[]domain.Digest{receipt.AfterDigest(), receipt.BeforeDigest()},
			domain.MaxDocumentBytes,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func resetCommittedWindowsTransaction(
	ctx context.Context,
	configDirectory string,
	backupDirectory string,
	metadata windowsTransactionMetadata,
	plan domain.MergePlan,
) error {
	proofPath := filepath.Join(configDirectory, metadata.proofName())
	proofBytes, _, proofErr := readWindowsOwned(ctx, proofPath, maximumMetadataLen)
	if proofErr == nil {
		var proof windowsReplacementProof
		if json.Unmarshal(proofBytes, &proof) != nil || proof.SchemaVersion != 1 ||
			proof.AfterDigest != metadata.AfterDigest || proof.OriginalExisted != metadata.OriginalExisted {
			return port.Wrap(port.ErrIntegrity, "reset transaction proof")
		}
		if err := archiveWindowsNamed(ctx, proofPath, maximumMetadataLen); err != nil {
			return err
		}
	} else if !errors.Is(proofErr, port.ErrNotFound) {
		return proofErr
	}
	for _, artifact := range []struct {
		name    string
		digests []domain.Digest
	}{
		{name: metadata.newName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.oldName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.rollbackName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.restoreName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.restoreDisplacedName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
		{name: metadata.restoreRollbackName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
	} {
		if err := archiveWindowsAllowed(
			ctx,
			filepath.Join(configDirectory, artifact.name),
			artifact.digests,
			domain.MaxDocumentBytes,
		); err != nil {
			return err
		}
	}
	for _, artifact := range []struct {
		suffix  string
		content []byte
	}{
		{suffix: ".commit", content: metadata.bytes("committed")},
		{suffix: ".prepared", content: metadata.bytes("prepared")},
		{suffix: ".new", content: metadata.bytes("prepared")},
	} {
		if err := archiveWindowsAllowed(
			ctx,
			filepath.Join(backupDirectory, metadata.anchorName()+artifact.suffix),
			[]domain.Digest{domain.DigestBytes(artifact.content)},
			maximumMetadataLen,
		); err != nil {
			return err
		}
	}
	anchorPath := filepath.Join(backupDirectory, metadata.anchorName())
	anchor, _, err := readWindowsOwned(ctx, anchorPath, maximumMetadataLen)
	if err != nil || string(anchor) != string(metadata.bytes("committed")) {
		return port.Wrap(port.ErrIntegrity, "reset committed transaction")
	}
	return archiveWindowsNamed(ctx, anchorPath, maximumMetadataLen)
}

func archiveWindowsAllowed(
	ctx context.Context,
	path string,
	allowed []domain.Digest,
	maximum int,
) error {
	content, _, err := readWindowsOwned(ctx, path, maximum)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	digest := domain.DigestBytes(content)
	matched := false
	for _, expected := range allowed {
		matched = matched || (!expected.IsZero() && digest.Equal(expected))
	}
	if !matched {
		return port.Wrap(port.ErrIntegrity, "archive transaction journal")
	}
	return archiveWindowsNamed(ctx, path, maximum)
}

func archiveWindowsNamed(ctx context.Context, path string, maximum int) error {
	content, identity, err := readWindowsOwned(ctx, path, maximum)
	if err != nil {
		return err
	}
	archive := filepath.Join(filepath.Dir(path), windowsArchiveName(filepath.Base(path), identity))
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, path, archive)
	if err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "archive transaction journal")
	}
	if !published {
		return port.Wrap(port.ErrConflict, "archive transaction journal occupied")
	}
	archived, archivedIdentity, err := readWindowsOwned(ctx, archive, maximum)
	if err != nil || archivedIdentity != identity ||
		!domain.DigestBytes(archived).Equal(domain.DigestBytes(content)) {
		return port.Wrap(port.ErrConflict, "archived journal changed")
	}
	return nil
}

func windowsArchiveName(name string, identity windowssecurity.FileIdentity) string {
	stableIdentity := fmt.Sprintf(
		"%s:%x:%x",
		strings.ToLower(filepath.Clean(name)),
		identity.VolumeSerial,
		identity.FileIndex,
	)
	return fmt.Sprintf(".agentmemory-journal-v1-%x", sha256.Sum256([]byte(stableIdentity)))
}

func windowsApplyReceipt(
	backupDirectory string,
	location port.ConfigLocation,
	plan domain.MergePlan,
) (port.ApplyReceipt, error) {
	backupLocation := ""
	backupDigest := domain.Digest{}
	if plan.OriginalExisted() {
		backupLocation = filepath.Join(backupDirectory, windowsBackupName(location, plan.BeforeDigest()))
		backupDigest = plan.BeforeDigest()
	}
	return port.NewApplyReceipt(
		true,
		plan.OriginalExisted(),
		plan.BeforeDigest(),
		plan.AfterDigest(),
		plan.ManagedEntryDigest(),
		backupLocation,
		backupDigest,
	)
}

func windowsBackupName(location port.ConfigLocation, before domain.Digest) string {
	return "config-v1-" + windowsLocationDigest(location) + "-" + before.String() + ".json"
}

func windowsLocationDigest(location port.ConfigLocation) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(filepath.Clean(location.String())))))
}

func openWindowsConfigParent(
	ctx context.Context,
	location port.ConfigLocation,
	create bool,
) (*os.File, string, error) {
	path := location.String()
	if windowssecurity.ValidateLocalPath(path) != nil || filepath.Clean(path) != path || filepath.Dir(path) == path {
		return nil, "", port.ErrInvalidArgument
	}
	parentPath := filepath.Dir(path)
	parent, err := openWindowsDirectory(ctx, parentPath, create)
	if err != nil {
		return nil, "", err
	}
	return parent, path, nil
}

func openWindowsDirectory(ctx context.Context, path string, create bool) (*os.File, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if windowssecurity.ValidateLocalPath(path) != nil {
		return nil, port.ErrInvalidArgument
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) || !create {
			return nil, err
		}
		if err := createWindowsPrivateChain(ctx, path); err != nil {
			return nil, err
		}
		if err := rejectWindowsReparseChain(path); err != nil {
			return nil, err
		}
	}
	file, _, err := windowssecurity.OpenVerified(ctx, path, true, true, true)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, sanitizedWindowsError(err, port.ErrUnsafePath, "open directory")
	}
	return file, nil
}

func rejectWindowsReparseChain(path string) error {
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(filepath.Clean(path), current)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		pointer, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return port.ErrInvalidArgument
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return os.ErrNotExist
		}
		if err != nil {
			return port.Wrap(port.ErrUnsafePath, "inspect directory")
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return port.Wrap(port.ErrUnsafePath, "directory reparse policy")
		}
	}
	return nil
}

func createWindowsPrivateChain(ctx context.Context, path string) error {
	missing := make([]string, 0, 4)
	current := filepath.Clean(path)
	for {
		if _, err := os.Lstat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return port.Wrap(port.ErrUnsafePath, "inspect directory")
		}
		if filepath.Dir(current) == current {
			return port.ErrNotFound
		}
		missing = append(missing, current)
		current = filepath.Dir(current)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := windowssecurity.CreatePrivateDirectory(ctx, missing[index]); err != nil &&
			!errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return sanitizedWindowsError(err, port.ErrIO, "create directory")
		}
		created, _, err := windowssecurity.OpenVerified(ctx, missing[index], true, true, true)
		if err != nil {
			return sanitizedWindowsError(err, port.ErrUnsafePath, "verify directory")
		}
		if err := windowssecurity.Flush(created); err != nil {
			_ = created.Close()
			return port.Wrap(port.ErrIO, "sync directory")
		}
		if err := created.Close(); err != nil {
			return port.Wrap(port.ErrIO, "close directory")
		}
	}
	return nil
}

func readWindowsOwned(
	ctx context.Context,
	path string,
	maximum int,
) ([]byte, windowssecurity.FileIdentity, error) {
	if maximum < 0 || windowssecurity.ValidateLocalPath(path) != nil {
		return nil, windowssecurity.FileIdentity{}, port.ErrInvalidArgument
	}
	file, identity, err := windowssecurity.OpenVerified(ctx, path, false, false, true)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, windowssecurity.FileIdentity{}, port.ErrNotFound
	}
	if err != nil {
		return nil, windowssecurity.FileIdentity{}, sanitizedWindowsError(err, port.ErrUnsafePath, "open file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > int64(maximum) {
		return nil, windowssecurity.FileIdentity{}, port.Wrap(port.ErrUnsafePath, "file size policy")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, windowssecurity.FileIdentity{}, port.Wrap(port.ErrIO, "read file")
	}
	if len(content) > maximum {
		return nil, windowssecurity.FileIdentity{}, port.Wrap(port.ErrUnsafePath, "file size policy")
	}
	if err := windowssecurity.VerifyPathIdentity(ctx, path, identity, true); err != nil {
		return nil, windowssecurity.FileIdentity{}, port.Wrap(port.ErrUnsafePath, "file identity")
	}
	return content, identity, nil
}

func writeWindowsExact(ctx context.Context, path string, content []byte, maximum int) error {
	if len(content) > maximum || windowssecurity.ValidateLocalPath(path) != nil {
		return port.ErrInvalidArgument
	}
	if existing, _, err := readWindowsOwned(ctx, path, maximum); err == nil {
		if !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "existing transaction file")
		}
		return nil
	} else if !errors.Is(err, port.ErrNotFound) {
		return err
	}
	file, err := windowssecurity.CreatePrivateFile(ctx, path)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		existing, _, readErr := readWindowsOwned(ctx, path, maximum)
		if readErr != nil || !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "existing transaction file")
		}
		return nil
	}
	if err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "create transaction file")
	}
	writeErr := writeAllWindows(file, content)
	flushErr := windowssecurity.Flush(file)
	closeErr := file.Close()
	if writeErr != nil || flushErr != nil || closeErr != nil {
		return port.Wrap(port.ErrIO, "write transaction file")
	}
	if _, _, err := readWindowsOwned(ctx, path, maximum); err != nil {
		return port.Wrap(port.ErrIntegrity, "verify transaction file")
	}
	return syncWindowsPath(ctx, filepath.Dir(path), true)
}

func writeAllWindows(file *os.File, content []byte) error {
	for len(content) > 0 {
		written, err := file.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func ensureWindowsImmutable(ctx context.Context, path string, content []byte, maximum int) error {
	if existing, _, err := readWindowsOwned(ctx, path, maximum); err == nil {
		if !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "immutable file")
		}
		return nil
	} else if !errors.Is(err, port.ErrNotFound) {
		return err
	}
	temporary := path + ".new"
	if err := writeWindowsExact(ctx, temporary, content, maximum); err != nil {
		return err
	}
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, temporary, path)
	if err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "publish immutable file")
	}
	if !published {
		if validateErr := validateWindowsAllowed(ctx, temporary, []domain.Digest{domain.DigestBytes(content)}); validateErr != nil {
			return validateErr
		}
	}
	observed, _, err := readWindowsOwned(ctx, path, maximum)
	if err != nil || !domain.DigestBytes(observed).Equal(domain.DigestBytes(content)) {
		return port.Wrap(port.ErrIntegrity, "verify immutable file")
	}
	return nil
}

func validateWindowsAllowed(ctx context.Context, path string, allowed []domain.Digest) error {
	content, _, err := readWindowsOwned(ctx, path, domain.MaxDocumentBytes)
	if err != nil {
		return err
	}
	digest := domain.DigestBytes(content)
	matched := false
	for _, expected := range allowed {
		matched = matched || (!expected.IsZero() && digest.Equal(expected))
	}
	if !matched {
		return port.Wrap(port.ErrIntegrity, "transaction cleanup")
	}
	return nil
}

func exchangeBackWindows(
	ctx context.Context,
	targetPath string,
	displacedPath string,
	journalPath string,
	publishedDigest domain.Digest,
	publishedIdentity windowssecurity.FileIdentity,
	displacedContent []byte,
	displacedIdentity windowssecurity.FileIdentity,
) error {
	live, liveIdentity, err := readWindowsOwned(ctx, targetPath, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(live).Equal(publishedDigest) || liveIdentity != publishedIdentity {
		return port.Wrap(port.ErrConflict, "exchange-back target changed")
	}
	if err := windowssecurity.AtomicExchange(ctx, displacedPath, targetPath, journalPath); err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "exchange back")
	}
	restored, restoredIdentity, err := readWindowsOwned(ctx, targetPath, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(restored).Equal(domain.DigestBytes(displacedContent)) ||
		restoredIdentity != displacedIdentity {
		return port.Wrap(port.ErrConflict, "exchange-back result changed")
	}
	return nil
}

func publishBackWindows(
	ctx context.Context,
	quarantinePath string,
	targetPath string,
	quarantinedContent []byte,
	quarantinedIdentity windowssecurity.FileIdentity,
) error {
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, quarantinePath, targetPath)
	if err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "publish quarantine back")
	}
	if !published {
		return port.Wrap(port.ErrConflict, "quarantine republish target occupied")
	}
	restored, restoredIdentity, err := readWindowsOwned(ctx, targetPath, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(restored).Equal(domain.DigestBytes(quarantinedContent)) ||
		restoredIdentity != quarantinedIdentity {
		return port.Wrap(port.ErrConflict, "quarantine republish changed")
	}
	return nil
}

func windowsFileIdentity(ctx context.Context, path string) (windowssecurity.FileIdentity, error) {
	file, identity, err := windowssecurity.OpenVerified(ctx, path, false, false, true)
	if err != nil {
		return windowssecurity.FileIdentity{}, sanitizedWindowsError(err, port.ErrUnsafePath, "open identity file")
	}
	if err := file.Close(); err != nil {
		return windowssecurity.FileIdentity{}, port.Wrap(port.ErrIO, "close identity file")
	}
	return identity, nil
}

func syncWindowsPath(ctx context.Context, path string, directory bool) error {
	file, _, err := windowssecurity.OpenVerified(ctx, path, directory, true, true)
	if err != nil {
		return sanitizedWindowsError(err, port.ErrIO, "open sync target")
	}
	if err := windowssecurity.Flush(file); err != nil {
		_ = file.Close()
		return port.Wrap(port.ErrIO, "sync target")
	}
	if err := file.Close(); err != nil {
		return port.Wrap(port.ErrIO, "close sync target")
	}
	return nil
}

func sanitizedWindowsError(err error, category error, operation string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, os.ErrNotExist) {
		return port.ErrNotFound
	}
	return port.Wrap(category, operation)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return port.ErrInvalidArgument
	}
	return ctx.Err()
}

var _ port.Store = (*WindowsStore)(nil)
