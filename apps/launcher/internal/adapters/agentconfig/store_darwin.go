//go:build darwin

// Package agentconfigadapter implements owner-bound Darwin filesystem semantics
// for a host-neutral JSON MCP configuration.
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
	"time"

	"golang.org/x/sys/unix"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	lockFileName       = ".agentmemory-config-v1.lock"
	maximumMetadataLen = 16 << 10
	renameNoReplace    = uint(1)
	renameExchange     = uint(2)
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

// DarwinStore is a symlink-resistant, owner-bound, receipt-driven Darwin Store.
// Its backup directory must be local, absolute, and owner-only.
type DarwinStore struct {
	backupDirectory string
	fault           func(faultStage) error
	processLock     chan struct{}
}

// NewDarwinStore validates the configured backup directory without creating it.
func NewDarwinStore(backupDirectory string) (*DarwinStore, error) {
	if !validAbsolutePath(backupDirectory) || backupDirectory == "/" {
		return nil, port.ErrInvalidArgument
	}
	processLock := make(chan struct{}, 1)
	processLock <- struct{}{}
	return &DarwinStore{backupDirectory: backupDirectory, processLock: processLock}, nil
}

// Detect observes only the explicitly addressed local file.
func (*DarwinStore) Detect(ctx context.Context, location port.ConfigLocation) (port.Detection, error) {
	if err := ctx.Err(); err != nil {
		return port.Detection{}, err
	}
	parent, name, err := openConfigParent(location, false)
	if errors.Is(err, port.ErrNotFound) {
		return port.NewDetection(false), nil
	}
	if err != nil {
		return port.Detection{}, err
	}
	defer func() { _ = parent.Close() }()
	_, _, readErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
	if errors.Is(readErr, port.ErrNotFound) {
		return port.NewDetection(false), nil
	}
	if readErr != nil {
		return port.Detection{}, readErr
	}
	return port.NewDetection(true), nil
}

// Read returns the exact owner-only regular-file bytes.
func (*DarwinStore) Read(ctx context.Context, location port.ConfigLocation) (port.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return port.Snapshot{}, err
	}
	parent, name, err := openConfigParent(location, false)
	if err != nil {
		return port.Snapshot{}, err
	}
	defer func() { _ = parent.Close() }()
	content, _, err := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
	if err != nil {
		return port.Snapshot{}, err
	}
	snapshot, err := port.NewSnapshot(true, content)
	if err != nil {
		return port.Snapshot{}, port.Wrap(port.ErrIntegrity, "read")
	}
	return snapshot, nil
}

// ApplyAtomic performs a locked compare-and-swap with durable backup and a
// prepared/committed transaction anchor. Replay can distinguish its own
// post-replace crash from coincidental external content.
func (s *DarwinStore) ApplyAtomic(ctx context.Context, location port.ConfigLocation, plan domain.MergePlan) (port.ApplyReceipt, error) {
	if err := ctx.Err(); err != nil {
		return port.ApplyReceipt{}, err
	}
	if !plan.Changed() || location.String() == "" || plan.AfterDigest().IsZero() {
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
	parent, name, err := openConfigParent(location, !plan.OriginalExisted())
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer func() { _ = parent.Close() }()
	backupDirectory, err := openDirectoryPath(s.backupDirectory, true, true)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer func() { _ = backupDirectory.Close() }()
	lock, err := acquireLock(ctx, int(backupDirectory.Fd()))
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	defer releaseLock(lock)

	current, currentStat, currentErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
	currentExists := currentErr == nil
	if currentErr != nil && !errors.Is(currentErr, port.ErrNotFound) {
		return port.ApplyReceipt{}, currentErr
	}
	metadata := newTransactionMetadata(location, plan)
	prepared, committed, metadataErr := transactionState(int(backupDirectory.Fd()), metadata)
	if metadataErr != nil {
		return port.ApplyReceipt{}, metadataErr
	}

	if currentExists && domain.DigestBytes(current).Equal(plan.AfterDigest()) {
		if !prepared && !committed {
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply replay")
		}
		if err := s.ensureBackup(int(backupDirectory.Fd()), location, plan); err != nil {
			return port.ApplyReceipt{}, err
		}
		if err := proveReplacedByTransaction(int(parent.Fd()), metadata, currentStat); err != nil {
			return port.ApplyReceipt{}, err
		}
		if !committed {
			if err := syncNamed(int(parent.Fd()), name); err != nil || darwinFullSync(parent) != nil {
				return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply replay sync")
			}
			if err := markCommitted(int(backupDirectory.Fd()), metadata); err != nil {
				return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply replay commit")
			}
		}
		if err := fsyncFD(int(backupDirectory.Fd()), "apply replay metadata sync"); err != nil {
			return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply replay metadata sync")
		}
		if err := cleanupApplyArtifacts(int(parent.Fd()), metadata, plan); err != nil {
			return port.ApplyReceipt{}, err
		}
		return applyReceipt(s.backupDirectory, location, plan)
	}
	if currentExists != plan.OriginalExisted() || (currentExists && !domain.DigestBytes(current).Equal(plan.BeforeDigest())) {
		return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply compare")
	}
	if committed {
		if err := resetCommittedDarwinTransaction(
			int(parent.Fd()), int(backupDirectory.Fd()), metadata, plan,
		); err != nil {
			return port.ApplyReceipt{}, err
		}
	}
	if err := s.ensureBackup(int(backupDirectory.Fd()), location, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := ensurePrepared(int(backupDirectory.Fd()), metadata); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := s.inject(faultAfterBackup, port.ErrIO); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := cleanupApplyArtifacts(int(parent.Fd()), metadata, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := prepareReplacement(int(parent.Fd()), metadata, after, currentStat); err != nil {
		return port.ApplyReceipt{}, err
	}
	_, replacementStat, err := readOwnedRegular(int(parent.Fd()), metadata.newName(), domain.MaxDocumentBytes)
	if err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := s.inject(faultBeforeReplace, port.ErrIO); err != nil {
		return port.ApplyReceipt{}, err
	}
	if plan.OriginalExisted() {
		if err := renameAt2(int(parent.Fd()), metadata.newName(), int(parent.Fd()), name, renameExchange); err != nil {
			return port.ApplyReceipt{}, mapFilesystemError(err, "apply exchange")
		}
		if err := s.inject(faultAfterExchange, port.ErrDurabilityAmbiguous); err != nil {
			return port.ApplyReceipt{}, err
		}
		old, oldStat, oldErr := readOwnedRegular(int(parent.Fd()), metadata.newName(), domain.MaxDocumentBytes)
		if oldErr != nil || !domain.DigestBytes(old).Equal(plan.BeforeDigest()) || !sameFile(oldStat, currentStat) {
			if oldErr == nil {
				_ = exchangeBackDarwin(
					int(parent.Fd()),
					name,
					metadata.newName(),
					plan.AfterDigest(),
					replacementStat,
					old,
					oldStat,
				)
			}
			_ = syncDarwinConflictState(int(parent.Fd()), name, metadata.newName())
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply post-compare")
		}
		published, publishedStat, publishedErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
		if publishedErr != nil || !domain.DigestBytes(published).Equal(plan.AfterDigest()) ||
			!sameFile(publishedStat, replacementStat) {
			_ = syncDarwinConflictState(int(parent.Fd()), name, metadata.newName())
			return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply published identity")
		}
		if err := archiveNamedDarwin(int(parent.Fd()), metadata.newName(), domain.MaxDocumentBytes); err != nil {
			return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply displaced journal")
		}
	} else {
		if err := renameAt2(int(parent.Fd()), metadata.newName(), int(parent.Fd()), name, renameNoReplace); err != nil {
			_ = cleanupApplyArtifacts(int(parent.Fd()), metadata, plan)
			if errors.Is(err, unix.EEXIST) {
				return port.ApplyReceipt{}, port.Wrap(port.ErrConflict, "apply create compare")
			}
			return port.ApplyReceipt{}, mapFilesystemError(err, "apply create")
		}
	}
	if err := s.inject(faultAfterReplace, port.ErrDurabilityAmbiguous); err != nil {
		return port.ApplyReceipt{}, err
	}
	if err := syncNamed(int(parent.Fd()), name); err != nil || darwinFullSync(parent) != nil {
		return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply sync")
	}
	if err := markCommitted(int(backupDirectory.Fd()), metadata); err != nil {
		return port.ApplyReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "apply commit")
	}
	if err := cleanupApplyArtifacts(int(parent.Fd()), metadata, plan); err != nil {
		return port.ApplyReceipt{}, err
	}
	return applyReceipt(s.backupDirectory, location, plan)
}

// RestoreBackup restores only while the current file and transaction anchor
// still match the receipt. External edits are never overwritten.
func (s *DarwinStore) RestoreBackup(ctx context.Context, location port.ConfigLocation, receipt port.ApplyReceipt) (port.RestoreReceipt, error) {
	if err := ctx.Err(); err != nil {
		return port.RestoreReceipt{}, err
	}
	if !receipt.Valid() || !receipt.Changed() || location.String() == "" {
		return port.RestoreReceipt{}, port.ErrInvalidArgument
	}
	if err := s.acquireProcessLock(ctx); err != nil {
		return port.RestoreReceipt{}, err
	}
	defer s.releaseProcessLock()
	if receipt.OriginalExisted() && receipt.BackupLocation() != filepath.Join(s.backupDirectory, backupName(location, receipt.BeforeDigest())) {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore binding")
	}
	backupDirectory, err := openDirectoryPath(s.backupDirectory, false, true)
	if err != nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore backup directory")
	}
	defer func() { _ = backupDirectory.Close() }()
	lock, err := acquireLock(ctx, int(backupDirectory.Fd()))
	if err != nil {
		return port.RestoreReceipt{}, err
	}
	defer releaseLock(lock)
	metadata := metadataFromReceipt(location, receipt)
	_, committed, err := transactionState(int(backupDirectory.Fd()), metadata)
	if err != nil || !committed {
		return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore transaction")
	}
	var before []byte
	if receipt.OriginalExisted() {
		before, _, err = readOwnedRegular(int(backupDirectory.Fd()), backupName(location, receipt.BeforeDigest()), domain.MaxDocumentBytes)
		if err != nil || !domain.DigestBytes(before).Equal(receipt.BeforeDigest()) {
			return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore backup")
		}
	}
	parent, name, err := openConfigParent(location, false)
	if errors.Is(err, port.ErrNotFound) && !receipt.OriginalExisted() {
		return port.NewRestoreReceipt(false, domain.Digest{})
	}
	if err != nil {
		return port.RestoreReceipt{}, err
	}
	defer func() { _ = parent.Close() }()
	current, currentStat, currentErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
	if errors.Is(currentErr, port.ErrNotFound) && !receipt.OriginalExisted() {
		if err := cleanupRestoreArtifact(int(parent.Fd()), metadata, receipt); err != nil {
			return port.RestoreReceipt{}, err
		}
		if darwinFullSync(parent) != nil {
			return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore absence replay sync")
		}
		return port.NewRestoreReceipt(false, domain.Digest{})
	}
	if currentErr != nil {
		return port.RestoreReceipt{}, currentErr
	}
	currentDigest := domain.DigestBytes(current)
	if receipt.OriginalExisted() && currentDigest.Equal(receipt.BeforeDigest()) {
		if err := cleanupRestoreArtifact(int(parent.Fd()), metadata, receipt); err != nil {
			return port.RestoreReceipt{}, err
		}
		if err := syncNamed(int(parent.Fd()), name); err != nil || darwinFullSync(parent) != nil {
			return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore replay sync")
		}
		return port.NewRestoreReceipt(true, receipt.BeforeDigest())
	}
	if !currentDigest.Equal(receipt.AfterDigest()) {
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore compare")
	}
	if receipt.OriginalExisted() {
		if err := writeNamedExact(int(parent.Fd()), metadata.restoreName(), before, domain.MaxDocumentBytes); err != nil {
			return port.RestoreReceipt{}, err
		}
		_, replacementStat, err := readOwnedRegular(int(parent.Fd()), metadata.restoreName(), domain.MaxDocumentBytes)
		if err != nil {
			return port.RestoreReceipt{}, err
		}
		if err := s.inject(faultBeforeRestoreReplace, port.ErrIO); err != nil {
			return port.RestoreReceipt{}, err
		}
		if err := renameAt2(int(parent.Fd()), metadata.restoreName(), int(parent.Fd()), name, renameExchange); err != nil {
			return port.RestoreReceipt{}, mapFilesystemError(err, "restore exchange")
		}
		if err := s.inject(faultAfterRestoreExchange, port.ErrDurabilityAmbiguous); err != nil {
			return port.RestoreReceipt{}, err
		}
		old, oldStat, oldErr := readOwnedRegular(int(parent.Fd()), metadata.restoreName(), domain.MaxDocumentBytes)
		if oldErr != nil || !domain.DigestBytes(old).Equal(receipt.AfterDigest()) || !sameFile(oldStat, currentStat) {
			if oldErr == nil {
				_ = exchangeBackDarwin(
					int(parent.Fd()),
					name,
					metadata.restoreName(),
					receipt.BeforeDigest(),
					replacementStat,
					old,
					oldStat,
				)
			}
			_ = syncDarwinConflictState(int(parent.Fd()), name, metadata.restoreName())
			return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore post-compare")
		}
		restored, restoredStat, restoredErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes)
		if restoredErr != nil || !domain.DigestBytes(restored).Equal(receipt.BeforeDigest()) ||
			!sameFile(restoredStat, replacementStat) {
			_ = syncDarwinConflictState(int(parent.Fd()), name, metadata.restoreName())
			return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore published identity")
		}
		if err := archiveNamedDarwin(int(parent.Fd()), metadata.restoreName(), domain.MaxDocumentBytes); err != nil {
			return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore displaced journal")
		}
		if err := syncNamed(int(parent.Fd()), name); err != nil || darwinFullSync(parent) != nil {
			return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore sync")
		}
		return port.NewRestoreReceipt(true, receipt.BeforeDigest())
	}
	quarantine := metadata.restoreName()
	if err := renameAt2(int(parent.Fd()), name, int(parent.Fd()), quarantine, renameNoReplace); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return port.RestoreReceipt{}, port.Wrap(port.ErrIntegrity, "restore quarantine")
		}
		return port.RestoreReceipt{}, mapFilesystemError(err, "restore remove")
	}
	if err := s.inject(faultAfterRestoreQuarantine, port.ErrDurabilityAmbiguous); err != nil {
		return port.RestoreReceipt{}, err
	}
	removed, removedStat, removedErr := readOwnedRegular(int(parent.Fd()), quarantine, domain.MaxDocumentBytes)
	if removedErr != nil || !domain.DigestBytes(removed).Equal(receipt.AfterDigest()) || !sameFile(removedStat, currentStat) {
		if removedErr == nil {
			if publishErr := publishBackDarwin(int(parent.Fd()), quarantine, name, removed, removedStat); publishErr != nil {
				_ = archiveNamedDarwin(int(parent.Fd()), quarantine, domain.MaxDocumentBytes)
			}
		}
		_ = syncDarwinConflictState(int(parent.Fd()), name, quarantine)
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore post-compare")
	}
	if err := s.inject(faultAfterRestoreJournal, port.ErrDurabilityAmbiguous); err != nil {
		return port.RestoreReceipt{}, err
	}
	if err := archiveNamedDarwin(int(parent.Fd()), quarantine, domain.MaxDocumentBytes); err != nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore quarantine journal")
	}
	if _, _, targetErr := readOwnedRegular(int(parent.Fd()), name, domain.MaxDocumentBytes); targetErr == nil {
		_ = darwinFullSync(parent)
		return port.RestoreReceipt{}, port.Wrap(port.ErrConflict, "restore concurrent create")
	} else if !errors.Is(targetErr, port.ErrNotFound) {
		return port.RestoreReceipt{}, targetErr
	}
	if darwinFullSync(parent) != nil {
		return port.RestoreReceipt{}, port.Wrap(port.ErrDurabilityAmbiguous, "restore remove sync")
	}
	return port.NewRestoreReceipt(false, domain.Digest{})
}

func (s *DarwinStore) ensureBackup(directoryFD int, location port.ConfigLocation, plan domain.MergePlan) error {
	if !plan.OriginalExisted() {
		return nil
	}
	return ensureImmutableFile(directoryFD, backupName(location, plan.BeforeDigest()), plan.BeforeContent(), domain.MaxDocumentBytes)
}

func (s *DarwinStore) inject(stage faultStage, category error) error {
	if s.fault != nil && s.fault(stage) != nil {
		return port.Wrap(category, "injected agent configuration fault")
	}
	return nil
}

func (s *DarwinStore) acquireProcessLock(ctx context.Context) error {
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

func (s *DarwinStore) releaseProcessLock() { s.processLock <- struct{}{} }

type transactionMetadata struct {
	LocationDigest     string `json:"location_sha256"`
	OriginalExisted    bool   `json:"original_existed"`
	BeforeDigest       string `json:"before_sha256"`
	AfterDigest        string `json:"after_sha256"`
	ManagedEntryDigest string `json:"managed_entry_sha256"`
}

func newTransactionMetadata(location port.ConfigLocation, plan domain.MergePlan) transactionMetadata {
	return transactionMetadata{
		LocationDigest:     locationDigest(location),
		OriginalExisted:    plan.OriginalExisted(),
		BeforeDigest:       plan.BeforeDigest().String(),
		AfterDigest:        plan.AfterDigest().String(),
		ManagedEntryDigest: plan.ManagedEntryDigest().String(),
	}
}

func metadataFromReceipt(location port.ConfigLocation, receipt port.ApplyReceipt) transactionMetadata {
	return transactionMetadata{
		LocationDigest:     locationDigest(location),
		OriginalExisted:    receipt.OriginalExisted(),
		BeforeDigest:       receipt.BeforeDigest().String(),
		AfterDigest:        receipt.AfterDigest().String(),
		ManagedEntryDigest: receipt.ManagedEntryDigest().String(),
	}
}

func (m transactionMetadata) anchorName() string {
	return "apply-v1-" + m.LocationDigest + "-" + m.AfterDigest + ".json"
}

func (m transactionMetadata) newName() string {
	return ".agentmemory-new-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m transactionMetadata) proofName() string {
	return ".agentmemory-proof-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

func (m transactionMetadata) restoreName() string {
	return ".agentmemory-restore-v1-" + m.LocationDigest + "-" + m.AfterDigest
}

type transactionAnchor struct {
	SchemaVersion uint32              `json:"schema_version"`
	State         string              `json:"state"`
	Transaction   transactionMetadata `json:"transaction"`
}

func (m transactionMetadata) bytes(state string) []byte {
	encoded, _ := json.Marshal(transactionAnchor{SchemaVersion: 1, State: state, Transaction: m})
	return append(encoded, '\n')
}

func transactionState(directoryFD int, metadata transactionMetadata) (bool, bool, error) {
	content, _, err := readOwnedRegular(directoryFD, metadata.anchorName(), maximumMetadataLen)
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

func ensurePrepared(directoryFD int, metadata transactionMetadata) error {
	prepared, committed, err := transactionState(directoryFD, metadata)
	if err != nil || prepared || committed {
		return err
	}
	return ensureImmutableFile(directoryFD, metadata.anchorName(), metadata.bytes("prepared"), maximumMetadataLen)
}

func markCommitted(directoryFD int, metadata transactionMetadata) error {
	prepared, committed, err := transactionState(directoryFD, metadata)
	if err != nil || committed {
		return err
	}
	if !prepared {
		return port.Wrap(port.ErrIntegrity, "missing prepared transaction")
	}
	name := metadata.anchorName()
	temporary := name + ".commit"
	if err := replaceNamedExact(
		directoryFD,
		temporary,
		name,
		metadata.bytes("committed"),
		metadata.bytes("prepared"),
		maximumMetadataLen,
	); err != nil {
		return err
	}
	return fsyncFD(directoryFD, "transaction directory sync")
}

func prepareReplacement(directoryFD int, metadata transactionMetadata, content []byte, original unix.Stat_t) error {
	if err := writeNamedExact(directoryFD, metadata.newName(), content, domain.MaxDocumentBytes); err != nil {
		return err
	}
	newContent, newStat, err := readOwnedRegular(directoryFD, metadata.newName(), domain.MaxDocumentBytes)
	if err != nil || domain.DigestBytes(newContent).String() != metadata.AfterDigest {
		return port.Wrap(port.ErrIntegrity, "replacement preparation")
	}
	proof := replacementProof{
		SchemaVersion:  1,
		AfterDigest:    metadata.AfterDigest,
		Device:         darwinDeviceIdentity(newStat.Dev),
		Inode:          newStat.Ino,
		OriginalExists: metadata.OriginalExisted,
		OriginalDevice: darwinDeviceIdentity(original.Dev),
		OriginalInode:  original.Ino,
	}
	proofBytes, encodeErr := json.Marshal(proof)
	if encodeErr != nil {
		return port.Wrap(port.ErrIntegrity, "replacement proof")
	}
	proofBytes = append(proofBytes, '\n')
	if err := ensureImmutableFile(directoryFD, metadata.proofName(), proofBytes, maximumMetadataLen); err != nil {
		return err
	}
	return fsyncFD(directoryFD, "replacement preparation sync")
}

func proveReplacedByTransaction(directoryFD int, metadata transactionMetadata, current unix.Stat_t) error {
	encoded, _, err := readOwnedRegular(directoryFD, metadata.proofName(), maximumMetadataLen)
	var proof replacementProof
	if err != nil || json.Unmarshal(encoded, &proof) != nil || proof.SchemaVersion != 1 ||
		proof.AfterDigest != metadata.AfterDigest || proof.Device != darwinDeviceIdentity(current.Dev) || proof.Inode != current.Ino ||
		proof.OriginalExists != metadata.OriginalExisted {
		return port.Wrap(port.ErrConflict, "apply replay proof")
	}
	if metadata.OriginalExisted {
		displaced, displacedStat, displacedErr := readOwnedRegular(directoryFD, metadata.newName(), domain.MaxDocumentBytes)
		if errors.Is(displacedErr, port.ErrNotFound) {
			displaced, displacedStat, displacedErr = readOwnedRegular(
				directoryFD,
				darwinArchiveName(metadata.newName(), proof.OriginalDevice, proof.OriginalInode),
				domain.MaxDocumentBytes,
			)
		} else if displacedErr == nil {
			if archiveErr := archiveNamedDarwin(directoryFD, metadata.newName(), domain.MaxDocumentBytes); archiveErr != nil {
				return port.Wrap(port.ErrConflict, "apply replay displaced archive")
			}
		}
		if displacedErr != nil || domain.DigestBytes(displaced).String() != metadata.BeforeDigest ||
			proof.OriginalDevice != darwinDeviceIdentity(displacedStat.Dev) || proof.OriginalInode != displacedStat.Ino {
			return port.Wrap(port.ErrConflict, "apply replay displaced proof")
		}
	}
	return nil
}

type replacementProof struct {
	SchemaVersion  uint32 `json:"schema_version"`
	AfterDigest    string `json:"after_sha256"`
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	OriginalExists bool   `json:"original_existed"`
	OriginalDevice uint64 `json:"original_device"`
	OriginalInode  uint64 `json:"original_inode"`
}

func cleanupApplyArtifacts(directoryFD int, metadata transactionMetadata, plan domain.MergePlan) error {
	proofBytes, _, proofErr := readOwnedRegular(directoryFD, metadata.proofName(), maximumMetadataLen)
	if proofErr == nil {
		var proof replacementProof
		if json.Unmarshal(proofBytes, &proof) != nil || proof.SchemaVersion != 1 ||
			proof.AfterDigest != metadata.AfterDigest || proof.OriginalExists != metadata.OriginalExisted {
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
	} {
		content, _, err := readOwnedRegular(directoryFD, artifact.name, domain.MaxDocumentBytes)
		if errors.Is(err, port.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		digest := domain.DigestBytes(content)
		matched := false
		for _, allowed := range artifact.digests {
			matched = matched || (!allowed.IsZero() && digest.Equal(allowed))
		}
		if !matched {
			return port.Wrap(port.ErrIntegrity, "transaction cleanup")
		}
	}
	return fsyncFD(directoryFD, "transaction cleanup sync")
}

func cleanupRestoreArtifact(directoryFD int, metadata transactionMetadata, receipt port.ApplyReceipt) error {
	content, _, err := readOwnedRegular(directoryFD, metadata.restoreName(), domain.MaxDocumentBytes)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	digest := domain.DigestBytes(content)
	if !digest.Equal(receipt.AfterDigest()) && !digest.Equal(receipt.BeforeDigest()) {
		return port.Wrap(port.ErrIntegrity, "restore cleanup")
	}
	return archiveNamedDarwin(directoryFD, metadata.restoreName(), domain.MaxDocumentBytes)
}

func resetCommittedDarwinTransaction(
	configDirectoryFD int,
	backupDirectoryFD int,
	metadata transactionMetadata,
	plan domain.MergePlan,
) error {
	proofBytes, _, proofErr := readOwnedRegular(configDirectoryFD, metadata.proofName(), maximumMetadataLen)
	if proofErr == nil {
		var proof replacementProof
		if json.Unmarshal(proofBytes, &proof) != nil || proof.SchemaVersion != 1 ||
			proof.AfterDigest != metadata.AfterDigest || proof.OriginalExists != metadata.OriginalExisted {
			return port.Wrap(port.ErrIntegrity, "reset transaction proof")
		}
		if err := archiveNamedDarwin(configDirectoryFD, metadata.proofName(), maximumMetadataLen); err != nil {
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
		{name: metadata.restoreName(), digests: []domain.Digest{plan.BeforeDigest(), plan.AfterDigest()}},
	} {
		if err := archiveAllowedDarwin(configDirectoryFD, artifact.name, artifact.digests, domain.MaxDocumentBytes); err != nil {
			return err
		}
	}
	if err := archiveAllowedDarwin(
		backupDirectoryFD,
		metadata.anchorName()+".commit",
		[]domain.Digest{domain.DigestBytes(metadata.bytes("prepared"))},
		maximumMetadataLen,
	); err != nil {
		return err
	}
	anchor, _, err := readOwnedRegular(backupDirectoryFD, metadata.anchorName(), maximumMetadataLen)
	if err != nil || string(anchor) != string(metadata.bytes("committed")) {
		return port.Wrap(port.ErrIntegrity, "reset committed transaction")
	}
	return archiveNamedDarwin(backupDirectoryFD, metadata.anchorName(), maximumMetadataLen)
}

func archiveAllowedDarwin(directoryFD int, name string, allowed []domain.Digest, maximum int) error {
	content, _, err := readOwnedRegular(directoryFD, name, maximum)
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
	return archiveNamedDarwin(directoryFD, name, maximum)
}

func archiveNamedDarwin(directoryFD int, name string, maximum int) error {
	content, stat, err := readOwnedRegular(directoryFD, name, maximum)
	if err != nil {
		return err
	}
	archive := darwinArchiveName(name, darwinDeviceIdentity(stat.Dev), stat.Ino)
	if err := renameAt2(directoryFD, name, directoryFD, archive, renameNoReplace); err != nil {
		return mapFilesystemError(err, "archive transaction journal")
	}
	archived, archivedStat, err := readOwnedRegular(directoryFD, archive, maximum)
	if err != nil || !sameFile(archivedStat, stat) ||
		!domain.DigestBytes(archived).Equal(domain.DigestBytes(content)) {
		return port.Wrap(port.ErrConflict, "archived journal changed")
	}
	if err := syncNamed(directoryFD, archive); err != nil {
		return err
	}
	if err := fsyncFD(directoryFD, "archive journal directory sync"); err != nil {
		return err
	}
	return nil
}

func darwinDeviceIdentity(device int32) uint64 {
	return uint64(uint32(device)) //nolint:gosec // dev_t is a signed ABI container; its bit pattern is the stable identity.
}

func darwinArchiveName(name string, device uint64, inode uint64) string {
	identity := fmt.Sprintf("%s:%x:%x", name, device, inode)
	return fmt.Sprintf(".agentmemory-journal-v1-%x", sha256.Sum256([]byte(identity)))
}

func applyReceipt(backupDirectory string, location port.ConfigLocation, plan domain.MergePlan) (port.ApplyReceipt, error) {
	backupLocation := ""
	backupDigest := domain.Digest{}
	if plan.OriginalExisted() {
		backupLocation = filepath.Join(backupDirectory, backupName(location, plan.BeforeDigest()))
		backupDigest = plan.BeforeDigest()
	}
	return port.NewApplyReceipt(true, plan.OriginalExisted(), plan.BeforeDigest(), plan.AfterDigest(), plan.ManagedEntryDigest(), backupLocation, backupDigest)
}

func backupName(location port.ConfigLocation, before domain.Digest) string {
	return "config-v1-" + locationDigest(location) + "-" + before.String() + ".json"
}

func locationDigest(location port.ConfigLocation) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(location.String())))
}

func validAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 &&
		!strings.ContainsAny(path, "\x00\r\n")
}

func openConfigParent(location port.ConfigLocation, create bool) (*os.File, string, error) {
	path := location.String()
	if !validAbsolutePath(path) || path == "/" || filepath.Dir(path) == "/" {
		return nil, "", port.ErrInvalidArgument
	}
	parent, err := openDirectoryPath(filepath.Dir(path), create, false)
	if err != nil {
		return nil, "", err
	}
	return parent, filepath.Base(path), nil
}

func openDirectoryPath(path string, create bool, privateFinal bool) (*os.File, error) {
	if !validAbsolutePath(path) {
		return nil, port.ErrInvalidArgument
	}
	currentFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, port.Wrap(port.ErrIO, "open directory root")
	}
	current := os.NewFile(uintptr(currentFD), "")
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		components = nil
	}
	for index, component := range components {
		nextFD, openErr := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			mkdirErr := unix.Mkdirat(int(current.Fd()), component, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = current.Close()
				return nil, mapFilesystemError(mkdirErr, "create directory")
			}
			nextFD, openErr = unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, unix.ENOENT) {
				return nil, port.ErrNotFound
			}
			return nil, mapFilesystemError(openErr, "open directory")
		}
		next := os.NewFile(uintptr(nextFD), "")
		_ = current.Close()
		current = next
		if index == len(components)-1 {
			var stat unix.Stat_t
			var filesystem unix.Statfs_t
			if unix.Fstat(int(current.Fd()), &stat) != nil || int64(stat.Uid) != int64(os.Geteuid()) ||
				(privateFinal && stat.Mode&0o077 != 0) || (!privateFinal && stat.Mode&0o022 != 0) ||
				darwinACLFree(current) != nil || unix.Fstatfs(int(current.Fd()), &filesystem) != nil ||
				!darwinFilesystemLocal(filesystem.Flags) {
				_ = current.Close()
				return nil, port.Wrap(port.ErrUnsafePath, "directory policy")
			}
		}
	}
	return current, nil
}

func darwinFilesystemLocal(flags uint32) bool { return flags&unix.MNT_LOCAL != 0 }

func readOwnedRegular(directoryFD int, name string, maximum int) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, unix.Stat_t{}, port.ErrNotFound
		}
		return nil, unix.Stat_t{}, mapFilesystemError(err, "open file")
	}
	file := os.NewFile(uintptr(fd), "")
	if file == nil {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, port.Wrap(port.ErrIO, "read file descriptor")
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	var pathStat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		unix.Fstatat(directoryFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, unix.Stat_t{}, port.Wrap(port.ErrIO, "inspect file")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || pathStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(pathStat.Uid) != int64(os.Geteuid()) ||
		stat.Mode&0o077 != 0 || pathStat.Mode&0o077 != 0 || stat.Nlink != 1 || pathStat.Nlink != 1 ||
		!sameFile(stat, pathStat) || stat.Size > int64(maximum) || darwinACLFree(file) != nil {
		return nil, unix.Stat_t{}, port.Wrap(port.ErrUnsafePath, "file policy")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, unix.Stat_t{}, port.Wrap(port.ErrIO, "read file")
	}
	if len(content) > maximum {
		return nil, unix.Stat_t{}, port.Wrap(port.ErrUnsafePath, "file size policy")
	}
	return content, stat, nil
}

func writeNamedExact(directoryFD int, name string, content []byte, maximum int) error {
	if len(content) > maximum {
		return port.ErrInvalidArgument
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		existing, _, readErr := readOwnedRegular(directoryFD, name, maximum)
		if readErr != nil || !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "existing transaction file")
		}
		return nil
	}
	if err != nil {
		return mapFilesystemError(err, "create transaction file")
	}
	file := os.NewFile(uintptr(fd), "")
	if file == nil {
		_ = unix.Close(fd)
		return port.Wrap(port.ErrIO, "create transaction descriptor")
	}
	var createdStat unix.Stat_t
	if unix.Fstat(fd, &createdStat) != nil || createdStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int64(createdStat.Uid) != int64(os.Geteuid()) || createdStat.Mode&0o077 != 0 ||
		createdStat.Nlink != 1 || darwinACLFree(file) != nil {
		_ = file.Close()
		return port.Wrap(port.ErrUnsafePath, "created transaction file policy")
	}
	writeErr := writeAndSync(file, content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return port.Wrap(port.ErrIO, "write transaction file")
	}
	return nil
}

func ensureImmutableFile(directoryFD int, name string, content []byte, maximum int) error {
	existing, _, err := readOwnedRegular(directoryFD, name, maximum)
	if err == nil {
		if !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "immutable file")
		}
		return nil
	}
	if !errors.Is(err, port.ErrNotFound) {
		return err
	}
	temporary := name + ".new"
	if err := writeNamedExact(directoryFD, temporary, content, maximum); err != nil {
		return err
	}
	if err := renameAt2(directoryFD, temporary, directoryFD, name, renameNoReplace); err != nil && !errors.Is(err, unix.EEXIST) {
		return mapFilesystemError(err, "publish immutable file")
	}
	published, _, err := readOwnedRegular(directoryFD, name, maximum)
	if err != nil || !domain.DigestBytes(published).Equal(domain.DigestBytes(content)) {
		return port.Wrap(port.ErrIntegrity, "verify immutable file")
	}
	return fsyncFD(directoryFD, "immutable directory sync")
}

func replaceNamedExact(
	directoryFD int,
	temporary string,
	destination string,
	content []byte,
	expectedDestination []byte,
	maximum int,
) error {
	if existing, _, err := readOwnedRegular(directoryFD, temporary, maximum); err == nil {
		if !domain.DigestBytes(existing).Equal(domain.DigestBytes(content)) {
			return port.Wrap(port.ErrIntegrity, "replacement metadata")
		}
	} else if errors.Is(err, port.ErrNotFound) {
		if err := writeNamedExact(directoryFD, temporary, content, maximum); err != nil {
			return err
		}
	} else {
		return err
	}
	destinationContent, destinationStat, destinationErr := readOwnedRegular(directoryFD, destination, maximum)
	if errors.Is(destinationErr, port.ErrNotFound) {
		if err := renameAt2(directoryFD, temporary, directoryFD, destination, renameNoReplace); err != nil {
			return mapFilesystemError(err, "publish metadata")
		}
		return nil
	}
	if destinationErr != nil {
		return destinationErr
	}
	if len(expectedDestination) == 0 ||
		!domain.DigestBytes(destinationContent).Equal(domain.DigestBytes(expectedDestination)) {
		return port.Wrap(port.ErrIntegrity, "replacement destination metadata")
	}
	if err := renameAt2(directoryFD, temporary, directoryFD, destination, renameExchange); err != nil {
		return mapFilesystemError(err, "replace metadata")
	}
	displaced, displacedStat, displacedErr := readOwnedRegular(directoryFD, temporary, maximum)
	if displacedErr != nil || !sameFile(displacedStat, destinationStat) ||
		!domain.DigestBytes(displaced).Equal(domain.DigestBytes(expectedDestination)) {
		return port.Wrap(port.ErrIntegrity, "displaced replacement metadata")
	}
	return nil
}

func writeAndSync(file *os.File, content []byte) error {
	for len(content) > 0 {
		written, err := file.Write(content)
		if err != nil {
			return err
		}
		content = content[written:]
	}
	return darwinFullSync(file)
}

func syncNamed(directoryFD int, name string) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapFilesystemError(err, "open sync target")
	}
	defer func() { _ = unix.Close(fd) }()
	if err := darwinFullSyncFD(fd); err != nil {
		return port.Wrap(port.ErrIO, "sync file")
	}
	return nil
}

func fsyncFD(fd int, operation string) error {
	if err := darwinFullSyncFD(fd); err != nil {
		return port.Wrap(port.ErrIO, operation)
	}
	return nil
}

func acquireLock(ctx context.Context, directoryFD int) (*os.File, error) {
	fd, err := unix.Openat(directoryFD, lockFileName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, mapFilesystemError(err, "open lock")
	}
	lock := os.NewFile(uintptr(fd), "")
	var stat unix.Stat_t
	var pathStat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		unix.Fstatat(directoryFD, lockFileName, &pathStat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(pathStat.Uid) != int64(os.Geteuid()) ||
		stat.Mode&0o077 != 0 || stat.Nlink != 1 || pathStat.Nlink != 1 ||
		!sameFile(stat, pathStat) || darwinACLFree(lock) != nil {
		_ = lock.Close()
		return nil, port.Wrap(port.ErrUnsafePath, "lock policy")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = lock.Close()
			return nil, mapFilesystemError(err, "acquire lock")
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func releaseLock(lock *os.File) {
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func exchangeBackDarwin(
	directoryFD int,
	targetName string,
	displacedName string,
	publishedDigest domain.Digest,
	publishedStat unix.Stat_t,
	displacedContent []byte,
	displacedStat unix.Stat_t,
) error {
	live, liveStat, err := readOwnedRegular(directoryFD, targetName, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(live).Equal(publishedDigest) || !sameFile(liveStat, publishedStat) {
		return port.Wrap(port.ErrConflict, "exchange-back target changed")
	}
	if err := renameAt2(directoryFD, displacedName, directoryFD, targetName, renameExchange); err != nil {
		return mapFilesystemError(err, "exchange back")
	}
	restored, restoredStat, err := readOwnedRegular(directoryFD, targetName, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(restored).Equal(domain.DigestBytes(displacedContent)) ||
		!sameFile(restoredStat, displacedStat) {
		return port.Wrap(port.ErrConflict, "exchange-back result changed")
	}
	return syncDarwinConflictState(directoryFD, targetName, displacedName)
}

func publishBackDarwin(
	directoryFD int,
	quarantineName string,
	targetName string,
	quarantinedContent []byte,
	quarantinedStat unix.Stat_t,
) error {
	if err := renameAt2(directoryFD, quarantineName, directoryFD, targetName, renameNoReplace); err != nil {
		return mapFilesystemError(err, "publish quarantine back")
	}
	restored, restoredStat, err := readOwnedRegular(directoryFD, targetName, domain.MaxDocumentBytes)
	if err != nil || !domain.DigestBytes(restored).Equal(domain.DigestBytes(quarantinedContent)) ||
		!sameFile(restoredStat, quarantinedStat) {
		return port.Wrap(port.ErrConflict, "quarantine republish changed")
	}
	return syncDarwinConflictState(directoryFD, targetName)
}

func syncDarwinConflictState(directoryFD int, names ...string) error {
	for _, name := range names {
		if _, _, err := readOwnedRegular(directoryFD, name, domain.MaxDocumentBytes); err == nil {
			if err := syncNamed(directoryFD, name); err != nil {
				return err
			}
		} else if !errors.Is(err, port.ErrNotFound) {
			return err
		}
	}
	return fsyncFD(directoryFD, "conflict journal directory sync")
}

func sameFile(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func darwinFullSync(file *os.File) error {
	if file == nil {
		return errors.New("darwin durability descriptor is absent")
	}
	return darwinFullSyncFD(int(file.Fd()))
}

func darwinFullSyncFD(fd int) error {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0)
	return err
}

func mapFilesystemError(err error, operation string) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return port.Wrap(port.ErrUnsafePath, operation)
	case errors.Is(err, unix.ENOENT):
		return port.ErrNotFound
	default:
		return port.Wrap(port.ErrIO, operation)
	}
}

func renameAt2(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
	var darwinFlags uint32
	switch flags {
	case renameNoReplace:
		darwinFlags = unix.RENAME_EXCL
	case renameExchange:
		darwinFlags = unix.RENAME_SWAP
	default:
		return unix.EINVAL
	}
	return unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, darwinFlags)
}

var _ port.Store = (*DarwinStore)(nil)
