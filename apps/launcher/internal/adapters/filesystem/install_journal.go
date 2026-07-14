//go:build linux || darwin || windows

// Package filesystem contains owner-only, crash-safe host filesystem adapters.
package filesystem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

const (
	journalFormatVersion = 1
	maximumJournalBytes  = 16 << 20
	maximumPayloadBytes  = 4 << 20
	maximumEntries       = 4096
	minimumHMACKeyBytes  = 32
)

var zeroHash = strings.Repeat("0", sha256.Size*2)

type persistedJournal struct {
	FormatVersion int              `json:"format_version"`
	OperationID   string           `json:"operation_id"`
	Entries       []persistedEntry `json:"entries"`
	TerminalHash  string           `json:"terminal_hash"`
	MAC           string           `json:"mac"`
}

type persistedEntry struct {
	Revision     uint64          `json:"revision"`
	CapturedAt   string          `json:"captured_at"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash string          `json:"previous_hash"`
	Hash         string          `json:"hash"`
	MAC          string          `json:"mac"`
}

type writeCheckpoint uint8

const (
	checkpointTempCreated writeCheckpoint = iota + 1
	checkpointTempWritten
	checkpointTempSynced
	checkpointTempClosed
	checkpointRenamed
	checkpointDirectorySynced
)

type checkpointHook func(writeCheckpoint) error

// InstallJournal persists the full authenticated checkpoint history in one
// atomically replaced file. Callers must still hold the installation's
// cross-process single-writer lock; the mutex below protects one adapter value.
type InstallJournal struct {
	path string
	key  []byte
	hook checkpointHook
	mu   sync.Mutex
}

var _ journalport.Journal = (*InstallJournal)(nil)

// NewInstallJournal creates a journal bound to path. The HMAC key is copied
// and must come from an owner-protected installation secret, not configuration.
func NewInstallJournal(path string, hmacKey []byte) (*InstallJournal, error) {
	return newInstallJournal(path, hmacKey, nil)
}

func newInstallJournal(path string, hmacKey []byte, hook checkpointHook) (*InstallJournal, error) {
	if strings.TrimSpace(path) == "" {
		return nil, journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"configure",
			errors.New("journal path is empty"),
		)
	}
	if len(hmacKey) < minimumHMACKeyBytes {
		return nil, journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"configure",
			fmt.Errorf("HMAC key must contain at least %d bytes", minimumHMACKeyBytes),
		)
	}

	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, journalport.NewError(journalport.ErrorInvalidSnapshot, "configure", err)
	}

	return &InstallJournal{
		path: cleanPath,
		key:  append([]byte(nil), hmacKey...),
		hook: hook,
	}, nil
}

// Append verifies all existing entries, appends exactly one revision, and
// atomically replaces the journal. A stale expected revision is rejected.
func (j *InstallJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "append", err)
	}
	if err := validateSnapshot(expectedPreviousRevision, snapshot); err != nil {
		return err
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.ensurePrivateParent(ctx); err != nil {
		return err
	}
	if err := j.removeAbandonedTemporaryFiles(ctx); err != nil {
		return err
	}

	document, err := j.loadDocument(ctx)
	switch {
	case err == nil:
		latest := document.Entries[len(document.Entries)-1]
		if document.OperationID != snapshot.OperationID {
			return journalport.NewError(
				journalport.ErrorConflict,
				"append",
				fmt.Errorf("operation ID does not match existing journal"),
			)
		}
		if latest.Revision != expectedPreviousRevision {
			return journalport.NewError(
				journalport.ErrorConflict,
				"append",
				fmt.Errorf("expected revision %d, found %d", expectedPreviousRevision, latest.Revision),
			)
		}
	case errors.Is(err, journalport.ErrNotFound):
		if expectedPreviousRevision != 0 {
			return journalport.NewError(
				journalport.ErrorConflict,
				"append",
				fmt.Errorf("expected revision %d, but journal does not exist", expectedPreviousRevision),
			)
		}
		document = persistedJournal{
			FormatVersion: journalFormatVersion,
			OperationID:   snapshot.OperationID,
		}
	default:
		return err
	}

	if len(document.Entries) >= maximumEntries {
		return journalport.NewError(
			journalport.ErrorIO,
			"append",
			fmt.Errorf("journal entry limit %d reached", maximumEntries),
		)
	}

	payload := compactJSON(snapshot.Payload)
	previousHash := zeroHash
	if len(document.Entries) != 0 {
		previousHash = document.Entries[len(document.Entries)-1].Hash
	}
	entry := persistedEntry{
		Revision:     snapshot.Revision,
		CapturedAt:   snapshot.CapturedAt.UTC().Format(time.RFC3339Nano),
		Payload:      payload,
		PreviousHash: previousHash,
	}
	entry.Hash = hashEntry(document.OperationID, entry)
	entry.MAC = j.entryMAC(entry.Hash)
	document.Entries = append(document.Entries, entry)
	document.TerminalHash = entry.Hash
	document.MAC = j.documentMAC(document)

	encoded, err := json.Marshal(document)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "encode", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumJournalBytes {
		return journalport.NewError(
			journalport.ErrorIO,
			"append",
			fmt.Errorf("journal exceeds %d bytes", maximumJournalBytes),
		)
	}

	return j.writeAtomically(ctx, encoded)
}

// LoadLatest authenticates the complete history before returning its newest
// application snapshot. No partially verified state is returned.
func (j *InstallJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return journalport.Snapshot{}, journalport.NewError(journalport.ErrorIO, "load", err)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	document, err := j.loadDocument(ctx)
	if err != nil {
		return journalport.Snapshot{}, err
	}
	latest := document.Entries[len(document.Entries)-1]
	capturedAt, _ := time.Parse(time.RFC3339Nano, latest.CapturedAt)
	return journalport.Snapshot{
		OperationID: document.OperationID,
		Revision:    latest.Revision,
		CapturedAt:  capturedAt,
		Payload:     append(json.RawMessage(nil), latest.Payload...),
	}, nil
}

// ConfirmDurable re-authenticates an already-visible revision and synchronizes
// both the journal file and its parent directory. This makes retry safe when a
// prior Append renamed the new journal but returned an ambiguous post-rename
// I/O error before durability could be acknowledged.
func (j *InstallJournal) ConfirmDurable(ctx context.Context, operationID string, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "confirm", err)
	}
	if !validOperationID(operationID) || revision == 0 {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"confirm",
			errors.New("operation ID and positive revision are required"),
		)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	document, err := j.loadDocument(ctx)
	if err != nil {
		return err
	}
	latest := document.Entries[len(document.Entries)-1]
	if document.OperationID != operationID || latest.Revision != revision {
		return journalport.NewError(
			journalport.ErrorConflict,
			"confirm",
			errors.New("journal revision changed before durability confirmation"),
		)
	}
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "confirm", err)
	}
	if err := j.syncCurrentFile(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "confirm", err)
	}
	return syncDirectory(ctx, filepath.Dir(j.path))
}

func (j *InstallJournal) syncCurrentFile(ctx context.Context) error {
	fileInfo, err := os.Lstat(j.path)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "confirm_inspect", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"confirm_inspect",
			errors.New("journal must remain a regular file and not a symbolic link"),
		)
	}
	if err := verifyCurrentOwner(fileInfo, "confirm_inspect"); err != nil {
		return err
	}
	if platformUnsafePermissions(fileInfo) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"confirm_inspect",
			errors.New("journal permissions changed before durability confirmation"),
		)
	}

	file, err := openVerifiedProtectedObject(ctx, j.path, fileInfo, "confirm_open")
	if err != nil {
		return err
	}
	if err := platformDurableSync(file); err != nil {
		_ = file.Close()
		return journalport.NewError(journalport.ErrorIO, "confirm_sync", err)
	}
	if err := file.Close(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "confirm_close", err)
	}
	return nil
}

func validateSnapshot(expectedPreviousRevision uint64, snapshot journalport.Snapshot) error {
	if !validOperationID(snapshot.OperationID) {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"append",
			errors.New("operation ID is empty, too long, or contains unsupported characters"),
		)
	}
	if expectedPreviousRevision == ^uint64(0) || snapshot.Revision != expectedPreviousRevision+1 {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"append",
			fmt.Errorf("revision %d must follow expected revision %d", snapshot.Revision, expectedPreviousRevision),
		)
	}
	if snapshot.CapturedAt.IsZero() {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"append",
			errors.New("capture time is required"),
		)
	}
	if len(snapshot.Payload) == 0 || len(snapshot.Payload) > maximumPayloadBytes || !json.Valid(snapshot.Payload) {
		return journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"append",
			fmt.Errorf("payload must be valid JSON no larger than %d bytes", maximumPayloadBytes),
		)
	}
	return nil
}

func validOperationID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	return true
}

func compactJSON(value json.RawMessage) json.RawMessage {
	var output bytes.Buffer
	_ = json.Compact(&output, value)
	return append(json.RawMessage(nil), output.Bytes()...)
}

func (j *InstallJournal) loadDocument(ctx context.Context) (persistedJournal, error) {
	if err := verifyPrivateDirectory(ctx, filepath.Dir(j.path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedJournal{}, journalport.NewError(journalport.ErrorNotFound, "load", err)
		}
		return persistedJournal{}, err
	}

	//nolint:gosec,nolintlint // G703: path is normalized at construction and its owner-only parent is verified; owner=security expiry=2027-07-13.
	fileInfo, err := os.Lstat(j.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedJournal{}, journalport.NewError(journalport.ErrorNotFound, "load", err)
		}
		return persistedJournal{}, journalport.NewError(journalport.ErrorIO, "inspect", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
		return persistedJournal{}, journalport.NewError(
			journalport.ErrorUnsafePermission,
			"inspect",
			errors.New("journal must be a regular file and not a symbolic link"),
		)
	}
	if err := verifyCurrentOwner(fileInfo, "inspect"); err != nil {
		return persistedJournal{}, err
	}
	if platformUnsafePermissions(fileInfo) {
		return persistedJournal{}, journalport.NewError(
			journalport.ErrorUnsafePermission,
			"inspect",
			fmt.Errorf("journal mode %04o grants group or other access", fileInfo.Mode().Perm()),
		)
	}
	if fileInfo.Size() > maximumJournalBytes {
		return persistedJournal{}, journalport.NewError(
			journalport.ErrorCorrupt,
			"read",
			fmt.Errorf("journal exceeds %d bytes", maximumJournalBytes),
		)
	}

	file, err := openVerifiedProtectedObject(ctx, j.path, fileInfo, "open")
	if err != nil {
		return persistedJournal{}, err
	}

	contents, err := io.ReadAll(io.LimitReader(file, maximumJournalBytes+1))
	if err != nil {
		_ = file.Close()
		return persistedJournal{}, journalport.NewError(journalport.ErrorIO, "read", err)
	}
	if err := file.Close(); err != nil {
		return persistedJournal{}, journalport.NewError(journalport.ErrorIO, "close", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document persistedJournal
	if err := decoder.Decode(&document); err != nil {
		return persistedJournal{}, journalport.NewError(journalport.ErrorCorrupt, "decode", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("journal contains trailing JSON")
		}
		return persistedJournal{}, journalport.NewError(journalport.ErrorCorrupt, "decode", err)
	}
	if err := j.verifyDocument(document); err != nil {
		return persistedJournal{}, err
	}
	return document, nil
}

func (j *InstallJournal) verifyDocument(document persistedJournal) error {
	if document.FormatVersion != journalFormatVersion {
		return corruptf("unsupported format version %d", document.FormatVersion)
	}
	if !validOperationID(document.OperationID) {
		return corruptf("invalid operation ID")
	}
	if len(document.Entries) == 0 || len(document.Entries) > maximumEntries {
		return corruptf("entry count %d is outside the supported range", len(document.Entries))
	}

	previousHash := zeroHash
	expectedRevision := uint64(1)
	for index, entry := range document.Entries {
		if entry.Revision != expectedRevision {
			return corruptf("entry %d has non-sequential revision %d", index, entry.Revision)
		}
		if entry.PreviousHash != previousHash {
			return corruptf("entry %d has an invalid previous hash", index)
		}
		capturedAt, err := time.Parse(time.RFC3339Nano, entry.CapturedAt)
		if err != nil || capturedAt.IsZero() {
			return corruptf("entry %d has an invalid capture time", index)
		}
		if len(entry.Payload) == 0 || len(entry.Payload) > maximumPayloadBytes || !json.Valid(entry.Payload) {
			return corruptf("entry %d has an invalid payload", index)
		}
		expectedHash := hashEntry(document.OperationID, entry)
		if !equalHexDigest(entry.Hash, expectedHash) {
			return corruptf("entry %d hash verification failed", index)
		}
		if !equalHexDigest(entry.MAC, j.entryMAC(entry.Hash)) {
			return corruptf("entry %d authentication failed", index)
		}
		previousHash = entry.Hash
		expectedRevision++
	}
	if !equalHexDigest(document.TerminalHash, previousHash) {
		return corruptf("terminal hash verification failed")
	}
	if !equalHexDigest(document.MAC, j.documentMAC(document)) {
		return corruptf("document authentication failed")
	}
	return nil
}

func hashEntry(operationID string, entry persistedEntry) string {
	hash := sha256.New()
	writeFramed(hash, []byte("agentmemory-install-journal-entry-v1"))
	writeFramed(hash, []byte(operationID))
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], entry.Revision)
	writeFramed(hash, revision[:])
	writeFramed(hash, []byte(entry.CapturedAt))
	writeFramed(hash, entry.Payload)
	writeFramed(hash, []byte(entry.PreviousHash))
	return hex.EncodeToString(hash.Sum(nil))
}

func writeFramed(writer io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func (j *InstallJournal) entryMAC(hashValue string) string {
	authenticator := hmac.New(sha256.New, j.key)
	writeFramed(authenticator, []byte("agentmemory-install-journal-entry-mac-v1"))
	writeFramed(authenticator, []byte(hashValue))
	return hex.EncodeToString(authenticator.Sum(nil))
}

func (j *InstallJournal) documentMAC(document persistedJournal) string {
	authenticator := hmac.New(sha256.New, j.key)
	writeFramed(authenticator, []byte("agentmemory-install-journal-document-mac-v1"))
	writeFramed(authenticator, []byte(document.OperationID))
	var entryCount [8]byte
	binary.BigEndian.PutUint64(entryCount[:], uint64(len(document.Entries)))
	writeFramed(authenticator, entryCount[:])
	writeFramed(authenticator, []byte(document.TerminalHash))
	return hex.EncodeToString(authenticator.Sum(nil))
}

func equalHexDigest(actual string, expected string) bool {
	actualBytes, err := hex.DecodeString(actual)
	if err != nil || len(actualBytes) != sha256.Size {
		return false
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil || len(expectedBytes) != sha256.Size {
		return false
	}
	return hmac.Equal(actualBytes, expectedBytes)
}

func corruptf(format string, values ...any) error {
	return journalport.NewError(
		journalport.ErrorCorrupt,
		"verify",
		fmt.Errorf(format, values...),
	)
}

func (j *InstallJournal) ensurePrivateParent(ctx context.Context) error {
	directory := filepath.Dir(j.path)
	if err := platformEnsurePrivateDirectory(ctx, directory); err != nil {
		return journalport.NewError(journalport.ErrorIO, "create_directory", err)
	}
	return verifyPrivateDirectory(ctx, directory)
}

func (j *InstallJournal) removeAbandonedTemporaryFiles(ctx context.Context) error {
	directory := filepath.Dir(j.path)
	prefix := "." + filepath.Base(j.path) + "."
	entries, err := os.ReadDir(directory)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "list_temporary", err)
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return journalport.NewError(journalport.ErrorIO, "inspect_temporary", err)
		}
		if !info.Mode().IsRegular() || platformUnsafePermissions(info) {
			return journalport.NewError(
				journalport.ErrorUnsafePermission,
				"inspect_temporary",
				errors.New("abandoned journal temporary file is not owner-only and regular"),
			)
		}
		if err := verifyCurrentOwner(info, "inspect_temporary"); err != nil {
			return err
		}
		path := filepath.Join(directory, entry.Name())
		opened, err := openVerifiedProtectedObject(ctx, path, info, "inspect_temporary")
		if err != nil {
			return err
		}
		if err := opened.Close(); err != nil {
			return journalport.NewError(journalport.ErrorIO, "close_temporary", err)
		}
		//nolint:gosec,nolintlint // G703: name comes from ReadDir and is restricted to the journal temp prefix in the verified parent; owner=security expiry=2027-07-13.
		if err := os.Remove(path); err != nil {
			return journalport.NewError(journalport.ErrorIO, "remove_temporary", err)
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDirectory(ctx, directory)
}

func verifyPrivateDirectory(ctx context.Context, directory string) error {
	//nolint:gosec,nolintlint // G703: this inspects only the normalized configured journal parent before any journal access; owner=security expiry=2027-07-13.
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"inspect_directory",
			errors.New("journal parent must be a directory and not a symbolic link"),
		)
	}
	if err := verifyCurrentOwner(info, "inspect_directory"); err != nil {
		return err
	}
	if platformUnsafePermissions(info) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"inspect_directory",
			fmt.Errorf("journal parent mode %04o grants group or other access", info.Mode().Perm()),
		)
	}
	opened, err := openVerifiedProtectedObject(ctx, directory, info, "inspect_directory")
	if err != nil {
		return err
	}
	if err := opened.Close(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "close_directory", err)
	}
	return nil
}

func openVerifiedProtectedObject(
	ctx context.Context,
	path string,
	expected os.FileInfo,
	operation string,
) (*os.File, error) {
	file, err := platformOpenProtectedObject(ctx, path, expected)
	if err != nil {
		return nil, journalport.NewError(
			journalport.ErrorUnsafePermission,
			operation,
			errors.New("protected filesystem object cannot be opened without following links"),
		)
	}
	if err := verifyOpenedProtectedObject(ctx, file, expected, operation); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func verifyOpenedProtectedObject(
	ctx context.Context,
	file *os.File,
	expected os.FileInfo,
	operation string,
) error {
	openedInfo, err := file.Stat()
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, operation, err)
	}
	if expected != nil && !os.SameFile(expected, openedInfo) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			operation,
			errors.New("protected filesystem object changed while it was opened"),
		)
	}
	if (!openedInfo.Mode().IsRegular() && !openedInfo.IsDir()) || platformUnsafePermissions(openedInfo) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			operation,
			errors.New("protected filesystem object is not owner-only and regular or directory"),
		)
	}
	if err := verifyCurrentOwner(openedInfo, operation); err != nil {
		return err
	}
	if err := verifyPlatformDescriptor(ctx, file); err != nil {
		return journalport.NewError(journalport.ErrorUnsafePermission, operation, err)
	}
	return nil
}

func verifyCurrentOwner(info os.FileInfo, operation string) error {
	if err := platformVerifyCurrentOwner(info); err != nil {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			operation,
			err,
		)
	}
	return nil
}

func (j *InstallJournal) writeAtomically(ctx context.Context, contents []byte) error {
	directory := filepath.Dir(j.path)
	//nolint:gosec,nolintlint // G703: normalized journal parent is descriptor-anchored and owner/ACL verified before replacement; owner=security expiry=2027-07-14.
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "inspect_directory", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "open_directory_root", err)
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(directoryInfo, rootInfo) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"open_directory_root",
			errors.New("journal directory changed while its anchored root was opened"),
		)
	}
	rootDescriptor, err := root.Open(".")
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "open_directory_descriptor", err)
	}
	defer func() { _ = rootDescriptor.Close() }()
	if err := verifyOpenedProtectedObject(ctx, rootDescriptor, directoryInfo, "open_directory_descriptor"); err != nil {
		return err
	}
	temporary, temporaryName, err := createProtectedRootTemporary(ctx, root, "."+filepath.Base(j.path)+".")
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "create_temporary", err)
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return journalport.NewError(journalport.ErrorIO, "protect_temporary", err)
	}
	if err := verifyOpenedProtectedObject(ctx, temporary, nil, "protect_temporary"); err != nil {
		return err
	}
	if err := j.runCheckpoint(checkpointTempCreated); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "write", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return journalport.NewError(journalport.ErrorIO, "write", err)
	}
	if err := j.runCheckpoint(checkpointTempWritten); err != nil {
		return err
	}
	if err := platformDurableSync(temporary); err != nil {
		return journalport.NewError(journalport.ErrorIO, "sync_temporary", err)
	}
	if err := j.runCheckpoint(checkpointTempSynced); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "close_temporary", err)
	}
	temporaryOpen = false
	if err := j.runCheckpoint(checkpointTempClosed); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "commit", err)
	}
	if err := platformAtomicRename(ctx, root, temporaryName, filepath.Base(j.path)); err != nil {
		return journalport.NewError(journalport.ErrorIO, "rename", err)
	}
	if err := j.runCheckpoint(checkpointRenamed); err != nil {
		return err
	}

	if err := platformDurableSync(rootDescriptor); err != nil {
		return journalport.NewError(journalport.ErrorIO, "sync_parent", err)
	}
	//nolint:gosec,nolintlint // G703: re-reading the normalized path proves it still names the descriptor-anchored directory; owner=security expiry=2027-07-14.
	currentDirectoryInfo, err := os.Lstat(directory)
	if err != nil || !os.SameFile(directoryInfo, currentDirectoryInfo) {
		return journalport.NewError(
			journalport.ErrorUnsafePermission,
			"verify_directory_path",
			errors.New("journal directory path was substituted during atomic replacement"),
		)
	}
	if err := j.runCheckpoint(checkpointDirectorySynced); err != nil {
		return err
	}
	return nil
}

func syncDirectory(ctx context.Context, directory string) error {
	//nolint:gosec,nolintlint // G703: caller supplies a normalized protected parent which is no-follow opened and owner/ACL verified below; owner=security expiry=2027-07-14.
	info, err := os.Lstat(directory)
	if err != nil {
		return journalport.NewError(journalport.ErrorIO, "inspect_parent", err)
	}
	parent, err := openVerifiedProtectedObject(ctx, directory, info, "open_parent")
	if err != nil {
		return err
	}
	if err := platformDurableSync(parent); err != nil {
		_ = parent.Close()
		return journalport.NewError(journalport.ErrorIO, "sync_parent", err)
	}
	if err := parent.Close(); err != nil {
		return journalport.NewError(journalport.ErrorIO, "close_parent", err)
	}
	return nil
}

func (j *InstallJournal) runCheckpoint(checkpoint writeCheckpoint) error {
	if j.hook == nil {
		return nil
	}
	if err := j.hook(checkpoint); err != nil {
		return journalport.NewError(journalport.ErrorIO, "atomic_write", err)
	}
	return nil
}
