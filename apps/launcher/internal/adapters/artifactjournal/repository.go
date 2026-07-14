// Package artifactjournal persists artifact acquisition state in the existing
// HMAC-authenticated, rollback-anchored installation journal boundary.
package artifactjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	journalSchemaVersion = uint16(2)
	maximumJournalBytes  = 4 * 1024 * 1024
)

// JournalProvider resolves a secure rollback-anchored operation journal.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// Clock supplies deterministic journal capture time.
type Clock interface {
	Now() time.Time
}

// Repository implements strict authenticated aggregate CAS persistence.
type Repository struct {
	provider JournalProvider
	clock    Clock
}

// New constructs an artifact journal repository.
func New(provider JournalProvider, clock Clock) (*Repository, error) {
	if nilInterface(provider) || nilInterface(clock) {
		return nil, artifactapp.ErrAggregatePersistence
	}
	return &Repository{provider: provider, clock: clock}, nil
}

// Load authenticates, strictly decodes, and durability-confirms latest state.
func (r *Repository) Load(ctx context.Context, operationID string) (artifactacquisition.Snapshot, error) {
	journalID, err := artifactJournalID(operationID)
	if err != nil {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	journal, err := r.journal(ctx, journalID)
	if err != nil {
		return artifactacquisition.Snapshot{}, mapJournalError(err)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return artifactacquisition.Snapshot{}, mapJournalError(err)
	}
	if latest.OperationID != journalID.String() || latest.Revision == 0 {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	snapshot, err := decodeSnapshot(latest.Payload)
	if err != nil || snapshot.OperationID != operationID {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	if err := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); err != nil {
		return artifactacquisition.Snapshot{}, mapJournalError(err)
	}
	return snapshot, nil
}

// Save appends exactly the next aggregate version or durability-confirms an
// exact same-version replay.
func (r *Repository) Save(ctx context.Context, expectedVersion uint64, snapshot artifactacquisition.Snapshot) error {
	canonical, journalID, err := encodeSnapshot(snapshot)
	if err != nil {
		return artifactapp.ErrAggregateIntegrity
	}
	journal, err := r.journal(ctx, journalID)
	if err != nil {
		return mapJournalError(err)
	}
	previousRevision := uint64(0)
	latest, loadError := journal.LoadLatest(ctx)
	switch {
	case loadError == nil:
		if latest.OperationID != journalID.String() || latest.Revision == 0 {
			return artifactapp.ErrAggregateIntegrity
		}
		persisted, decodeError := decodeSnapshot(latest.Payload)
		if decodeError != nil || persisted.OperationID != snapshot.OperationID || persisted.PlanDigest != snapshot.PlanDigest {
			return artifactapp.ErrAggregateIntegrity
		}
		persistedCanonical, _, encodeError := encodeSnapshot(persisted)
		if encodeError != nil {
			return artifactapp.ErrAggregateIntegrity
		}
		if persisted.Version != expectedVersion {
			return artifactapp.ErrAggregateConflict
		}
		if snapshot.Version == expectedVersion && bytes.Equal(persistedCanonical, canonical) {
			return mapJournalError(journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision))
		}
		if expectedVersion == math.MaxUint64 || snapshot.Version != expectedVersion+1 || latest.Revision == math.MaxUint64 {
			return artifactapp.ErrAggregateConflict
		}
		previousRevision = latest.Revision
	case errors.Is(loadError, installjournal.ErrNotFound):
		if expectedVersion != 0 || snapshot.Version != 0 {
			return artifactapp.ErrAggregateConflict
		}
	default:
		return mapJournalError(loadError)
	}
	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return artifactapp.ErrAggregatePersistence
	}
	if err := journal.Append(ctx, previousRevision, installjournal.Snapshot{
		OperationID: journalID.String(), Revision: previousRevision + 1, CapturedAt: capturedAt, Payload: canonical,
	}); err != nil {
		return mapJournalError(err)
	}
	return nil
}

func (r *Repository) journal(ctx context.Context, journalID install.OperationID) (installjournal.Journal, error) {
	journal, err := r.provider.JournalFor(ctx, journalID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, artifactapp.ErrAggregateIntegrity
	}
	return journal, nil
}

type snapshotDocument struct {
	SchemaVersion uint16             `json:"schema_version"`
	OperationID   string             `json:"operation_id"`
	PlanDigest    string             `json:"plan_digest"`
	Version       uint64             `json:"version"`
	ReservationID string             `json:"reservation_id"`
	ReservedBytes uint64             `json:"reserved_bytes"`
	FilesystemID  string             `json:"filesystem_id"`
	ReleaseState  string             `json:"release_state"`
	ReleaseReason string             `json:"release_reason"`
	Progress      []progressDocument `json:"progress"`
}

type progressDocument struct {
	ArtifactID          string   `json:"artifact_id"`
	ArtifactDigest      string   `json:"artifact_digest"`
	PartialID           string   `json:"partial_id"`
	VerifiedChunks      []uint32 `json:"verified_chunks"`
	ReservationConsumed bool     `json:"reservation_consumed"`
	Completed           bool     `json:"completed"`
}

func encodeSnapshot(snapshot artifactacquisition.Snapshot) ([]byte, install.OperationID, error) {
	if !validSnapshot(snapshot) {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	journalID, err := artifactJournalID(snapshot.OperationID)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	progress := make([]progressDocument, 0, len(snapshot.Progress))
	for _, entry := range snapshot.Progress {
		progress = append(progress, progressDocument{
			ArtifactID: entry.ArtifactID, ArtifactDigest: entry.ArtifactDigest, PartialID: entry.PartialID,
			VerifiedChunks: append([]uint32(nil), entry.VerifiedChunks...), ReservationConsumed: entry.ReservationConsumed,
			Completed: entry.Completed,
		})
	}
	canonical, err := json.Marshal(snapshotDocument{
		SchemaVersion: journalSchemaVersion, OperationID: snapshot.OperationID, PlanDigest: snapshot.PlanDigest,
		Version: snapshot.Version, ReservationID: snapshot.ReservationID, ReservedBytes: snapshot.ReservedBytes,
		FilesystemID: snapshot.FilesystemID, ReleaseState: snapshot.ReleaseState, ReleaseReason: snapshot.ReleaseReason,
		Progress: progress,
	})
	if err != nil || len(canonical) == 0 || len(canonical) > maximumJournalBytes {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	return canonical, journalID, nil
}

func decodeSnapshot(payload []byte) (artifactacquisition.Snapshot, error) {
	if len(payload) == 0 || len(payload) > maximumJournalBytes || !json.Valid(payload) || duplicateKeys(payload) {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(payload, &raw) != nil || !exactFields(raw,
		"schema_version", "operation_id", "plan_digest", "version", "reservation_id", "reserved_bytes", "filesystem_id",
		"release_state", "release_reason", "progress",
	) {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	var rawProgress []json.RawMessage
	if json.Unmarshal(raw["progress"], &rawProgress) != nil || rawProgress == nil {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	for _, entry := range rawProgress {
		var fields map[string]json.RawMessage
		if json.Unmarshal(entry, &fields) != nil || !exactFields(fields,
			"artifact_id", "artifact_digest", "partial_id", "verified_chunks", "reservation_consumed", "completed",
		) {
			return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document snapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	progress := make([]artifactacquisition.ProgressSnapshot, 0, len(document.Progress))
	for _, entry := range document.Progress {
		progress = append(progress, artifactacquisition.ProgressSnapshot{
			ArtifactID: entry.ArtifactID, ArtifactDigest: entry.ArtifactDigest, PartialID: entry.PartialID,
			VerifiedChunks: append([]uint32(nil), entry.VerifiedChunks...), ReservationConsumed: entry.ReservationConsumed,
			Completed: entry.Completed,
		})
	}
	snapshot := artifactacquisition.Snapshot{
		SchemaVersion: document.SchemaVersion, OperationID: document.OperationID, PlanDigest: document.PlanDigest,
		Version: document.Version, ReservationID: document.ReservationID, ReservedBytes: document.ReservedBytes,
		FilesystemID: document.FilesystemID, ReleaseState: document.ReleaseState, ReleaseReason: document.ReleaseReason,
		Progress: progress,
	}
	if !validSnapshot(snapshot) {
		return artifactacquisition.Snapshot{}, artifactapp.ErrAggregateIntegrity
	}
	return snapshot, nil
}

func validSnapshot(snapshot artifactacquisition.Snapshot) bool {
	if snapshot.SchemaVersion != journalSchemaVersion || len(snapshot.Progress) > 4096 {
		return false
	}
	if _, err := install.NewOperationID(snapshot.OperationID); err != nil {
		return false
	}
	if _, err := releaseinventory.ParseDigest(snapshot.PlanDigest); err != nil {
		return false
	}
	reservationPresent := snapshot.ReservationID != "" || snapshot.ReservedBytes != 0 || snapshot.FilesystemID != "" ||
		snapshot.ReleaseState != "" || snapshot.ReleaseReason != ""
	if reservationPresent && (!token(snapshot.ReservationID, "r-") || snapshot.ReservedBytes == 0 ||
		snapshot.ReservedBytes > uint64(1<<53-1) || (snapshot.FilesystemID != "" && !safeIdentifier(snapshot.FilesystemID))) {
		return false
	}
	if !reservationPresent && (len(snapshot.Progress) != 0 || snapshot.ReleaseState != "" || snapshot.ReleaseReason != "") {
		return false
	}
	if reservationPresent {
		switch snapshot.ReleaseState {
		case "allocating":
			if snapshot.FilesystemID != "" || snapshot.ReleaseReason != "" {
				return false
			}
		case "active":
			if snapshot.FilesystemID == "" || snapshot.ReleaseReason != "" {
				return false
			}
		case "pending", "released":
			if snapshot.ReleaseReason != "completed" && snapshot.ReleaseReason != "cancelled" && snapshot.ReleaseReason != "rollback" {
				return false
			}
		default:
			return false
		}
	}
	if len(snapshot.Progress) != 0 && snapshot.FilesystemID == "" {
		return false
	}
	seen := make(map[string]struct{}, len(snapshot.Progress))
	for _, entry := range snapshot.Progress {
		if _, err := install.NewOperationID(entry.ArtifactID); err != nil || !token(entry.PartialID, "p-") {
			return false
		}
		if _, err := releaseinventory.ParseDigest(entry.ArtifactDigest); err != nil {
			return false
		}
		if _, duplicate := seen[entry.ArtifactID]; duplicate {
			return false
		}
		seen[entry.ArtifactID] = struct{}{}
		if entry.VerifiedChunks == nil || !sort.SliceIsSorted(entry.VerifiedChunks, func(i, j int) bool { return entry.VerifiedChunks[i] < entry.VerifiedChunks[j] }) {
			return false
		}
		for index, chunk := range entry.VerifiedChunks {
			if chunk != uint32(index) {
				return false
			}
		}
		if entry.Completed && !entry.ReservationConsumed {
			return false
		}
	}
	return true
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func artifactJournalID(operationID string) (install.OperationID, error) {
	if _, err := install.NewOperationID(operationID); err != nil {
		return install.OperationID{}, err
	}
	digest := sha256.Sum256([]byte("artifact-journal\x00" + operationID))
	return install.NewOperationID("artifact-" + releaseinventory.Digest(digest).Hex())
}

func token(value string, prefix string) bool {
	if len(value) != len(prefix)+64 || len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func exactFields(document map[string]json.RawMessage, fields ...string) bool {
	if len(document) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := document[field]; !exists {
			return false
		}
	}
	return true
}

func duplicateKeys(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if consumeUnique(decoder) != nil {
		return true
	}
	_, err := decoder.Token()
	return !errors.Is(err, io.EOF)
}

func consumeUnique(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return keyError
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return artifactapp.ErrAggregateIntegrity
			}
			if _, duplicate := seen[key]; duplicate {
				return artifactapp.ErrAggregateIntegrity
			}
			seen[key] = struct{}{}
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return artifactapp.ErrAggregateIntegrity
		}
	case '[':
		for decoder.More() {
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return artifactapp.ErrAggregateIntegrity
		}
	default:
		return artifactapp.ErrAggregateIntegrity
	}
	return nil
}

func mapJournalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, installjournal.ErrNotFound):
		return artifactapp.ErrAggregateNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return artifactapp.ErrAggregateConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return artifactapp.ErrAggregateIntegrity
	default:
		return artifactapp.ErrAggregatePersistence
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}

var _ artifactapp.Repository = (*Repository)(nil)
