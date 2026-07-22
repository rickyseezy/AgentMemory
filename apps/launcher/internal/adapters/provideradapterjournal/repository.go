// Package provideradapterjournal persists PRO-002 receipts in the existing
// HMAC-authenticated, owner-protected, rollback-anchored host journal.
package provideradapterjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

const journalSchemaVersion = 1

// JournalProvider resolves a platform-secured authenticated journal.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// Clock supplies canonical durable capture time.
type Clock interface{ Now() time.Time }

// Repository implements idempotent host install-receipt persistence.
type Repository struct {
	provider JournalProvider
	clock    Clock
}

// New validates the rollback-anchored persistence dependencies.
func New(provider JournalProvider, clock Clock) (*Repository, error) {
	if nilInterface(provider) || nilInterface(clock) {
		return nil, provideradapterapp.ErrStorage
	}
	return &Repository{provider: provider, clock: clock}, nil
}

// Find loads, authenticates, and durability-confirms an exact operation receipt.
func (r *Repository) Find(ctx context.Context, operationID string) (provideradapterapp.InstallResult, bool, error) {
	journal, journalID, err := r.journal(ctx, operationID)
	if err != nil {
		return provideradapterapp.InstallResult{}, false, err
	}
	snapshot, err := journal.LoadLatest(ctx)
	if errors.Is(err, installjournal.ErrNotFound) {
		return provideradapterapp.InstallResult{}, false, nil
	}
	if err != nil || snapshot.OperationID != journalID.String() || snapshot.Revision != 1 {
		return provideradapterapp.InstallResult{}, false, provideradapterapp.ErrStorage
	}
	result, err := decodeResult(snapshot.Payload)
	if err != nil || result.OperationID() != operationID || journal.ConfirmDurable(ctx, snapshot.OperationID, snapshot.Revision) != nil {
		return provideradapterapp.InstallResult{}, false, provideradapterapp.ErrStorage
	}
	return result, true, nil
}

// Commit appends the first receipt or durability-confirms a byte-identical replay.
func (r *Repository) Commit(ctx context.Context, result provideradapterapp.InstallResult) error {
	payload, err := encodeResult(result)
	if err != nil {
		return err
	}
	journal, journalID, err := r.journal(ctx, result.OperationID())
	if err != nil {
		return err
	}
	existing, loadErr := journal.LoadLatest(ctx)
	if loadErr == nil {
		if existing.OperationID != journalID.String() || existing.Revision != 1 || !bytes.Equal(existing.Payload, payload) {
			return provideradapterapp.ErrConflict
		}
		if journal.ConfirmDurable(ctx, existing.OperationID, existing.Revision) != nil {
			return provideradapterapp.ErrStorage
		}
		return nil
	}
	if !errors.Is(loadErr, installjournal.ErrNotFound) {
		return provideradapterapp.ErrStorage
	}
	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return provideradapterapp.ErrStorage
	}
	if err := journal.Append(ctx, 0, installjournal.Snapshot{OperationID: journalID.String(), Revision: 1, CapturedAt: capturedAt, Payload: payload}); err != nil {
		if errors.Is(err, installjournal.ErrConflict) {
			return provideradapterapp.ErrConflict
		}
		return provideradapterapp.ErrStorage
	}
	return nil
}

func (r *Repository) journal(ctx context.Context, operationID string) (installjournal.Journal, install.OperationID, error) {
	if r == nil || ctx == nil {
		return nil, install.OperationID{}, provideradapterapp.ErrStorage
	}
	if _, err := install.NewOperationID(operationID); err != nil {
		return nil, install.OperationID{}, provideradapterapp.ErrStorage
	}
	digest := sha256.Sum256([]byte("provider-adapter-journal\x00" + operationID))
	journalID, err := install.NewOperationID("provider-adapter-" + provideradapter.Digest(digest).Hex())
	if err != nil {
		return nil, install.OperationID{}, provideradapterapp.ErrStorage
	}
	journal, err := r.provider.JournalFor(ctx, journalID)
	if err != nil || nilInterface(journal) {
		return nil, install.OperationID{}, provideradapterapp.ErrStorage
	}
	return journal, journalID, nil
}

type resultDocument struct {
	SchemaVersion     uint16 `json:"schema_version"`
	OperationID       string `json:"operation_id"`
	AdapterID         string `json:"adapter_id"`
	RuntimeID         string `json:"runtime_id"`
	RequestDigest     string `json:"request_digest"`
	ManifestDigest    string `json:"manifest_digest"`
	PlanDigest        string `json:"plan_digest"`
	AttestationDigest string `json:"attestation_digest"`
	Status            string `json:"status"`
}

func encodeResult(result provideradapterapp.InstallResult) ([]byte, error) {
	if result.Status() != provideradapterapp.StatusActive {
		return nil, provideradapterapp.ErrStorage
	}
	payload, err := json.Marshal(resultDocument{journalSchemaVersion, result.OperationID(), result.AdapterID(), result.RuntimeID(),
		result.RequestDigest().Hex(), result.ManifestDigest().Hex(), result.PlanDigest().Hex(), result.AttestationDigest().Hex(), string(result.Status())})
	if err != nil {
		return nil, provideradapterapp.ErrStorage
	}
	return payload, nil
}

func decodeResult(payload []byte) (provideradapterapp.InstallResult, error) {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return provideradapterapp.InstallResult{}, provideradapterapp.ErrStorage
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document resultDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != journalSchemaVersion {
		return provideradapterapp.InstallResult{}, provideradapterapp.ErrStorage
	}
	values := []string{document.RequestDigest, document.ManifestDigest, document.PlanDigest, document.AttestationDigest}
	digests := make([]provideradapter.Digest, 4)
	for index, value := range values {
		parsed, err := provideradapter.ParseDigest(value)
		if err != nil {
			return provideradapterapp.InstallResult{}, provideradapterapp.ErrStorage
		}
		digests[index] = parsed
	}
	return provideradapterapp.RestoreInstallResult(document.OperationID, document.AdapterID, document.RuntimeID,
		digests[0], digests[1], digests[2], digests[3], provideradapterapp.Status(document.Status))
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

var _ provideradapterapp.Repository = (*Repository)(nil)
