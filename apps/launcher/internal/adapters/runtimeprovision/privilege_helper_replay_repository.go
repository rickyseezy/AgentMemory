package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	privilegeHelperReplaySchemaVersion = uint16(1)
	privilegeHelperReplayPending       = "pending"
	privilegeHelperReplayComplete      = "complete"
	maximumPrivilegeHelperReplayBytes  = 8 * 1024 * 1024
	maximumPrivilegeHelperReplayItems  = 16 * 1024
)

// PrivilegeHelperReplayJournalProvider resolves one operation-scoped,
// authenticated journal. Production callers must also hold the helper's
// machine-global execution lock while calling Begin through Complete.
type PrivilegeHelperReplayJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (journalport.Journal, error)
}

// AnchoredPrivilegeHelperReplayRepository records pending intent before root
// mutation and the exact canonical signed receipt after the mutation. A
// pending replay is deliberately executable again because every closed helper
// operation independently probes its post-state and is idempotent.
type AnchoredPrivilegeHelperReplayRepository struct {
	provider PrivilegeHelperReplayJournalProvider
	clock    PrivilegeHelperClock
}

// NewAnchoredPrivilegeHelperReplayRepository requires protected journal and
// trusted-time capabilities. It never falls back to an ordinary file.
func NewAnchoredPrivilegeHelperReplayRepository(
	provider PrivilegeHelperReplayJournalProvider,
	clock PrivilegeHelperClock,
) (*AnchoredPrivilegeHelperReplayRepository, error) {
	if nilArtifactDependency(provider) || nilArtifactDependency(clock) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return &AnchoredPrivilegeHelperReplayRepository{provider: provider, clock: clock}, nil
}

// BeginPrivilegeRequest durably reserves a nonce/request binding before any
// artifact copy or host mutation. A completed exact replay returns its cached
// signed receipt; nonce substitution fails closed.
func (r *AnchoredPrivilegeHelperReplayRepository) BeginPrivilegeRequest(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (runtimeport.PrivilegeReceipt, bool, error) {
	journal, operation, err := r.resolve(ctx, request)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, false, err
	}
	document, err := loadPrivilegeHelperReplay(ctx, journal, operation)
	if err != nil && !errors.Is(err, journalport.ErrNotFound) {
		return runtimeport.PrivilegeReceipt{}, false, runtimeport.ErrPrivilegeIntegrity
	}
	if errors.Is(err, journalport.ErrNotFound) {
		document = privilegeHelperReplayDocument{
			SchemaVersion: privilegeHelperReplaySchemaVersion,
			OperationID:   operation.String(),
		}
	}
	nonce := privilegeHelperReplayNonce(request.Nonce())
	for _, entry := range document.Entries {
		if entry.Nonce != nonce {
			continue
		}
		if !entry.matchesRequest(request) {
			return runtimeport.PrivilegeReceipt{}, false, runtimeport.ErrPrivilegeIntegrity
		}
		if entry.Status == privilegeHelperReplayPending {
			return runtimeport.PrivilegeReceipt{}, false, nil
		}
		receipt, decodeError := DecodeCanonicalPrivilegeReceipt(entry.Receipt)
		now := r.clock.Now()
		if decodeError != nil || now.IsZero() || now.Location() != time.UTC || !receipt.Matches(request, now) {
			return runtimeport.PrivilegeReceipt{}, false, runtimeport.ErrPrivilegeIntegrity
		}
		return receipt, true, nil
	}
	if len(document.Entries) >= maximumPrivilegeHelperReplayItems {
		return runtimeport.PrivilegeReceipt{}, false, runtimeport.ErrPrivilegeIntegrity
	}
	document.Revision++
	document.Entries = append(document.Entries, newPrivilegeHelperReplayEntry(request))
	sort.Slice(document.Entries, func(left, right int) bool {
		return document.Entries[left].Nonce < document.Entries[right].Nonce
	})
	if err := appendPrivilegeHelperReplay(ctx, journal, document, r.clock); err != nil {
		return runtimeport.PrivilegeReceipt{}, false, err
	}
	return runtimeport.PrivilegeReceipt{}, false, nil
}

// CompletePrivilegeRequest atomically replaces the exact pending entry with
// its canonical receipt. Exact completion replay is idempotent.
func (r *AnchoredPrivilegeHelperReplayRepository) CompletePrivilegeRequest(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	receipt runtimeport.PrivilegeReceipt,
) error {
	journal, operation, err := r.resolve(ctx, request)
	if err != nil {
		return err
	}
	now := r.clock.Now()
	encoded, err := EncodeCanonicalPrivilegeReceipt(receipt)
	if err != nil || now.IsZero() || now.Location() != time.UTC || !receipt.Matches(request, now) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	document, err := loadPrivilegeHelperReplay(ctx, journal, operation)
	if err != nil {
		return runtimeport.ErrPrivilegeIntegrity
	}
	nonce := privilegeHelperReplayNonce(request.Nonce())
	for index := range document.Entries {
		entry := &document.Entries[index]
		if entry.Nonce != nonce {
			continue
		}
		if !entry.matchesRequest(request) {
			return runtimeport.ErrPrivilegeIntegrity
		}
		if entry.Status == privilegeHelperReplayComplete {
			if !bytes.Equal(entry.Receipt, encoded) {
				return runtimeport.ErrPrivilegeIntegrity
			}
			return nil
		}
		entry.Status = privilegeHelperReplayComplete
		entry.Receipt = append(json.RawMessage(nil), encoded...)
		document.Revision++
		return appendPrivilegeHelperReplay(ctx, journal, document, r.clock)
	}
	return runtimeport.ErrPrivilegeIntegrity
}

func (r *AnchoredPrivilegeHelperReplayRepository) resolve(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (*bootstrapadapter.AnchoredJournal, install.OperationID, error) {
	if r == nil || ctx == nil || nilArtifactDependency(r.provider) || nilArtifactDependency(r.clock) ||
		request.Digest().IsZero() || request.OperationKey().IsZero() || request.Nonce().IsZero() {
		return nil, install.OperationID{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, install.OperationID{}, err
	}
	operation, err := install.NewOperationID(request.OperationID())
	if err != nil {
		return nil, install.OperationID{}, runtimeport.ErrPrivilegeIntegrity
	}
	resolved, err := r.provider.JournalFor(ctx, operation)
	journal, ok := resolved.(*bootstrapadapter.AnchoredJournal)
	if err != nil || !ok || journal == nil {
		return nil, install.OperationID{}, privilegeHelperContextOrIntegrity(ctx)
	}
	return journal, operation, nil
}

type privilegeHelperReplayEntry struct {
	ExpiresAtUnixMicro int64           `json:"expires_at_unix_micro"`
	Nonce              string          `json:"nonce"`
	OperationKey       string          `json:"operation_key"`
	Receipt            json.RawMessage `json:"receipt,omitempty"`
	RequestDigest      string          `json:"request_digest"`
	Status             string          `json:"status"`
}

type privilegeHelperReplayDocument struct {
	Entries       []privilegeHelperReplayEntry `json:"entries"`
	OperationID   string                       `json:"operation_id"`
	Revision      uint64                       `json:"revision"`
	SchemaVersion uint16                       `json:"schema_version"`
}

func newPrivilegeHelperReplayEntry(request runtimeport.PrivilegeRequest) privilegeHelperReplayEntry {
	return privilegeHelperReplayEntry{
		ExpiresAtUnixMicro: request.ExpiresAt().UnixMicro(),
		Nonce:              privilegeHelperReplayNonce(request.Nonce()),
		OperationKey:       request.OperationKey().String(),
		RequestDigest:      request.Digest().String(),
		Status:             privilegeHelperReplayPending,
	}
}

func (e privilegeHelperReplayEntry) matchesRequest(request runtimeport.PrivilegeRequest) bool {
	return e.Nonce == privilegeHelperReplayNonce(request.Nonce()) &&
		e.RequestDigest == request.Digest().String() && e.OperationKey == request.OperationKey().String() &&
		e.ExpiresAtUnixMicro == request.ExpiresAt().UnixMicro()
}

func privilegeHelperReplayNonce(nonce runtimeport.Nonce) string {
	return hex.EncodeToString(nonce[:])
}

func appendPrivilegeHelperReplay(
	ctx context.Context,
	journal *bootstrapadapter.AnchoredJournal,
	document privilegeHelperReplayDocument,
	clock PrivilegeHelperClock,
) error {
	payload, err := encodePrivilegeHelperReplay(document)
	capturedAt := clock.Now()
	if err != nil || capturedAt.IsZero() || capturedAt.Location() != time.UTC {
		return runtimeport.ErrPrivilegeIntegrity
	}
	previous := document.Revision - 1
	err = journal.Append(ctx, previous, journalport.Snapshot{
		OperationID: document.OperationID, Revision: document.Revision,
		CapturedAt: capturedAt.Truncate(time.Microsecond), Payload: payload,
	})
	if err != nil || journal.ConfirmDurable(ctx, document.OperationID, document.Revision) != nil {
		return privilegeHelperContextOrIntegrity(ctx)
	}
	return nil
}

func loadPrivilegeHelperReplay(
	ctx context.Context,
	journal *bootstrapadapter.AnchoredJournal,
	operation install.OperationID,
) (privilegeHelperReplayDocument, error) {
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return privilegeHelperReplayDocument{}, err
	}
	if snapshot.OperationID != operation.String() || snapshot.Revision == 0 ||
		journal.ConfirmDurable(ctx, operation.String(), snapshot.Revision) != nil {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	document, err := decodePrivilegeHelperReplay(snapshot.Payload)
	if err != nil || document.OperationID != operation.String() || document.Revision != snapshot.Revision {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return document, nil
}

func encodePrivilegeHelperReplay(document privilegeHelperReplayDocument) ([]byte, error) {
	if !validPrivilegeHelperReplay(document) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	payload, err := json.Marshal(document)
	if err != nil || len(payload) == 0 || len(payload) > maximumPrivilegeHelperReplayBytes {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return payload, nil
}

func decodePrivilegeHelperReplay(payload []byte) (privilegeHelperReplayDocument, error) {
	if len(payload) == 0 || len(payload) > maximumPrivilegeHelperReplayBytes {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document privilegeHelperReplayDocument
	if err := decoder.Decode(&document); err != nil {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validPrivilegeHelperReplay(document) {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(payload, canonical) {
		return privilegeHelperReplayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return document, nil
}

func validPrivilegeHelperReplay(document privilegeHelperReplayDocument) bool {
	if document.SchemaVersion != privilegeHelperReplaySchemaVersion || document.Revision == 0 ||
		len(document.Entries) == 0 || len(document.Entries) > maximumPrivilegeHelperReplayItems {
		return false
	}
	if _, err := install.NewOperationID(document.OperationID); err != nil {
		return false
	}
	previous := ""
	for index, entry := range document.Entries {
		nonce, nonceError := hex.DecodeString(entry.Nonce)
		request, requestError := runtimeinstall.ParseHash(entry.RequestDigest)
		operationKey, operationKeyError := runtimeinstall.ParseHash(entry.OperationKey)
		if nonceError != nil || len(nonce) != len(runtimeport.Nonce{}) || requestError != nil || request.IsZero() ||
			operationKeyError != nil || operationKey.IsZero() || entry.ExpiresAtUnixMicro <= 0 ||
			index > 0 && previous >= entry.Nonce {
			return false
		}
		switch entry.Status {
		case privilegeHelperReplayPending:
			if len(entry.Receipt) != 0 {
				return false
			}
		case privilegeHelperReplayComplete:
			receipt, err := DecodeCanonicalPrivilegeReceipt(entry.Receipt)
			input := receipt.TransportInput()
			if err != nil || receipt.Digest().IsZero() || input.RequestDigest != request ||
				input.OperationKey != operationKey || privilegeHelperReplayNonce(input.Nonce) != entry.Nonce ||
				input.ExpiresAt.UnixMicro() != entry.ExpiresAtUnixMicro {
				return false
			}
		default:
			return false
		}
		previous = entry.Nonce
	}
	return true
}

var _ PrivilegeHelperReplayRepository = (*AnchoredPrivilegeHelperReplayRepository)(nil)
