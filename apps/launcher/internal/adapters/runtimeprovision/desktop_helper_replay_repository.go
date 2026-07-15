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
	desktopMutationHelperReplaySchemaVersion = uint16(1)
	desktopMutationHelperReplayPending       = "pending"
	desktopMutationHelperReplayComplete      = "complete"
	maximumDesktopMutationReplayBytes        = 8 * 1024 * 1024
	maximumDesktopMutationReplayItems        = 16 * 1024
)

// DesktopMutationHelperReplayJournalProvider resolves one protected,
// operation-scoped journal. Production also holds a machine-global helper
// execution lock from Begin through Complete.
type DesktopMutationHelperReplayJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (journalport.Journal, error)
}

// AnchoredDesktopMutationHelperReplayRepository records mutation intent
// before privileged file preparation and publishes the exact signed receipt
// afterward. Pending operations may be retried because executors must probe
// and converge idempotently.
type AnchoredDesktopMutationHelperReplayRepository struct {
	provider DesktopMutationHelperReplayJournalProvider
	clock    DesktopMutationHelperClock
}

// NewAnchoredDesktopMutationHelperReplayRepository requires authenticated,
// rollback-anchored storage and a trusted UTC clock.
func NewAnchoredDesktopMutationHelperReplayRepository(
	provider DesktopMutationHelperReplayJournalProvider,
	clock DesktopMutationHelperClock,
) (*AnchoredDesktopMutationHelperReplayRepository, error) {
	if nilArtifactDependency(provider) || nilArtifactDependency(clock) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return &AnchoredDesktopMutationHelperReplayRepository{provider: provider, clock: clock}, nil
}

// BeginDesktopMutationRequest reserves the request/nonce binding and returns
// a cached receipt only for an exact completed replay.
func (r *AnchoredDesktopMutationHelperReplayRepository) BeginDesktopMutationRequest(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
) (runtimeport.DesktopMutationReceipt, bool, error) {
	journal, operation, err := r.resolve(ctx, request)
	if err != nil {
		return runtimeport.DesktopMutationReceipt{}, false, err
	}
	document, err := loadDesktopMutationHelperReplay(ctx, journal, operation)
	if err != nil && !errors.Is(err, journalport.ErrNotFound) {
		return runtimeport.DesktopMutationReceipt{}, false, runtimeport.ErrDesktopMutationIntegrity
	}
	if errors.Is(err, journalport.ErrNotFound) {
		document = desktopMutationHelperReplayDocument{
			SchemaVersion: desktopMutationHelperReplaySchemaVersion,
			OperationID:   operation.String(),
		}
	}
	nonce := desktopMutationHelperReplayNonce(request.Nonce())
	for _, entry := range document.Entries {
		if entry.Nonce != nonce {
			continue
		}
		if !entry.matchesRequest(request) {
			return runtimeport.DesktopMutationReceipt{}, false, runtimeport.ErrDesktopMutationIntegrity
		}
		if entry.Status == desktopMutationHelperReplayPending {
			return runtimeport.DesktopMutationReceipt{}, false, nil
		}
		receipt, decodeError := runtimeport.DecodeDesktopMutationReceiptV1(entry.Receipt)
		now := r.clock.Now()
		if decodeError != nil || now.IsZero() || now.Location() != time.UTC || !receipt.Matches(request, now) {
			return runtimeport.DesktopMutationReceipt{}, false, runtimeport.ErrDesktopMutationIntegrity
		}
		return receipt, true, nil
	}
	if len(document.Entries) >= maximumDesktopMutationReplayItems {
		return runtimeport.DesktopMutationReceipt{}, false, runtimeport.ErrDesktopMutationIntegrity
	}
	document.Revision++
	document.Entries = append(document.Entries, newDesktopMutationHelperReplayEntry(request))
	sort.Slice(document.Entries, func(left, right int) bool {
		return document.Entries[left].Nonce < document.Entries[right].Nonce
	})
	if err := appendDesktopMutationHelperReplay(ctx, journal, document, r.clock); err != nil {
		return runtimeport.DesktopMutationReceipt{}, false, err
	}
	return runtimeport.DesktopMutationReceipt{}, false, nil
}

// CompleteDesktopMutationRequest replaces only the exact pending entry with
// the exact canonical signed receipt. Exact completion replay is idempotent.
func (r *AnchoredDesktopMutationHelperReplayRepository) CompleteDesktopMutationRequest(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	receipt runtimeport.DesktopMutationReceipt,
) error {
	journal, operation, err := r.resolve(ctx, request)
	if err != nil {
		return err
	}
	now := r.clock.Now()
	encoded := receipt.CanonicalBytes()
	if len(encoded) == 0 || now.IsZero() || now.Location() != time.UTC || !receipt.Matches(request, now) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	document, err := loadDesktopMutationHelperReplay(ctx, journal, operation)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	nonce := desktopMutationHelperReplayNonce(request.Nonce())
	for index := range document.Entries {
		entry := &document.Entries[index]
		if entry.Nonce != nonce {
			continue
		}
		if !entry.matchesRequest(request) {
			return runtimeport.ErrDesktopMutationIntegrity
		}
		if entry.Status == desktopMutationHelperReplayComplete {
			if !bytes.Equal(entry.Receipt, encoded) {
				return runtimeport.ErrDesktopMutationIntegrity
			}
			return nil
		}
		entry.Status = desktopMutationHelperReplayComplete
		entry.Receipt = append(json.RawMessage(nil), encoded...)
		document.Revision++
		return appendDesktopMutationHelperReplay(ctx, journal, document, r.clock)
	}
	return runtimeport.ErrDesktopMutationIntegrity
}

func (r *AnchoredDesktopMutationHelperReplayRepository) resolve(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
) (*bootstrapadapter.AnchoredJournal, install.OperationID, error) {
	if r == nil || ctx == nil || nilArtifactDependency(r.provider) || nilArtifactDependency(r.clock) ||
		request.Digest().IsZero() || request.Nonce().IsZero() {
		return nil, install.OperationID{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, install.OperationID{}, err
	}
	operation, err := install.NewOperationID(request.OperationID())
	if err != nil {
		return nil, install.OperationID{}, runtimeport.ErrDesktopMutationIntegrity
	}
	resolved, err := r.provider.JournalFor(ctx, operation)
	journal, ok := resolved.(*bootstrapadapter.AnchoredJournal)
	if err != nil || !ok || journal == nil {
		return nil, install.OperationID{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return journal, operation, nil
}

type desktopMutationHelperReplayEntry struct {
	AuthorityDigest    string          `json:"authority_digest"`
	ExpiresAtUnixMicro int64           `json:"expires_at_unix_micro"`
	Nonce              string          `json:"nonce"`
	Receipt            json.RawMessage `json:"receipt,omitempty"`
	RequestDigest      string          `json:"request_digest"`
	Status             string          `json:"status"`
}

type desktopMutationHelperReplayDocument struct {
	Entries       []desktopMutationHelperReplayEntry `json:"entries"`
	OperationID   string                             `json:"operation_id"`
	Revision      uint64                             `json:"revision"`
	SchemaVersion uint16                             `json:"schema_version"`
}

func newDesktopMutationHelperReplayEntry(
	request runtimeport.DesktopMutationRequest,
) desktopMutationHelperReplayEntry {
	return desktopMutationHelperReplayEntry{
		AuthorityDigest:    request.Authority().Digest().String(),
		ExpiresAtUnixMicro: request.ExpiresAt().UnixMicro(),
		Nonce:              desktopMutationHelperReplayNonce(request.Nonce()),
		RequestDigest:      request.Digest().String(),
		Status:             desktopMutationHelperReplayPending,
	}
}

func (e desktopMutationHelperReplayEntry) matchesRequest(request runtimeport.DesktopMutationRequest) bool {
	return e.Nonce == desktopMutationHelperReplayNonce(request.Nonce()) &&
		e.RequestDigest == request.Digest().String() &&
		e.AuthorityDigest == request.Authority().Digest().String() &&
		e.ExpiresAtUnixMicro == request.ExpiresAt().UnixMicro()
}

func desktopMutationHelperReplayNonce(nonce runtimeport.Nonce) string {
	return hex.EncodeToString(nonce[:])
}

func appendDesktopMutationHelperReplay(
	ctx context.Context,
	journal *bootstrapadapter.AnchoredJournal,
	document desktopMutationHelperReplayDocument,
	clock DesktopMutationHelperClock,
) error {
	payload, err := encodeDesktopMutationHelperReplay(document)
	capturedAt := clock.Now()
	if err != nil || capturedAt.IsZero() || capturedAt.Location() != time.UTC {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	previous := document.Revision - 1
	err = journal.Append(ctx, previous, journalport.Snapshot{
		OperationID: document.OperationID, Revision: document.Revision,
		CapturedAt: capturedAt.Truncate(time.Microsecond), Payload: payload,
	})
	if err != nil || journal.ConfirmDurable(ctx, document.OperationID, document.Revision) != nil {
		return desktopMutationHelperContextOrIntegrity(ctx)
	}
	return nil
}

func loadDesktopMutationHelperReplay(
	ctx context.Context,
	journal *bootstrapadapter.AnchoredJournal,
	operation install.OperationID,
) (desktopMutationHelperReplayDocument, error) {
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return desktopMutationHelperReplayDocument{}, err
	}
	if snapshot.OperationID != operation.String() || snapshot.Revision == 0 ||
		journal.ConfirmDurable(ctx, operation.String(), snapshot.Revision) != nil {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	document, err := decodeDesktopMutationHelperReplay(snapshot.Payload)
	if err != nil || document.OperationID != operation.String() || document.Revision != snapshot.Revision {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return document, nil
}

func encodeDesktopMutationHelperReplay(document desktopMutationHelperReplayDocument) ([]byte, error) {
	if !validDesktopMutationHelperReplay(document) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	payload, err := json.Marshal(document)
	if err != nil || len(payload) == 0 || len(payload) > maximumDesktopMutationReplayBytes {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return payload, nil
}

func decodeDesktopMutationHelperReplay(payload []byte) (desktopMutationHelperReplayDocument, error) {
	if len(payload) == 0 || len(payload) > maximumDesktopMutationReplayBytes {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document desktopMutationHelperReplayDocument
	if err := decoder.Decode(&document); err != nil {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validDesktopMutationHelperReplay(document) {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(payload, canonical) {
		return desktopMutationHelperReplayDocument{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return document, nil
}

func validDesktopMutationHelperReplay(document desktopMutationHelperReplayDocument) bool {
	if document.SchemaVersion != desktopMutationHelperReplaySchemaVersion || document.Revision == 0 ||
		len(document.Entries) == 0 || len(document.Entries) > maximumDesktopMutationReplayItems {
		return false
	}
	if _, err := install.NewOperationID(document.OperationID); err != nil {
		return false
	}
	previous := ""
	for index, entry := range document.Entries {
		nonce, nonceError := hex.DecodeString(entry.Nonce)
		request, requestError := runtimeinstall.ParseHash(entry.RequestDigest)
		authority, authorityError := runtimeinstall.ParseHash(entry.AuthorityDigest)
		if nonceError != nil || len(nonce) != len(runtimeport.Nonce{}) || requestError != nil || request.IsZero() ||
			authorityError != nil || authority.IsZero() || entry.ExpiresAtUnixMicro <= 0 ||
			index > 0 && previous >= entry.Nonce {
			return false
		}
		switch entry.Status {
		case desktopMutationHelperReplayPending:
			if len(entry.Receipt) != 0 {
				return false
			}
		case desktopMutationHelperReplayComplete:
			receipt, err := runtimeport.DecodeDesktopMutationReceiptV1(entry.Receipt)
			if err != nil || receipt.Digest().IsZero() {
				return false
			}
		default:
			return false
		}
		previous = entry.Nonce
	}
	return true
}

var _ DesktopMutationHelperReplayRepository = (*AnchoredDesktopMutationHelperReplayRepository)(nil)
