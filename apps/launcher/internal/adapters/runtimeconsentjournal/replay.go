package runtimeconsentjournal

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
	replaySchemaVersion = uint16(1)
	replayDomainLinux   = "linux_privilege"
	replayDomainDesktop = "desktop_mutation"
	maximumReplayBytes  = 4 * 1024 * 1024
	maximumReplayItems  = 16 * 1024
	maximumReplayCAS    = 8
)

// ReplayLedger atomically consumes PF-006 receipt challenges in a dedicated,
// rollback-anchored operation journal. Consent, progress, and replay state
// never share a journal namespace.
type ReplayLedger struct {
	provider  JournalProvider
	clock     Clock
	operation install.OperationID
}

// NewReplayLedger binds one ledger to the parent installation operation.
func NewReplayLedger(provider JournalProvider, clock Clock, operationID string) (*ReplayLedger, error) {
	operation, err := install.NewOperationID(operationID)
	if err != nil || nilPort(provider) || nilPort(clock) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return &ReplayLedger{provider: provider, clock: clock, operation: operation}, nil
}

// ConsumePrivilegeReceipt rejects any prior use of the Linux helper nonce.
func (l *ReplayLedger) ConsumePrivilegeReceipt(
	ctx context.Context,
	nonce runtimeport.Nonce,
	receipt runtimeinstall.Hash,
) error {
	return l.consume(ctx, replayDomainLinux, nonce, receipt, runtimeport.ErrPrivilegeIntegrity)
}

// ConsumeDesktopMutation rejects any prior use of the desktop helper nonce.
func (l *ReplayLedger) ConsumeDesktopMutation(
	ctx context.Context,
	nonce runtimeport.Nonce,
	receipt runtimeinstall.Hash,
) error {
	return l.consume(ctx, replayDomainDesktop, nonce, receipt, runtimeport.ErrDesktopMutationIntegrity)
}

type replayEntry struct {
	Domain        string `json:"domain"`
	Nonce         string `json:"nonce"`
	ReceiptDigest string `json:"receipt_digest"`
}

type replayDocument struct {
	SchemaVersion uint16        `json:"schema_version"`
	OperationID   string        `json:"operation_id"`
	Revision      uint64        `json:"revision"`
	Entries       []replayEntry `json:"entries"`
}

func (l *ReplayLedger) consume(
	ctx context.Context,
	domain string,
	nonce runtimeport.Nonce,
	receipt runtimeinstall.Hash,
	integrityError error,
) error {
	if l == nil || ctx == nil || nilPort(l.provider) || nilPort(l.clock) || l.operation.IsZero() ||
		!validReplayDomain(domain) || nonce.IsZero() || receipt.IsZero() {
		return integrityError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := l.provider.JournalFor(ctx, l.operation)
	journal, ok := resolved.(*bootstrapadapter.AnchoredJournal)
	if err != nil || !ok || journal == nil {
		return integrityError
	}
	key := hex.EncodeToString(nonce[:])
	entry := replayEntry{Domain: domain, Nonce: key, ReceiptDigest: receipt.String()}
	for range maximumReplayCAS {
		document, loadError := loadReplayDocument(ctx, journal, l.operation)
		if loadError != nil && !errors.Is(loadError, journalport.ErrNotFound) {
			return integrityError
		}
		if errors.Is(loadError, journalport.ErrNotFound) {
			document = replayDocument{SchemaVersion: replaySchemaVersion, OperationID: l.operation.String()}
		}
		if replayNoncePresent(document.Entries, key) || len(document.Entries) >= maximumReplayItems {
			return integrityError
		}
		previous := document.Revision
		document.Revision++
		document.Entries = append(document.Entries, entry)
		sort.Slice(document.Entries, func(left, right int) bool {
			if document.Entries[left].Domain == document.Entries[right].Domain {
				return document.Entries[left].Nonce < document.Entries[right].Nonce
			}
			return document.Entries[left].Domain < document.Entries[right].Domain
		})
		payload, encodeError := encodeReplayDocument(document)
		capturedAt := l.clock.Now().UTC().Truncate(time.Microsecond)
		if encodeError != nil || capturedAt.IsZero() {
			return integrityError
		}
		appendError := journal.Append(ctx, previous, journalport.Snapshot{
			OperationID: l.operation.String(), Revision: document.Revision,
			CapturedAt: capturedAt, Payload: payload,
		})
		if errors.Is(appendError, journalport.ErrConflict) {
			continue
		}
		if appendError != nil || journal.ConfirmDurable(ctx, l.operation.String(), document.Revision) != nil {
			return integrityError
		}
		return nil
	}
	return integrityError
}

func loadReplayDocument(
	ctx context.Context,
	journal *bootstrapadapter.AnchoredJournal,
	operation install.OperationID,
) (replayDocument, error) {
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return replayDocument{}, err
	}
	if snapshot.OperationID != operation.String() || snapshot.Revision == 0 ||
		journal.ConfirmDurable(ctx, operation.String(), snapshot.Revision) != nil {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	document, err := decodeReplayDocument(snapshot.Payload)
	if err != nil || document.OperationID != operation.String() || document.Revision != snapshot.Revision {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return document, nil
}

func encodeReplayDocument(document replayDocument) ([]byte, error) {
	if !validReplayDocument(document) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	payload, err := json.Marshal(document)
	if err != nil || len(payload) == 0 || len(payload) > maximumReplayBytes {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return payload, nil
}

func decodeReplayDocument(payload []byte) (replayDocument, error) {
	if len(payload) == 0 || len(payload) > maximumReplayBytes {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document replayDocument
	if err := decoder.Decode(&document); err != nil {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validReplayDocument(document) {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(payload, canonical) {
		return replayDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return document, nil
}

func validReplayDocument(document replayDocument) bool {
	if document.SchemaVersion != replaySchemaVersion || document.OperationID == "" || document.Revision == 0 ||
		len(document.Entries) == 0 || len(document.Entries) > maximumReplayItems ||
		uint64(len(document.Entries)) != document.Revision {
		return false
	}
	if _, err := install.NewOperationID(document.OperationID); err != nil {
		return false
	}
	previousDomain, previousNonce := "", ""
	for _, entry := range document.Entries {
		decoded, nonceError := hex.DecodeString(entry.Nonce)
		_, digestError := runtimeinstall.ParseHash(entry.ReceiptDigest)
		if !validReplayDomain(entry.Domain) || nonceError != nil || len(decoded) != len(runtimeport.Nonce{}) ||
			digestError != nil || previousDomain > entry.Domain ||
			previousDomain == entry.Domain && previousNonce >= entry.Nonce {
			return false
		}
		previousDomain, previousNonce = entry.Domain, entry.Nonce
	}
	return true
}

func validReplayDomain(domain string) bool {
	return domain == replayDomainLinux || domain == replayDomainDesktop
}

func replayNoncePresent(entries []replayEntry, nonce string) bool {
	for _, entry := range entries {
		if entry.Nonce == nonce {
			return true
		}
	}
	return false
}

var (
	_ runtimeport.ReplayLedger                = (*ReplayLedger)(nil)
	_ runtimeport.DesktopMutationReplayLedger = (*ReplayLedger)(nil)
)
