// Package runtimeconsentjournal persists platform consent receipts in an
// authenticated, rollback-protected operation journal.
package runtimeconsentjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	schemaVersion       = uint16(1)
	kindLinux           = "linux"
	kindDesktop         = "desktop"
	maximumSnapshotSize = 16 * 1024
)

// JournalProvider resolves an operation-scoped protected journal.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (journalport.Journal, error)
}

// Clock supplies the trusted snapshot capture time.
type Clock interface{ Now() time.Time }

// Repository stores at most one immutable platform consent receipt for an
// installation operation. A material change requires a new visible consent
// and therefore cannot overwrite an existing receipt in place.
type Repository struct {
	provider JournalProvider
	clock    Clock
}

// New accepts only complete persistence capabilities. Each resolved journal
// is additionally required to be the concrete rollback-protected decorator.
func New(provider JournalProvider, clock Clock) (*Repository, error) {
	if nilPort(provider) || nilPort(clock) {
		return nil, runtimeport.ErrLinuxConsentIntegrity
	}
	return &Repository{provider: provider, clock: clock}, nil
}

// StoreLinuxConsent durably publishes one exact signed Linux receipt.
func (r *Repository) StoreLinuxConsent(
	ctx context.Context,
	operationID string,
	receipt runtimeport.LinuxConsentReceipt,
) error {
	statement := receipt.Statement()
	payload, err := encodeLinux(statement, receipt.Signature(), receipt.Digest())
	if err != nil {
		return runtimeport.ErrLinuxConsentIntegrity
	}
	return r.store(ctx, operationID, statement.PlanDigest, kindLinux, receipt.Digest(), payload,
		runtimeport.ErrLinuxConsentIntegrity)
}

// LoadLinuxConsent authenticates, durability-confirms, and strictly restores
// the exact receipt selected by operation and signed plan digest.
func (r *Repository) LoadLinuxConsent(
	ctx context.Context,
	operationID string,
	planDigest runtimeinstall.Hash,
) (runtimeport.LinuxConsentReceipt, error) {
	payload, err := r.load(ctx, operationID, planDigest, kindLinux, runtimeport.ErrLinuxConsentIntegrity)
	if err != nil {
		return runtimeport.LinuxConsentReceipt{}, err
	}
	receipt, err := decodeLinux(payload)
	if err != nil || receipt.Statement().PlanDigest != planDigest {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	return receipt, nil
}

// StoreDesktopConsent durably publishes one exact signed Desktop receipt.
func (r *Repository) StoreDesktopConsent(
	ctx context.Context,
	operationID string,
	receipt runtimeport.DesktopConsentReceipt,
) error {
	statement := receipt.Statement()
	payload, err := encodeDesktop(statement, receipt.Signature(), receipt.Digest())
	if err != nil {
		return runtimeport.ErrDesktopConsentIntegrity
	}
	return r.store(ctx, operationID, statement.PlanDigest, kindDesktop, receipt.Digest(), payload,
		runtimeport.ErrDesktopConsentIntegrity)
}

// LoadDesktopConsent authenticates and strictly restores one Desktop receipt.
func (r *Repository) LoadDesktopConsent(
	ctx context.Context,
	operationID string,
	planDigest runtimeinstall.Hash,
) (runtimeport.DesktopConsentReceipt, error) {
	payload, err := r.load(ctx, operationID, planDigest, kindDesktop, runtimeport.ErrDesktopConsentIntegrity)
	if err != nil {
		return runtimeport.DesktopConsentReceipt{}, err
	}
	receipt, err := decodeDesktop(payload)
	if err != nil || receipt.Statement().PlanDigest != planDigest {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	return receipt, nil
}

type envelope struct {
	SchemaVersion uint16          `json:"schema_version"`
	Kind          string          `json:"kind"`
	OperationID   string          `json:"operation_id"`
	PlanDigest    string          `json:"plan_digest"`
	ReceiptDigest string          `json:"receipt_digest"`
	Receipt       json.RawMessage `json:"receipt"`
}

func (r *Repository) store(
	ctx context.Context,
	operationID string,
	planDigest runtimeinstall.Hash,
	kind string,
	receiptDigest runtimeinstall.Hash,
	receiptPayload []byte,
	integrityError error,
) error {
	journalID, journal, err := r.journal(ctx, operationID, integrityError)
	if err != nil || planDigest.IsZero() || receiptDigest.IsZero() {
		return integrityError
	}
	payload, err := encodeEnvelope(operationID, planDigest, kind, receiptDigest, receiptPayload)
	if err != nil {
		return integrityError
	}
	latest, loadErr := journal.LoadLatest(ctx)
	switch {
	case loadErr == nil:
		if latest.OperationID != operationID || latest.Revision == 0 {
			return integrityError
		}
		persisted, decodeErr := decodeEnvelope(latest.Payload)
		if decodeErr != nil || persisted.OperationID != operationID || persisted.PlanDigest != planDigest.String() ||
			persisted.Kind != kind || persisted.ReceiptDigest != receiptDigest.String() ||
			!bytes.Equal(persisted.Receipt, receiptPayload) || !bytes.Equal(latest.Payload, payload) {
			return integrityError
		}
		if err := journal.ConfirmDurable(ctx, operationID, latest.Revision); err != nil {
			return integrityError
		}
		return nil
	case errors.Is(loadErr, journalport.ErrNotFound):
	default:
		return integrityError
	}
	capturedAt := r.clock.Now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() {
		return integrityError
	}
	if err := journal.Append(ctx, 0, journalport.Snapshot{
		OperationID: operationID, Revision: 1, CapturedAt: capturedAt, Payload: payload,
	}); err != nil {
		return integrityError
	}
	if err := journal.ConfirmDurable(ctx, journalID.String(), 1); err != nil {
		return integrityError
	}
	return nil
}

func (r *Repository) load(
	ctx context.Context,
	operationID string,
	planDigest runtimeinstall.Hash,
	kind string,
	integrityError error,
) ([]byte, error) {
	_, journal, err := r.journal(ctx, operationID, integrityError)
	if err != nil || planDigest.IsZero() {
		return nil, integrityError
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil || latest.OperationID != operationID || latest.Revision == 0 {
		return nil, integrityError
	}
	document, err := decodeEnvelope(latest.Payload)
	if err != nil || document.OperationID != operationID || document.PlanDigest != planDigest.String() ||
		document.Kind != kind {
		return nil, integrityError
	}
	if err := journal.ConfirmDurable(ctx, operationID, latest.Revision); err != nil {
		return nil, integrityError
	}
	return bytes.Clone(document.Receipt), nil
}

func (r *Repository) journal(
	ctx context.Context,
	operationID string,
	integrityError error,
) (install.OperationID, *bootstrapadapter.AnchoredJournal, error) {
	if r == nil || ctx == nil || r.provider == nil || r.clock == nil {
		return install.OperationID{}, nil, integrityError
	}
	if err := ctx.Err(); err != nil {
		return install.OperationID{}, nil, err
	}
	identifier, err := install.NewOperationID(operationID)
	if err != nil {
		return install.OperationID{}, nil, integrityError
	}
	resolved, err := r.provider.JournalFor(ctx, identifier)
	if err != nil {
		return install.OperationID{}, nil, integrityError
	}
	journal, ok := resolved.(*bootstrapadapter.AnchoredJournal)
	if !ok || journal == nil {
		return install.OperationID{}, nil, integrityError
	}
	return identifier, journal, nil
}

func encodeEnvelope(
	operationID string,
	planDigest runtimeinstall.Hash,
	kind string,
	receiptDigest runtimeinstall.Hash,
	receipt []byte,
) ([]byte, error) {
	if _, err := install.NewOperationID(operationID); err != nil {
		return nil, errors.New("invalid consent operation")
	}
	if planDigest.IsZero() || receiptDigest.IsZero() {
		return nil, errors.New("invalid consent digest")
	}
	if kind != kindLinux && kind != kindDesktop {
		return nil, errors.New("invalid consent platform")
	}
	if len(receipt) == 0 || len(receipt) > maximumSnapshotSize {
		return nil, errors.New("invalid consent receipt size")
	}
	payload, err := json.Marshal(envelope{
		SchemaVersion: schemaVersion, Kind: kind, OperationID: operationID,
		PlanDigest: planDigest.String(), ReceiptDigest: receiptDigest.String(), Receipt: bytes.Clone(receipt),
	})
	if err != nil {
		return nil, errors.New("encode consent envelope")
	}
	if len(payload) == 0 || len(payload) > maximumSnapshotSize {
		return nil, errors.New("invalid consent envelope size")
	}
	return payload, nil
}

func decodeEnvelope(payload []byte) (envelope, error) {
	var document envelope
	if !strictDecode(payload, &document) || document.SchemaVersion != schemaVersion ||
		(document.Kind != kindLinux && document.Kind != kindDesktop) {
		return envelope{}, errors.New("invalid consent envelope")
	}
	planDigest, planErr := runtimeinstall.ParseHash(document.PlanDigest)
	receiptDigest, receiptErr := runtimeinstall.ParseHash(document.ReceiptDigest)
	canonical, encodeErr := encodeEnvelope(
		document.OperationID, planDigest, document.Kind, receiptDigest, document.Receipt,
	)
	if planErr != nil || receiptErr != nil || encodeErr != nil || !bytes.Equal(canonical, payload) {
		return envelope{}, errors.New("invalid consent envelope")
	}
	return document, nil
}

type linuxReceiptDocument struct {
	RequestDigest   string            `json:"request_digest"`
	PlanDigest      string            `json:"plan_digest"`
	AuthorityDigest string            `json:"authority_digest"`
	CatalogDigest   string            `json:"catalog_digest"`
	ArtifactDigest  string            `json:"artifact_digest"`
	TermsDigest     string            `json:"terms_digest"`
	PrincipalID     string            `json:"principal_id"`
	MachineDigest   string            `json:"machine_digest"`
	Nonce           runtimeport.Nonce `json:"nonce"`
	AcceptedAt      int64             `json:"accepted_at_unix_micro"`
	ExpiresAt       int64             `json:"expires_at_unix_micro"`
	Signature       []byte            `json:"signature"`
	ReceiptDigest   string            `json:"receipt_digest"`
}

func encodeLinux(
	statement runtimeport.LinuxConsentStatement,
	signature []byte,
	receiptDigest runtimeinstall.Hash,
) ([]byte, error) {
	if _, err := statement.CanonicalBytes(); err != nil || receiptDigest.IsZero() || len(signature) == 0 {
		return nil, runtimeport.ErrLinuxConsentIntegrity
	}
	return json.Marshal(linuxReceiptDocument{
		RequestDigest: statement.RequestDigest.String(), PlanDigest: statement.PlanDigest.String(),
		AuthorityDigest: statement.AuthorityDigest.String(), CatalogDigest: statement.CatalogDigest.String(),
		ArtifactDigest: statement.ArtifactDigest.String(), TermsDigest: statement.TermsDigest.String(),
		PrincipalID: statement.PrincipalID, MachineDigest: statement.MachineDigest.String(), Nonce: statement.Nonce,
		AcceptedAt: statement.AcceptedAt.UnixMicro(), ExpiresAt: statement.ExpiresAt.UnixMicro(),
		Signature: bytes.Clone(signature), ReceiptDigest: receiptDigest.String(),
	})
}

func decodeLinux(payload []byte) (runtimeport.LinuxConsentReceipt, error) {
	var document linuxReceiptDocument
	if !strictDecode(payload, &document) {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	request, requestErr := runtimeinstall.ParseHash(document.RequestDigest)
	plan, planErr := runtimeinstall.ParseHash(document.PlanDigest)
	authority, authorityErr := runtimeinstall.ParseHash(document.AuthorityDigest)
	catalog, catalogErr := runtimeinstall.ParseHash(document.CatalogDigest)
	artifact, artifactErr := runtimeinstall.ParseHash(document.ArtifactDigest)
	terms, termsErr := runtimeinstall.ParseHash(document.TermsDigest)
	machine, machineErr := runtimeinstall.ParseHash(document.MachineDigest)
	expectedDigest, digestErr := runtimeinstall.ParseHash(document.ReceiptDigest)
	statement := runtimeport.LinuxConsentStatement{
		RequestDigest: request, PlanDigest: plan, AuthorityDigest: authority, CatalogDigest: catalog,
		ArtifactDigest: artifact, TermsDigest: terms, PrincipalID: document.PrincipalID, MachineDigest: machine,
		Nonce: document.Nonce, AcceptedAt: time.UnixMicro(document.AcceptedAt).UTC(),
		ExpiresAt: time.UnixMicro(document.ExpiresAt).UTC(),
	}
	receipt, receiptErr := runtimeport.NewSignedLinuxConsentReceipt(statement, document.Signature)
	canonical, encodeErr := encodeLinux(statement, document.Signature, expectedDigest)
	if requestErr != nil || planErr != nil || authorityErr != nil || catalogErr != nil || artifactErr != nil ||
		termsErr != nil || machineErr != nil || digestErr != nil || receiptErr != nil || encodeErr != nil ||
		receipt.Digest() != expectedDigest || !bytes.Equal(canonical, payload) {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	return receipt, nil
}

type desktopReceiptDocument struct {
	RequestDigest              string            `json:"request_digest"`
	AuthorityDigest            string            `json:"authority_digest"`
	PlanDigest                 string            `json:"plan_digest"`
	TermsDigest                string            `json:"terms_digest"`
	PrincipalID                string            `json:"principal_id"`
	MachineDigest              string            `json:"machine_digest"`
	Nonce                      runtimeport.Nonce `json:"nonce"`
	ExplicitlyAccepted         bool              `json:"explicitly_accepted"`
	AuthorityAndEntitlement    bool              `json:"authority_and_entitlement"`
	NonPreselectedConfirmation bool              `json:"non_preselected_confirmation"`
	AcceptedAt                 int64             `json:"accepted_at_unix_micro"`
	ExpiresAt                  int64             `json:"expires_at_unix_micro"`
	Signature                  []byte            `json:"signature"`
	ReceiptDigest              string            `json:"receipt_digest"`
}

func encodeDesktop(
	statement runtimeport.DesktopConsentStatement,
	signature []byte,
	receiptDigest runtimeinstall.Hash,
) ([]byte, error) {
	if _, err := statement.CanonicalBytes(); err != nil || receiptDigest.IsZero() || len(signature) == 0 {
		return nil, runtimeport.ErrDesktopConsentIntegrity
	}
	return json.Marshal(desktopReceiptDocument{
		RequestDigest: statement.RequestDigest.String(), AuthorityDigest: statement.AuthorityDigest.String(),
		PlanDigest: statement.PlanDigest.String(), TermsDigest: statement.TermsDigest.String(),
		PrincipalID: statement.PrincipalID, MachineDigest: statement.MachineDigest.String(), Nonce: statement.Nonce,
		ExplicitlyAccepted: statement.ExplicitlyAccepted, AuthorityAndEntitlement: statement.AuthorityAndEntitlement,
		NonPreselectedConfirmation: statement.NonPreselectedConfirmation,
		AcceptedAt:                 statement.AcceptedAt.UnixMicro(), ExpiresAt: statement.ExpiresAt.UnixMicro(),
		Signature: bytes.Clone(signature), ReceiptDigest: receiptDigest.String(),
	})
}

func decodeDesktop(payload []byte) (runtimeport.DesktopConsentReceipt, error) {
	var document desktopReceiptDocument
	if !strictDecode(payload, &document) {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	request, requestErr := runtimeinstall.ParseHash(document.RequestDigest)
	authority, authorityErr := runtimeinstall.ParseHash(document.AuthorityDigest)
	plan, planErr := runtimeinstall.ParseHash(document.PlanDigest)
	terms, termsErr := runtimeinstall.ParseHash(document.TermsDigest)
	machine, machineErr := runtimeinstall.ParseHash(document.MachineDigest)
	expectedDigest, digestErr := runtimeinstall.ParseHash(document.ReceiptDigest)
	statement := runtimeport.DesktopConsentStatement{
		RequestDigest: request, AuthorityDigest: authority, PlanDigest: plan, TermsDigest: terms,
		PrincipalID: document.PrincipalID, MachineDigest: machine, Nonce: document.Nonce,
		ExplicitlyAccepted: document.ExplicitlyAccepted, AuthorityAndEntitlement: document.AuthorityAndEntitlement,
		NonPreselectedConfirmation: document.NonPreselectedConfirmation,
		AcceptedAt:                 time.UnixMicro(document.AcceptedAt).UTC(),
		ExpiresAt:                  time.UnixMicro(document.ExpiresAt).UTC(),
	}
	receipt, receiptErr := runtimeport.NewSignedDesktopConsentReceipt(statement, document.Signature)
	canonical, encodeErr := encodeDesktop(statement, document.Signature, expectedDigest)
	if requestErr != nil || authorityErr != nil || planErr != nil || termsErr != nil || machineErr != nil ||
		digestErr != nil || receiptErr != nil || encodeErr != nil || receipt.Digest() != expectedDigest ||
		!bytes.Equal(canonical, payload) {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	return receipt, nil
}

func strictDecode(payload []byte, destination any) bool {
	if len(payload) == 0 || len(payload) > maximumSnapshotSize || !json.Valid(payload) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() { //nolint:exhaustive // Only nilable port kinds require special handling.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ runtimeport.LinuxConsentRepository   = (*Repository)(nil)
	_ runtimeport.DesktopConsentRepository = (*Repository)(nil)
)
