package runtimeconsentjournal

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	linuxOperation   = "019f6001-0000-7000-8000-000000000001"
	desktopOperation = "019f6001-0000-7000-8000-000000000002"
)

func TestRepositoryPersistsAndRestoresAuthenticatedPlatformReceipts(t *testing.T) {
	t.Parallel()
	provider := newTestProvider(t)
	clock := fixedClock{now: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	repository, err := New(provider, clock)
	if err != nil {
		t.Fatal(err)
	}

	linux := testLinuxReceipt(t, "linux")
	if err := repository.StoreLinuxConsent(context.Background(), linuxOperation, linux); err != nil {
		t.Fatal(err)
	}
	if err := repository.StoreLinuxConsent(context.Background(), linuxOperation, linux); err != nil {
		t.Fatalf("idempotent Linux store: %v", err)
	}
	restarted, _ := New(provider, clock)
	loadedLinux, err := restarted.LoadLinuxConsent(
		context.Background(), linuxOperation, linux.Statement().PlanDigest,
	)
	if err != nil || loadedLinux.Digest() != linux.Digest() ||
		!bytes.Equal(loadedLinux.Signature(), linux.Signature()) {
		t.Fatalf("Linux receipt=(%x,%v)", loadedLinux.Digest(), err)
	}

	desktop := testDesktopReceipt(t, "desktop")
	if err := repository.StoreDesktopConsent(context.Background(), desktopOperation, desktop); err != nil {
		t.Fatal(err)
	}
	if err := repository.StoreDesktopConsent(context.Background(), desktopOperation, desktop); err != nil {
		t.Fatalf("idempotent Desktop store: %v", err)
	}
	loadedDesktop, err := restarted.LoadDesktopConsent(
		context.Background(), desktopOperation, desktop.Statement().PlanDigest,
	)
	if err != nil || loadedDesktop.Digest() != desktop.Digest() ||
		!bytes.Equal(loadedDesktop.Signature(), desktop.Signature()) {
		t.Fatalf("Desktop receipt=(%x,%v)", loadedDesktop.Digest(), err)
	}
}

func TestRepositoryRejectsSubstitutionUnprotectedStorageAndInvalidDependencies(t *testing.T) {
	t.Parallel()
	provider := newTestProvider(t)
	repository, _ := New(provider, fixedClock{now: time.Now().UTC()})
	linux := testLinuxReceipt(t, "first")
	if err := repository.StoreLinuxConsent(context.Background(), linuxOperation, linux); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"overwrite": func() error {
			return repository.StoreLinuxConsent(context.Background(), linuxOperation, testLinuxReceipt(t, "second"))
		},
		"plan substitution": func() error {
			_, err := repository.LoadLinuxConsent(context.Background(), linuxOperation, testHash("other-plan"))
			return err
		},
		"platform substitution": func() error {
			_, err := repository.LoadDesktopConsent(context.Background(), linuxOperation, linux.Statement().PlanDigest)
			return err
		},
		"bad operation": func() error {
			return repository.StoreLinuxConsent(context.Background(), "../not-an-operation", linux)
		},
		"missing operation": func() error {
			_, err := repository.LoadLinuxConsent(context.Background(), desktopOperation, linux.Statement().PlanDigest)
			return err
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	unprotected, _ := New(staticProvider{journal: &memoryJournal{}}, fixedClock{now: time.Now().UTC()})
	if err := unprotected.StoreLinuxConsent(context.Background(), linuxOperation, linux); err == nil {
		t.Fatal("unprotected journal accepted")
	}
	zeroClock, _ := New(newTestProvider(t), fixedClock{})
	if err := zeroClock.StoreLinuxConsent(context.Background(), linuxOperation, linux); err == nil {
		t.Fatal("zero capture time accepted")
	}
	var typedNilProvider *testProvider
	var typedNilClock *fixedClock
	if _, err := New(nil, fixedClock{}); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := New(typedNilProvider, fixedClock{}); err == nil {
		t.Fatal("typed nil provider accepted")
	}
	if _, err := New(staticProvider{}, typedNilClock); err == nil {
		t.Fatal("typed nil clock accepted")
	}
}

func TestConsentReceiptCodecsRejectNonCanonicalAndDamagedDocuments(t *testing.T) {
	t.Parallel()
	linux := testLinuxReceipt(t, "codec-linux")
	linuxPayload, err := encodeLinux(linux.Statement(), linux.Signature(), linux.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := decodeLinux(linuxPayload); err != nil || restored.Digest() != linux.Digest() {
		t.Fatalf("decode Linux=%x,%v", restored.Digest(), err)
	}
	desktop := testDesktopReceipt(t, "codec-desktop")
	desktopPayload, err := encodeDesktop(desktop.Statement(), desktop.Signature(), desktop.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := decodeDesktop(desktopPayload); err != nil || restored.Digest() != desktop.Digest() {
		t.Fatalf("decode Desktop=%x,%v", restored.Digest(), err)
	}

	for name, payload := range map[string][]byte{
		"empty":     nil,
		"malformed": []byte(`{"schema_version":`),
		"unknown": append(
			bytes.Clone(bytes.TrimSuffix(linuxPayload, []byte("}"))), []byte(`,"unknown":true}`)...,
		),
		"trailing":  append(bytes.Clone(linuxPayload), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte("x"), maximumSnapshotSize+1),
	} {
		if _, err := decodeLinux(payload); err == nil {
			t.Fatalf("Linux %s accepted", name)
		}
	}
	damaged := bytes.Replace(linuxPayload, []byte(linux.Statement().PlanDigest.String()), []byte(testHash("damage").String()), 1)
	if _, err := decodeLinux(damaged); err == nil {
		t.Fatal("digest-damaged Linux receipt accepted")
	}
	damaged = bytes.Replace(desktopPayload, []byte(`"explicitly_accepted":true`), []byte(`"explicitly_accepted":false`), 1)
	if _, err := decodeDesktop(damaged); err == nil {
		t.Fatal("confirmation-damaged Desktop receipt accepted")
	}

	enveloped, err := encodeEnvelope(linuxOperation, linux.Statement().PlanDigest, kindLinux, linux.Digest(), linuxPayload)
	if err != nil {
		t.Fatalf("envelope len=%d plan_zero=%t receipt_zero=%t error=%v", len(linuxPayload),
			linux.Statement().PlanDigest.IsZero(), linux.Digest().IsZero(), err)
	}
	if decoded, err := decodeEnvelope(enveloped); err != nil || !bytes.Equal(decoded.Receipt, linuxPayload) {
		t.Fatalf("envelope=%+v,%v", decoded, err)
	}
	for _, damagedEnvelope := range [][]byte{
		bytes.Replace(enveloped, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
		bytes.Replace(enveloped, []byte(`"kind":"linux"`), []byte(`"kind":"other"`), 1),
		append(bytes.Clone(bytes.TrimSuffix(enveloped, []byte("}"))), []byte(`,"extra":1}`)...),
	} {
		if _, err := decodeEnvelope(damagedEnvelope); err == nil {
			t.Fatal("damaged envelope accepted")
		}
	}
}

func testLinuxReceipt(t testing.TB, seed string) runtimeport.LinuxConsentReceipt {
	t.Helper()
	accepted := time.Date(2026, 7, 15, 10, 0, 0, 123000000, time.UTC)
	receipt, err := runtimeport.NewSignedLinuxConsentReceipt(runtimeport.LinuxConsentStatement{
		RequestDigest: testHash(seed + "-request"), PlanDigest: testHash(seed + "-plan"),
		AuthorityDigest: testHash(seed + "-authority"), CatalogDigest: testHash(seed + "-catalog"),
		ArtifactDigest: testHash(seed + "-artifact"), TermsDigest: testHash(seed + "-terms"),
		PrincipalID: "linux:uid:1000", MachineDigest: testHash(seed + "-machine"),
		Nonce: runtimeport.Nonce{1, 2, 3}, AcceptedAt: accepted, ExpiresAt: accepted.Add(24 * time.Hour),
	}, bytes.Repeat([]byte{0x5a}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func testDesktopReceipt(t testing.TB, seed string) runtimeport.DesktopConsentReceipt {
	t.Helper()
	accepted := time.Date(2026, 7, 15, 10, 0, 0, 456000000, time.UTC)
	receipt, err := runtimeport.NewSignedDesktopConsentReceipt(runtimeport.DesktopConsentStatement{
		RequestDigest: testHash(seed + "-request"), AuthorityDigest: testHash(seed + "-authority"),
		PlanDigest: testHash(seed + "-plan"), TermsDigest: testHash(seed + "-terms"),
		PrincipalID: "sid:S-1-5-21-1000", MachineDigest: testHash(seed + "-machine"),
		Nonce: runtimeport.Nonce{4, 5, 6}, ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: accepted, ExpiresAt: accepted.Add(24 * time.Hour),
	}, bytes.Repeat([]byte{0x6b}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func testHash(value string) runtimeinstall.Hash { return runtimeinstall.Sum([]byte(value)) }

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type staticProvider struct {
	journal journalport.Journal
	err     error
}

func (p staticProvider) JournalFor(context.Context, install.OperationID) (journalport.Journal, error) {
	return p.journal, p.err
}

type testProvider struct {
	mu       sync.Mutex
	owner    install.OwnerBinding
	keys     *bootstrapadapter.MemoryOperationKeySource
	anchors  *bootstrapadapter.MemoryRollbackAnchorStore
	journals map[string]*bootstrapadapter.AnchoredJournal
}

func newTestProvider(t testing.TB) *testProvider {
	t.Helper()
	owner, err := install.BindOwner("consent-test-machine", "consent-test-principal")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x7c}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		t.Fatal(err)
	}
	return &testProvider{owner: owner, keys: keys, anchors: anchors, journals: make(map[string]*bootstrapadapter.AnchoredJournal)}
}

func (p *testProvider) JournalFor(ctx context.Context, operationID install.OperationID) (journalport.Journal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.journals[operationID.String()]; existing != nil {
		return existing, nil
	}
	key, err := p.keys.Ensure(ctx, operationID, p.owner)
	if err != nil {
		return nil, err
	}
	journal, err := bootstrapadapter.NewAnchoredJournal(&memoryJournal{}, p.anchors, key, operationID, p.owner)
	if err != nil {
		return nil, err
	}
	p.journals[operationID.String()] = journal
	return journal, nil
}

type memoryJournal struct {
	mu       sync.Mutex
	snapshot journalport.Snapshot
	present  bool
}

func (j *memoryJournal) Append(_ context.Context, expected uint64, snapshot journalport.Snapshot) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	current := uint64(0)
	if j.present {
		current = j.snapshot.Revision
	}
	if expected != current || snapshot.Revision != current+1 {
		return journalport.ErrConflict
	}
	j.snapshot = cloneSnapshot(snapshot)
	j.present = true
	return nil
}

func (j *memoryJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.present {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	return cloneSnapshot(j.snapshot), nil
}

func (j *memoryJournal) ConfirmDurable(_ context.Context, operationID string, revision uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.present || j.snapshot.OperationID != operationID || j.snapshot.Revision != revision {
		return journalport.ErrConflict
	}
	return nil
}

func cloneSnapshot(snapshot journalport.Snapshot) journalport.Snapshot {
	clone := snapshot
	clone.Payload = bytes.Clone(snapshot.Payload)
	return clone
}
