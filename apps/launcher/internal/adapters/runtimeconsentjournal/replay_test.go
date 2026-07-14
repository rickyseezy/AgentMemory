package runtimeconsentjournal

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const replayOperation = "019f6001-0000-7000-8000-000000000003"

func TestReplayLedgerPersistsLinuxAndDesktopChallengesAcrossRestart(t *testing.T) {
	t.Parallel()
	provider := newTestProvider(t)
	clock := fixedClock{now: time.Date(2026, 7, 15, 14, 0, 0, 123000000, time.UTC)}
	ledger, err := NewReplayLedger(provider, clock, replayOperation)
	if err != nil {
		t.Fatal(err)
	}
	linuxNonce, desktopNonce := replayNonce(1), replayNonce(2)
	linuxReceipt, desktopReceipt := testHash("linux-replay"), testHash("desktop-replay")
	if err := ledger.ConsumePrivilegeReceipt(t.Context(), linuxNonce, linuxReceipt); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ConsumeDesktopMutation(t.Context(), desktopNonce, desktopReceipt); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewReplayLedger(provider, clock, replayOperation)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConsumePrivilegeReceipt(t.Context(), linuxNonce, linuxReceipt); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("Linux replay error=%v", err)
	}
	if err := restarted.ConsumeDesktopMutation(t.Context(), desktopNonce, desktopReceipt); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("desktop replay error=%v", err)
	}
	operation, _ := install.NewOperationID(replayOperation)
	journal, _ := provider.JournalFor(t.Context(), operation)
	snapshot, err := journal.LoadLatest(t.Context())
	document, decodeError := decodeReplayDocument(snapshot.Payload)
	if err != nil || decodeError != nil || snapshot.Revision != 2 || document.Revision != 2 ||
		len(document.Entries) != 2 || document.Entries[0].Domain != replayDomainDesktop ||
		document.Entries[1].Domain != replayDomainLinux {
		t.Fatalf("snapshot=%+v document=%+v errors=%v/%v", snapshot, document, err, decodeError)
	}
}

func TestReplayLedgerAtomicallyAllowsOnlyOneConcurrentNonceConsumer(t *testing.T) {
	t.Parallel()
	provider := newTestProvider(t)
	ledger, err := NewReplayLedger(
		provider,
		fixedClock{now: time.Date(2026, 7, 15, 14, 1, 0, 0, time.UTC)},
		replayOperation,
	)
	if err != nil {
		t.Fatal(err)
	}
	nonce, receipt := replayNonce(3), testHash("concurrent-replay")
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- ledger.ConsumePrivilegeReceipt(context.Background(), nonce, receipt)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes, replays := 0, 0
	for result := range results {
		if result == nil {
			successes++
		} else if errors.Is(result, runtimeport.ErrPrivilegeIntegrity) {
			replays++
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("successes=%d replays=%d", successes, replays)
	}
}

func TestReplayLedgerRejectsCrossDomainReuseAndUnsafeDependencies(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 7, 15, 14, 2, 0, 0, time.UTC)}
	provider := newTestProvider(t)
	ledger, _ := NewReplayLedger(provider, clock, replayOperation)
	nonce, receipt := replayNonce(4), testHash("cross-domain")
	if err := ledger.ConsumePrivilegeReceipt(t.Context(), nonce, receipt); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ConsumeDesktopMutation(t.Context(), nonce, testHash("other-receipt")); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("cross-domain reuse error=%v", err)
	}
	for name, construct := range map[string]func() (*ReplayLedger, error){
		"nil provider":  func() (*ReplayLedger, error) { return NewReplayLedger(nil, clock, replayOperation) },
		"nil clock":     func() (*ReplayLedger, error) { return NewReplayLedger(provider, nil, replayOperation) },
		"bad operation": func() (*ReplayLedger, error) { return NewReplayLedger(provider, clock, "../bad") },
	} {
		if candidate, err := construct(); err == nil || candidate != nil {
			t.Fatalf("%s accepted", name)
		}
	}
	unprotected, _ := NewReplayLedger(staticProvider{journal: &memoryJournal{}}, clock, replayOperation)
	if err := unprotected.ConsumePrivilegeReceipt(t.Context(), replayNonce(5), receipt); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("unprotected journal error=%v", err)
	}
	zeroClock, _ := NewReplayLedger(newTestProvider(t), fixedClock{}, replayOperation)
	if err := zeroClock.ConsumeDesktopMutation(t.Context(), replayNonce(6), receipt); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero clock error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ledger.ConsumePrivilegeReceipt(cancelled, replayNonce(7), receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if err := (*ReplayLedger)(nil).ConsumePrivilegeReceipt(t.Context(), replayNonce(8), receipt); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("nil ledger error=%v", err)
	}
	if err := ledger.ConsumePrivilegeReceipt(t.Context(), runtimeport.Nonce{}, receipt); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("zero nonce error=%v", err)
	}
	if err := ledger.ConsumeDesktopMutation(t.Context(), replayNonce(9), runtimeinstall.Hash{}); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero receipt error=%v", err)
	}
}

func TestReplayDocumentCodecRejectsNonCanonicalAndDamagedState(t *testing.T) {
	t.Parallel()
	nonce := replayNonce(10)
	document := replayDocument{
		SchemaVersion: replaySchemaVersion, OperationID: replayOperation, Revision: 1,
		Entries: []replayEntry{{
			Domain: replayDomainLinux, Nonce: nonceHex(nonce), ReceiptDigest: testHash("codec").String(),
		}},
	}
	payload, err := encodeReplayDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeReplayDocument(payload)
	if err != nil || decoded.Revision != 1 || !bytes.Equal(payload, mustReplayBytes(t, decoded)) {
		t.Fatalf("decoded=%+v error=%v", decoded, err)
	}
	for name, damaged := range map[string][]byte{
		"empty":      nil,
		"malformed":  []byte(`{"schema_version":`),
		"unknown":    append(bytes.Clone(bytes.TrimSuffix(payload, []byte("}"))), []byte(`,"unknown":true}`)...),
		"trailing":   append(bytes.Clone(payload), []byte(` {}`)...),
		"whitespace": append([]byte(" "), payload...),
		"oversized":  bytes.Repeat([]byte("x"), maximumReplayBytes+1),
	} {
		if _, err := decodeReplayDocument(damaged); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	invalid := []replayDocument{
		{},
		{SchemaVersion: 2, OperationID: replayOperation, Revision: 1, Entries: document.Entries},
		{SchemaVersion: 1, OperationID: "../bad", Revision: 1, Entries: document.Entries},
		{SchemaVersion: 1, OperationID: replayOperation, Revision: 2, Entries: document.Entries},
		{SchemaVersion: 1, OperationID: replayOperation, Revision: 1, Entries: []replayEntry{{Domain: "foreign", Nonce: nonceHex(nonce), ReceiptDigest: testHash("codec").String()}}},
		{SchemaVersion: 1, OperationID: replayOperation, Revision: 1, Entries: []replayEntry{{Domain: replayDomainLinux, Nonce: "bad", ReceiptDigest: testHash("codec").String()}}},
		{SchemaVersion: 1, OperationID: replayOperation, Revision: 1, Entries: []replayEntry{{Domain: replayDomainLinux, Nonce: nonceHex(nonce), ReceiptDigest: "bad"}}},
	}
	for index, candidate := range invalid {
		if _, err := encodeReplayDocument(candidate); err == nil {
			t.Fatalf("invalid document %d accepted", index)
		}
	}
	if !replayNoncePresent(document.Entries, nonceHex(nonce)) || replayNoncePresent(document.Entries, nonceHex(replayNonce(11))) {
		t.Fatal("nonce lookup did not preserve exact identity")
	}
	if validReplayDomain("foreign") {
		t.Fatal("foreign replay domain accepted")
	}
}

func replayNonce(seed byte) runtimeport.Nonce {
	var nonce runtimeport.Nonce
	for index := range nonce {
		nonce[index] = seed + byte(index)
	}
	return nonce
}

func nonceHex(nonce runtimeport.Nonce) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(nonce)*2)
	for index, value := range nonce {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&0x0f]
	}
	return string(encoded)
}

func mustReplayBytes(t testing.TB, document replayDocument) []byte {
	t.Helper()
	payload, err := encodeReplayDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
