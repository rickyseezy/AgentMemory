//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001LinuxOperationJournalProviderCreatesOwnerKeyBoundPerOperationJournals(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	keys, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0x73}, 128)))
	anchors, _ := NewLinuxFileRollbackAnchorStore(locator, keys, ownerSource)
	provider, err := NewLinuxOperationJournalProvider(locator, keys, ownerSource, anchors)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := install.NewOperationID("provider-operation-a")
	secondID, _ := install.NewOperationID("provider-operation-b")
	first, err := provider.JournalFor(context.Background(), firstID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.JournalFor(context.Background(), secondID)
	if err != nil {
		t.Fatal(err)
	}
	for operationID, journal := range map[install.OperationID]journalport.Journal{firstID: first, secondID: second} {
		if err := journal.Append(context.Background(), 0, journalport.Snapshot{
			OperationID: operationID.String(),
			Revision:    1,
			CapturedAt:  time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC),
			Payload:     json.RawMessage(`{"state":"running"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	firstLatest, err := first.LoadLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondLatest, err := second.LoadLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstLatest.OperationID != firstID.String() || secondLatest.OperationID != secondID.String() {
		t.Fatal("journal provider crossed operation identities")
	}
	if err := first.ConfirmDurable(context.Background(), firstID.String(), firstLatest.Revision); err != nil {
		t.Fatalf("first operation durability confirmation = %v", err)
	}
	if err := second.ConfirmDurable(context.Background(), secondID.String(), secondLatest.Revision); err != nil {
		t.Fatalf("second operation durability confirmation = %v", err)
	}

	wrongOwner, _ := install.BindOwner("linux:machine-id:fedcba9876543210fedcba9876543210", "linux:uid:1000")
	wrongProvider, _ := NewLinuxOperationJournalProvider(locator, keys, linuxOwnerBindingStub{owner: wrongOwner}, anchors)
	if _, err := wrongProvider.JournalFor(context.Background(), firstID); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong provider owner error = %v", err)
	}
}

func TestPF001LinuxOperationJournalProviderRejectsOldButValidJournalReplay(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	keys, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0x83}, 64)))
	anchors, _ := NewLinuxFileRollbackAnchorStore(locator, keys, ownerSource)
	provider, _ := NewLinuxOperationJournalProvider(locator, keys, ownerSource, anchors)
	operationID, _ := install.NewOperationID("provider-old-valid-replay")
	journal, err := provider.JournalFor(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	first := journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    1,
		CapturedAt:  time.Date(2026, time.July, 13, 1, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"first"}`),
	}
	if err := journal.Append(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	journalPath, _ := locator.JournalPath(operationID)
	//nolint:gosec // G304: the journal path is emitted by the digest-only locator in an isolated replay fixture; owner=security expiry=2027-07-13.
	oldValidBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	second := journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    2,
		CapturedAt:  time.Date(2026, time.July, 13, 1, 0, 1, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"second"}`),
	}
	if err := journal.Append(context.Background(), 1, second); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: deliberate replay of authenticated old bytes at a digest-derived path verifies anti-rollback; owner=security expiry=2027-07-13.
	if err := os.WriteFile(journalPath, oldValidBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("old-but-valid journal replay error = %v", err)
	}
}

func TestPF001LinuxOperationJournalProviderPropagatesEverySecurityBoundary(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	keyRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("provider-edge-key")))
	operationID, _ := install.NewOperationID("provider-edge-operation")
	sentinel := errors.New("security boundary failed")

	tests := []struct {
		name      string
		owners    bootstrapport.OwnerBindingSource
		keys      bootstrapport.OperationKeySource
		operation install.OperationID
		want      error
	}{
		{
			name:      "owner lookup",
			owners:    linuxOwnerBindingStub{err: sentinel},
			keys:      linuxOperationKeyStub{ref: keyRef},
			operation: operationID,
			want:      sentinel,
		},
		{
			name:      "key provisioning",
			owners:    linuxOwnerBindingStub{owner: owner},
			keys:      linuxOperationKeyStub{ref: keyRef, ensureErr: sentinel},
			operation: operationID,
			want:      sentinel,
		},
		{
			name:      "invalid operation location",
			owners:    linuxOwnerBindingStub{owner: owner},
			keys:      linuxOperationKeyStub{ref: keyRef},
			operation: install.OperationID{},
			want:      journalport.ErrInvalidSnapshot,
		},
		{
			name:      "key access",
			owners:    linuxOwnerBindingStub{owner: owner},
			keys:      linuxOperationKeyStub{ref: keyRef, useErr: sentinel},
			operation: operationID,
			want:      sentinel,
		},
		{
			name:      "key callback omitted",
			owners:    linuxOwnerBindingStub{owner: owner},
			keys:      linuxOperationKeyStub{ref: keyRef, skipConsumer: true},
			operation: operationID,
			want:      errors.New("linux operation key source did not provide key access"),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider, err := NewLinuxOperationJournalProvider(locator, test.keys, test.owners, linuxRollbackAnchorStub{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.JournalFor(context.Background(), test.operation)
			if test.name == "key callback omitted" {
				if err == nil || err.Error() != test.want.Error() {
					t.Fatalf("JournalFor() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("JournalFor() error = %v, want %v", err, test.want)
			}
		})
	}
}

type linuxRollbackAnchorStub struct{}

func (linuxRollbackAnchorStub) Load(
	context.Context,
	install.BootstrapKeyRef,
	install.OperationID,
	install.OwnerBinding,
) (install.RollbackAnchor, error) {
	return install.RollbackAnchor{}, bootstrapport.ErrNotFound
}

func (linuxRollbackAnchorStub) Advance(
	context.Context,
	install.BootstrapKeyRef,
	uint64,
	install.RollbackAnchor,
) error {
	return nil
}

func (linuxRollbackAnchorStub) ConfirmDurable(
	context.Context,
	install.BootstrapKeyRef,
	install.RollbackAnchor,
) error {
	return nil
}

type linuxOperationKeyStub struct {
	ref          install.BootstrapKeyRef
	ensureErr    error
	useErr       error
	skipConsumer bool
}

func (s linuxOperationKeyStub) Ensure(
	context.Context,
	install.OperationID,
	install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	return s.ref, s.ensureErr
}

func (s linuxOperationKeyStub) UseHMACKey(
	_ context.Context,
	_ install.BootstrapKeyRef,
	_ install.OperationID,
	_ install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if s.useErr != nil {
		return s.useErr
	}
	if s.skipConsumer {
		return nil
	}
	return consumer(bytes.Repeat([]byte{0xc3}, 32))
}
