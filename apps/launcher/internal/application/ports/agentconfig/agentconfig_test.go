package agentconfig

import (
	"errors"
	"strings"
	"testing"

	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

func TestPF001PortValuesAreValidatedAndCopyOwned(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"", "bad\x00path", "bad\npath", strings.Repeat("a", 4097)} {
		if _, err := NewConfigLocation(invalid); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("NewConfigLocation(%q) error = %v", invalid, err)
		}
	}
	location, err := NewConfigLocation("/owner/config.json")
	if err != nil || location.String() != "/owner/config.json" {
		t.Fatalf("NewConfigLocation() location=%q error=%v", location.String(), err)
	}
	content := []byte(`{"value":true}`)
	snapshot, err := NewSnapshot(true, content)
	if err != nil {
		t.Fatal(err)
	}
	content[0] = 'x'
	returned := snapshot.Content()
	returned[0] = 'y'
	if string(snapshot.Content()) != `{"value":true}` || !snapshot.Exists() || !snapshot.Digest().Equal(domain.DigestBytes([]byte(`{"value":true}`))) {
		t.Fatal("Snapshot did not copy-own exact bytes")
	}
	absent, err := NewSnapshot(false, nil)
	if err != nil || absent.Exists() || len(absent.Content()) != 0 || !absent.Digest().IsZero() {
		t.Fatalf("absent snapshot error=%v", err)
	}
	if _, err := NewSnapshot(false, []byte("unexpected")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewSnapshot(absent content) error=%v", err)
	}
	if _, err := NewSnapshot(true, make([]byte, domain.MaxDocumentBytes+1)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewSnapshot(oversize) error=%v", err)
	}
	if !NewDetection(true).Exists() || NewDetection(false).Exists() {
		t.Fatal("Detection existence is unstable")
	}
}

func TestPF001ApplyReceiptRequiresCompleteHashBoundBackupEvidence(t *testing.T) {
	t.Parallel()
	before := domain.DigestBytes([]byte("before"))
	after := domain.DigestBytes([]byte("after"))
	entry := domain.DigestBytes([]byte("entry"))
	valid, err := NewApplyReceipt(true, true, before, after, entry, "/private/backup", before)
	if err != nil {
		t.Fatal(err)
	}
	if !valid.Valid() || !valid.Changed() || !valid.OriginalExisted() ||
		!valid.BeforeDigest().Equal(before) || !valid.AfterDigest().Equal(after) ||
		!valid.ManagedEntryDigest().Equal(entry) || valid.BackupLocation() != "/private/backup" ||
		!valid.BackupDigest().Equal(before) {
		t.Fatal("apply receipt accessors lost evidence")
	}
	for _, test := range []struct {
		changed bool
		existed bool
		before  domain.Digest
		after   domain.Digest
		entry   domain.Digest
		path    string
		backup  domain.Digest
	}{
		{false, true, before, after, entry, "/backup", before},
		{true, true, domain.Digest{}, after, entry, "/backup", before},
		{true, true, before, after, entry, "", before},
		{true, true, before, after, entry, "/backup", after},
		{true, false, before, after, entry, "", domain.Digest{}},
		{true, false, domain.Digest{}, after, entry, "/backup", domain.Digest{}},
		{true, false, domain.Digest{}, domain.Digest{}, entry, "", domain.Digest{}},
		{true, false, domain.Digest{}, after, domain.Digest{}, "", domain.Digest{}},
	} {
		if _, err := NewApplyReceipt(test.changed, test.existed, test.before, test.after, test.entry, test.path, test.backup); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("NewApplyReceipt(%+v) error=%v", test, err)
		}
	}
}

func TestPF001RestoreReceiptAndStableWrapping(t *testing.T) {
	t.Parallel()
	digest := domain.DigestBytes([]byte("restored"))
	existing, err := NewRestoreReceipt(true, digest)
	if err != nil || !existing.Valid() || !existing.Exists() || !existing.Digest().Equal(digest) {
		t.Fatalf("existing restore receipt error=%v", err)
	}
	absent, err := NewRestoreReceipt(false, domain.Digest{})
	if err != nil || !absent.Valid() || absent.Exists() || !absent.Digest().IsZero() {
		t.Fatalf("absent restore receipt error=%v", err)
	}
	if _, err := NewRestoreReceipt(true, domain.Digest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewRestoreReceipt(missing digest) error=%v", err)
	}
	if _, err := NewRestoreReceipt(false, digest); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewRestoreReceipt(absent digest) error=%v", err)
	}
	if err := Wrap(ErrConflict, "apply compare"); !errors.Is(err, ErrConflict) || err.Error() != "apply compare: agent configuration conflict" {
		t.Fatalf("Wrap() error=%v", err)
	}
}
