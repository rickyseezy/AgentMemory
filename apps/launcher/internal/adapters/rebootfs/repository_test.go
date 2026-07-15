package rebootfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

func TestPF001ContinuationRepositoryPublishesClaimsRecoversAndDeletes(t *testing.T) {
	repository, err := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	if err != nil {
		t.Fatal(err)
	}
	record := repositoryRecordFixture(t)
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(t.Context(), record.OperationID())
	if err != nil || !sameRecord(loaded, record) {
		t.Fatalf("Load() = (%+v, %v)", loaded, err)
	}
	token, _ := rebootcontinuation.TokenFor(record.OperationID())
	loadedByToken, err := repository.LoadByToken(t.Context(), token)
	if err != nil || !sameRecord(loadedByToken, record) {
		t.Fatalf("LoadByToken() = (%+v, %v)", loadedByToken, err)
	}
	if _, err := repository.LoadByToken(t.Context(), strings.Repeat("A", 64)); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("uppercase token error = %v", err)
	}
	if err := repository.Publish(t.Context(), record); !errors.Is(err, rebootapp.ErrRecordConflict) {
		t.Fatalf("replacement publish error = %v", err)
	}
	if err := repository.Claim(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	loadedByToken, err = repository.LoadByToken(t.Context(), token)
	if err != nil || !sameRecord(loadedByToken, record) {
		t.Fatalf("claimed LoadByToken() = (%+v, %v)", loadedByToken, err)
	}
	if _, err := os.Stat(repository.activePath(record.OperationID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active record survived claim: %v", err)
	}
	if _, err := os.Stat(repository.claimedPath(record.OperationID())); err != nil {
		t.Fatalf("claimed record missing: %v", err)
	}
	if err := repository.Claim(t.Context(), record); err != nil {
		t.Fatalf("same claim was not crash-recoverable: %v", err)
	}
	loaded, err = repository.Load(t.Context(), record.OperationID())
	if err != nil || !sameRecord(loaded, record) {
		t.Fatalf("claimed Load() = (%+v, %v)", loaded, err)
	}
	if err := repository.Delete(t.Context(), record.OperationID()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Delete(t.Context(), record.OperationID()); err != nil {
		t.Fatalf("Delete() was not idempotent: %v", err)
	}
	if _, err := repository.Load(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrRecordNotFound) {
		t.Fatalf("deleted Load() error = %v", err)
	}
	if _, err := repository.LoadByToken(t.Context(), token); !errors.Is(err, rebootapp.ErrRecordNotFound) {
		t.Fatalf("deleted LoadByToken() error = %v", err)
	}
}

func TestPF001ContinuationRepositoryRejectsSubstitutionAndCorruption(t *testing.T) {
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	foreign := repositoryRecordFixtureWithID(t, "019f5f23-5678-7def-9123-abcdef012399")
	if err := repository.Claim(t.Context(), foreign); !errors.Is(err, rebootapp.ErrRecordConflict) {
		t.Fatalf("foreign claim error = %v", err)
	}
	if err := os.WriteFile(repository.activePath(record.OperationID()), []byte(`{"launcher_path":"/opt/agentmemory","foreign":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Load(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("corrupt record error = %v", err)
	}
}

func TestPF001ContinuationRepositoryRejectsUnsafeRootsAndObjects(t *testing.T) {
	for _, root := range []string{"", "relative", t.TempDir() + string(filepath.Separator) + ".." + string(filepath.Separator) + "unsafe"} {
		if repository, err := NewRepository(root); repository != nil || !errors.Is(err, rebootapp.ErrRecordIntegrity) {
			t.Fatalf("NewRepository(%q) = (%v, %v)", root, repository, err)
		}
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(parent, "link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if repository, err := NewRepository(symlink); repository != nil || !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("symlink root accepted: (%v, %v)", repository, err)
	}
	repository, _ := NewRepository(filepath.Join(parent, "private"))
	record := repositoryRecordFixture(t)
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(repository.activePath(record.OperationID()), 0o644); err != nil { // #nosec G302 -- unsafe-mode rejection fixture.
		t.Fatal(err)
	}
	if _, err := repository.Load(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("unsafe record mode error = %v", err)
	}
}

func TestPF001ContinuationRepositoryValidatesCallsBeforeFilesystemAccess(t *testing.T) {
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := repository.Publish(cancelled, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publish error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context repository-boundary regression fixture.
	if _, err := repository.Load(nil, record.OperationID()); !errors.Is(err, rebootapp.ErrRecordIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil context load error = %v", err)
	}
	if err := repository.Claim(t.Context(), rebootcontinuation.Record{}); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("zero record claim error = %v", err)
	}
	var absent *Repository
	if err := absent.Delete(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("nil repository delete error = %v", err)
	}
}

func TestPF001ContinuationRepositoryReconcilesInterruptedClaimAndRejectsDivergence(t *testing.T) {
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(repository.activePath(record.OperationID()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repository.claimedPath(record.OperationID()), raw, 0o600); err != nil { // #nosec G703 -- digest-derived path under the test's private root.
		t.Fatal(err)
	}
	if loaded, err := repository.Load(t.Context(), record.OperationID()); err != nil || !sameRecord(loaded, record) {
		t.Fatalf("interrupted claim recovery = (%+v, %v)", loaded, err)
	}
	if pathExists(repository.activePath(record.OperationID())) {
		t.Fatal("recovered claim retained the obsolete active name")
	}

	// A different valid nonce for the same operation cannot replay a durable claim.
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	other, _ := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: record.LauncherPath(), LauncherDigest: record.LauncherDigest(), OperationID: record.OperationID(),
		JournalPath: record.JournalPath(), JournalDigest: record.JournalDigest(), ExpiresAt: record.ExpiresAt(),
		Nonce: rebootcontinuation.NonceBytes([]byte("other nonce")),
	}, now)
	if err := repository.Claim(t.Context(), other); !errors.Is(err, rebootapp.ErrRecordConflict) {
		t.Fatalf("different claimed nonce error = %v", err)
	}
}

func TestPF001ContinuationRecordCodecRejectsEveryMalformedField(t *testing.T) {
	record := repositoryRecordFixture(t)
	valid, _ := encodeRecord(record)
	if _, err := encodeRecord(rebootcontinuation.Record{}); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("zero record encode error = %v", err)
	}
	mutations := []string{
		string(valid) + `{}`,
		strings.Replace(string(valid), record.LauncherDigest().String(), "bad", 1),
		strings.Replace(string(valid), record.JournalDigest().String(), "bad", 1),
		strings.Replace(string(valid), record.OperationID().String(), "", 1),
		strings.Replace(string(valid), record.ExpiresAt().Format(time.RFC3339Nano), "not-a-time", 1),
		strings.Replace(string(valid), `"nonce":"`, `"nonce":"***`, 1),
		strings.Replace(string(valid), `"launcher_path":`, `"foreign":true,"launcher_path":`, 1),
	}
	for index, raw := range mutations {
		if _, err := decodeRecord([]byte(raw)); err == nil {
			t.Fatalf("malformed codec case %d accepted", index)
		}
	}
}

func TestPF001ContinuationRepositoryRejectsAbsentClaimAndUnsafeExistingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unsafe-root")
	if err := os.Mkdir(root, 0o755); err != nil { // #nosec G301 -- deliberately world-readable root rejection fixture.
		t.Fatal(err)
	}
	if repository, err := NewRepository(root); repository != nil || !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("world-readable root accepted: (%v, %v)", repository, err)
	}
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	if err := repository.Claim(t.Context(), record); !errors.Is(err, rebootapp.ErrRecordConflict) {
		t.Fatalf("absent claim error = %v", err)
	}
	if err := repository.Publish(t.Context(), rebootcontinuation.Record{}); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("zero publish error = %v", err)
	}
	if reopened, err := NewRepository(repository.root); reopened == nil || err != nil {
		t.Fatalf("valid existing private root could not reopen: (%v, %v)", reopened, err)
	}
}

func TestPF001ContinuationRepositoryReportsUnremovableAndCorruptClaimState(t *testing.T) {
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	if err := os.Mkdir(repository.activePath(record.OperationID()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository.activePath(record.OperationID()), "child"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repository.Delete(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("unremovable state error = %v", err)
	}
	if err := os.RemoveAll(repository.activePath(record.OperationID())); err != nil {
		t.Fatal(err)
	}
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := repository.Claim(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(repository.claimedPath(record.OperationID()), 0o644); err != nil { // #nosec G302 -- deliberately unsafe claimed-file rejection fixture.
		t.Fatal(err)
	}
	if err := repository.Claim(t.Context(), record); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("corrupt claimed state error = %v", err)
	}
	if err := os.Chmod(repository.claimedPath(record.OperationID()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(repository.activePath(record.OperationID()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository.activePath(record.OperationID()), "child"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repository.Claim(t.Context(), record); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("unremovable obsolete active state error = %v", err)
	}
}

func TestPF001ContinuationTokenLookupRejectsDivergentCrashState(t *testing.T) {
	repository, _ := NewRepository(filepath.Join(t.TempDir(), "continuations"))
	record := repositoryRecordFixture(t)
	if err := repository.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	other, _ := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: record.LauncherPath(), LauncherDigest: record.LauncherDigest(), OperationID: record.OperationID(),
		JournalPath: record.JournalPath(), JournalDigest: record.JournalDigest(), ExpiresAt: record.ExpiresAt(),
		Nonce: rebootcontinuation.NonceBytes([]byte("divergent claim nonce")),
	}, now)
	otherRaw, _ := encodeRecord(other)
	if err := os.WriteFile(repository.claimedPath(record.OperationID()), otherRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	token, _ := rebootcontinuation.TokenFor(record.OperationID())
	if _, err := repository.LoadByToken(t.Context(), token); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
		t.Fatalf("divergent token state error = %v", err)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("g", 64), strings.Repeat("A", 64)} {
		if validToken(invalid) {
			t.Fatalf("invalid token %q accepted by predicate", invalid)
		}
		if _, err := repository.LoadByToken(t.Context(), invalid); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
			t.Fatalf("invalid token error = %v", err)
		}
	}
}

func TestPF001ContinuationEntropyValidatesSizeAndContext(t *testing.T) {
	value, err := (Entropy{}).Bytes(t.Context(), 32)
	if err != nil || len(value) != 32 {
		t.Fatalf("Entropy.Bytes() = (%d, %v)", len(value), err)
	}
	for _, size := range []int{-1, 0, 1025} {
		if _, err := (Entropy{}).Bytes(t.Context(), size); !errors.Is(err, rebootapp.ErrRecordIntegrity) {
			t.Fatalf("invalid entropy size %d error = %v", size, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Entropy{}).Bytes(cancelled, 32); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled entropy error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context entropy-boundary regression fixture.
	if _, err := (Entropy{}).Bytes(nil, 32); !errors.Is(err, rebootapp.ErrRecordIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil entropy context error = %v", err)
	}
}

func repositoryRecordFixture(t testing.TB) rebootcontinuation.Record {
	return repositoryRecordFixtureWithID(t, "019f5f23-5678-7def-9123-abcdef012347")
}

func repositoryRecordFixtureWithID(t testing.TB, rawID string) rebootcontinuation.Record {
	t.Helper()
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	operationID, _ := install.NewOperationID(rawID)
	record, err := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: "/opt/Agent Memory/bin/agentmemory", LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID: operationID, JournalPath: "/home/owner/.config/AgentMemory/install-operation.json",
		JournalDigest: install.DigestBytes([]byte("journal")), ExpiresAt: now.Add(rebootcontinuation.MaximumLifetime),
		Nonce: rebootcontinuation.NonceBytes([]byte("nonce " + rawID)),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
