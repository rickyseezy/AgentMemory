package rebootlogin

import (
	"context"
	"encoding/base64"
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

func TestPF001NativeLoginEntriesUseSafeTokenizedArgvWithoutResumeSecrets(t *testing.T) {
	record := loginRecordFixture(t)
	token, _ := rebootcontinuation.TokenFor(record.OperationID())
	nonceText := base64.RawURLEncoding.EncodeToString(record.Nonce().Bytes())
	for name, render := range map[string]func(rebootcontinuation.Record) (entry, error){
		"darwin":  renderDarwinEntry,
		"linux":   renderLinuxEntry,
		"windows": renderWindowsEntry,
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := render(record)
			if err != nil {
				t.Fatal(err)
			}
			if actual.name == "" || !strings.Contains(actual.content, token) ||
				strings.Contains(actual.content, record.OperationID().String()) ||
				strings.Contains(actual.content, record.JournalDigest().String()) ||
				strings.Contains(actual.content, nonceText) {
				t.Fatalf("%s entry leaked authority or omitted safe token: %+v", name, actual)
			}
			if !strings.Contains(actual.content, record.LauncherPath()) && name != "darwin" {
				t.Fatalf("%s entry omitted exact launcher path", name)
			}
		})
	}
	darwin, _ := renderDarwinEntry(record)
	if strings.Contains(darwin.content, "&trusted") || !strings.Contains(darwin.content, "&amp;trusted") {
		t.Fatal("darwin plist did not XML-escape the launcher path")
	}
	linux, _ := renderLinuxEntry(record)
	if !strings.Contains(linux.content, `Exec="/opt/Agent Memory/bin/agentmemory&trusted" resume --continuation `) {
		t.Fatalf("linux desktop Exec was not argv quoted: %q", linux.content)
	}
}

func TestPF001FileLoginRegistrarPublishesIdempotentlyAndRemoves(t *testing.T) {
	root := filepath.Join(t.TempDir(), "login")
	registrar, err := newFileRegistrar(root, ".desktop", renderLinuxEntry)
	if err != nil {
		t.Fatal(err)
	}
	record := loginRecordFixture(t)
	if err := registrar.Register(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := registrar.Register(t.Context(), record); err != nil {
		t.Fatalf("same registration was not idempotent: %v", err)
	}
	path := registrar.path(record.OperationID())
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("entry metadata = (%v, %v)", info, err)
	}
	if err := registrar.Remove(t.Context(), record.OperationID()); err != nil {
		t.Fatal(err)
	}
	if err := registrar.Remove(t.Context(), record.OperationID()); err != nil {
		t.Fatalf("remove was not idempotent: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry survived removal: %v", err)
	}
}

func TestPF001FileLoginRegistrarRejectsReplacementAndUnsafeRoots(t *testing.T) {
	for _, root := range []string{"", "relative", t.TempDir() + string(filepath.Separator) + ".."} {
		if registrar, err := newFileRegistrar(root, ".plist", renderDarwinEntry); registrar != nil ||
			!errors.Is(err, rebootapp.ErrIntegrity) {
			t.Fatalf("newFileRegistrar(%q) = (%v, %v)", root, registrar, err)
		}
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	_ = os.Mkdir(target, 0o700)
	link := filepath.Join(parent, "link")
	_ = os.Symlink(target, link)
	if registrar, err := newFileRegistrar(link, ".desktop", renderLinuxEntry); registrar != nil ||
		!errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("symlink registrar root accepted: (%v, %v)", registrar, err)
	}

	registrar, _ := newFileRegistrar(filepath.Join(parent, "safe"), ".desktop", renderLinuxEntry)
	record := loginRecordFixture(t)
	if err := registrar.Register(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registrar.path(record.OperationID()), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registrar.Register(t.Context(), record); !errors.Is(err, rebootapp.ErrConflict) {
		t.Fatalf("foreign replacement error = %v", err)
	}
}

func TestPF001LoginEntryRenderersAndRegistrarRejectInvalidBoundaries(t *testing.T) {
	for name, render := range map[string]func(rebootcontinuation.Record) (entry, error){
		"darwin": renderDarwinEntry, "linux": renderLinuxEntry, "windows": renderWindowsEntry,
	} {
		if _, err := render(rebootcontinuation.Record{}); !errors.Is(err, rebootapp.ErrIntegrity) {
			t.Fatalf("%s zero record error = %v", name, err)
		}
	}
	record := loginRecordFixture(t)
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	longPathRecord, _ := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: "/" + strings.Repeat("a", 250), LauncherDigest: record.LauncherDigest(),
		OperationID: record.OperationID(), JournalPath: record.JournalPath(), JournalDigest: record.JournalDigest(),
		ExpiresAt: record.ExpiresAt(), Nonce: record.Nonce(),
	}, now)
	if _, err := renderWindowsEntry(longPathRecord); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("overlong Windows command error = %v", err)
	}

	registrar, _ := newFileRegistrar(filepath.Join(t.TempDir(), "login"), ".desktop", renderLinuxEntry)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registrar.Register(cancelled, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled register error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context registrar-boundary regression fixture.
	if err := registrar.Register(nil, record); !errors.Is(err, rebootapp.ErrIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil register error = %v", err)
	}
	if err := registrar.Remove(t.Context(), install.OperationID{}); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("zero remove error = %v", err)
	}
	if err := registrar.Remove(cancelled, record.OperationID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled remove error = %v", err)
	}
	var absent *fileRegistrar
	if err := absent.Register(t.Context(), record); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil registrar error = %v", err)
	}
}

func TestPF001FileLoginRegistrarRejectsUnsafeExistingEntryAndRemovalFailure(t *testing.T) {
	registrar, _ := newFileRegistrar(filepath.Join(t.TempDir(), "login"), ".desktop", renderLinuxEntry)
	record := loginRecordFixture(t)
	if err := registrar.Register(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(registrar.path(record.OperationID()), 0o644); err != nil { // #nosec G302 -- deliberately unsafe login-entry rejection fixture.
		t.Fatal(err)
	}
	if err := registrar.Register(t.Context(), record); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("unsafe entry error = %v", err)
	}
	if err := os.Remove(registrar.path(record.OperationID())); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(registrar.path(record.OperationID()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(registrar.path(record.OperationID()), "child"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registrar.Remove(t.Context(), record.OperationID()); !errors.Is(err, rebootapp.ErrUnavailable) {
		t.Fatalf("unremovable entry error = %v", err)
	}
}

func loginRecordFixture(t testing.TB) rebootcontinuation.Record {
	t.Helper()
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	record, err := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: "/opt/Agent Memory/bin/agentmemory&trusted", LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID: operationID, JournalPath: "/home/owner/.config/AgentMemory/install-operation.json",
		JournalDigest: install.DigestBytes([]byte("journal")), ExpiresAt: now.Add(rebootcontinuation.MaximumLifetime),
		Nonce: rebootcontinuation.NonceBytes([]byte("nonce must never enter login registration")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
