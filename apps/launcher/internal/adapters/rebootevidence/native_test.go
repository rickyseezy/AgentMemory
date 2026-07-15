package rebootevidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NativeObjectVerifierHashesOwnerControlledLauncherAndJournal(t *testing.T) {
	root := t.TempDir()
	launcherPath := filepath.Join(root, "Agent Memory")
	journalPath := filepath.Join(root, "install-operation.json")
	launcherBytes := []byte("signed launcher bytes")
	journalBytes := []byte("authenticated journal bytes")
	writeNativeObjectFixture(t, launcherPath, launcherBytes, true)
	writeNativeObjectFixture(t, journalPath, journalBytes, false)
	verifier, err := newNativeObjectVerifier(func() (string, error) { return launcherPath, nil })
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := verifier.VerifyLauncher(t.Context())
	resolvedLauncher, _ := filepath.EvalSymlinks(launcherPath)
	if err != nil || launcher.Path != resolvedLauncher || !launcher.Digest.Equal(install.DigestBytes(launcherBytes)) {
		t.Fatalf("VerifyLauncher() = (%+v, %v)", launcher, err)
	}
	journal, err := verifier.VerifyJournal(t.Context(), journalPath)
	if err != nil || journal.Path != journalPath || !journal.Digest.Equal(install.DigestBytes(journalBytes)) {
		t.Fatalf("VerifyJournal() = (%+v, %v)", journal, err)
	}
}

func TestPF001NativeObjectVerifierRejectsSymlinksPermissionsAndInvalidCalls(t *testing.T) {
	root := t.TempDir()
	launcherPath := filepath.Join(root, "launcher")
	journalPath := filepath.Join(root, "journal")
	writeNativeObjectFixture(t, launcherPath, []byte("launcher"), true)
	writeNativeObjectFixture(t, journalPath, []byte("journal"), false)
	verifier, _ := newNativeObjectVerifier(func() (string, error) { return launcherPath, nil })
	//lint:ignore SA1012 Deliberate nil-context trust-boundary regression fixture.
	if _, err := verifier.VerifyJournal(nil, journalPath); !errors.Is(err, rebootapp.ErrIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := verifier.VerifyJournal(t.Context(), "relative"); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("relative journal error = %v", err)
	}
	makeNativeObjectUnsafe(t, journalPath)
	if _, err := verifier.VerifyJournal(t.Context(), journalPath); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("unsafe journal mode error = %v", err)
	}
	makeNativeObjectUnsafe(t, launcherPath)
	if _, err := verifier.VerifyLauncher(t.Context()); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("writable launcher error = %v", err)
	}
	restoreNativeObjectFixture(t, journalPath, []byte("journal"), false)
	link := filepath.Join(root, "journal-link")
	_ = os.Symlink(journalPath, link)
	if _, err := verifier.VerifyJournal(t.Context(), link); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("journal symlink error = %v", err)
	}
}

func TestPF001NativeObjectVerifierMapsExecutableAndContextFailures(t *testing.T) {
	if verifier, err := newNativeObjectVerifier(nil); verifier != nil || !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil executable resolver = (%v, %v)", verifier, err)
	}
	verifier, _ := newNativeObjectVerifier(func() (string, error) { return "", errors.New("private") })
	if _, err := verifier.VerifyLauncher(t.Context()); !errors.Is(err, rebootapp.ErrUnavailable) {
		t.Fatalf("executable resolver error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyLauncher(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled launcher error = %v", err)
	}
	var absent *NativeObjectVerifier
	if _, err := absent.VerifyLauncher(t.Context()); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil verifier error = %v", err)
	}
}
