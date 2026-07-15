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
	if err := os.WriteFile(launcherPath, launcherBytes, 0o700); err != nil { // #nosec G306 -- executable-mode fixture verifies launcher admission.
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, journalBytes, 0o600); err != nil {
		t.Fatal(err)
	}
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
	_ = os.WriteFile(launcherPath, []byte("launcher"), 0o700) // #nosec G306 -- executable-mode rejection fixture.
	_ = os.WriteFile(journalPath, []byte("journal"), 0o600)
	verifier, _ := newNativeObjectVerifier(func() (string, error) { return launcherPath, nil })
	//lint:ignore SA1012 Deliberate nil-context trust-boundary regression fixture.
	if _, err := verifier.VerifyJournal(nil, journalPath); !errors.Is(err, rebootapp.ErrIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := verifier.VerifyJournal(t.Context(), "relative"); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("relative journal error = %v", err)
	}
	if err := os.Chmod(journalPath, 0o644); err != nil { // #nosec G302 -- deliberately unsafe permission rejection fixture.
		t.Fatal(err)
	}
	if _, err := verifier.VerifyJournal(t.Context(), journalPath); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("unsafe journal mode error = %v", err)
	}
	if err := os.Chmod(launcherPath, 0o722); err != nil { // #nosec G302 -- deliberately writable executable rejection fixture.
		t.Fatal(err)
	}
	if _, err := verifier.VerifyLauncher(t.Context()); !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("writable launcher error = %v", err)
	}
	_ = os.Chmod(journalPath, 0o600)
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
