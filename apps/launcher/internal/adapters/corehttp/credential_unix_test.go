//go:build darwin || linux

package corehttp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPF001NativeCredentialSourceRequiresPrivateStableExact32ByteFile(t *testing.T) {
	t.Parallel()
	if _, valid := credentialDeviceIdentity(nil); valid {
		t.Fatal("nil credential device identity was accepted")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".agentmemory-corehttp-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- credential parent must be owner-only.
		t.Fatal(err)
	}
	credentialPath := filepath.Join(root, "api-credential")
	want := []byte("01234567890123456789012345678901")
	if err := os.WriteFile(credentialPath, want, 0o400); err != nil {
		t.Fatal(err)
	}
	source := NewNativeCredentialSource()
	actual, err := source.ReadCredential(context.Background(), credentialPath)
	if err != nil || string(actual) != string(want) {
		t.Fatalf("ReadCredential() = %x/%v", actual, err)
	}
	clear(actual)

	if err := os.Chmod(credentialPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReadCredential(context.Background(), credentialPath); !errors.Is(err, errCredentialIntegrity) {
		t.Fatalf("unsafe mode error = %v", err)
	}
}

func TestPF001NativeCredentialSourceRejectsLinksUnsafeParentAndCancellation(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	root, err := os.MkdirTemp(home, ".agentmemory-corehttp-edge-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- credential parent must be owner-only.
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("01234567890123456789012345678901"), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, readError := NewNativeCredentialSource().ReadCredential(context.Background(), link); readError == nil {
			t.Fatal("credential source followed a symlink")
		}
	}
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(target, hardlink); err == nil {
		if _, readError := NewNativeCredentialSource().ReadCredential(context.Background(), target); !errors.Is(readError, errCredentialIntegrity) {
			t.Fatalf("hard-linked credential error = %v", readError)
		}
		if err := os.Remove(hardlink); err != nil {
			t.Fatal(err)
		}
	}
	oversized := filepath.Join(root, "oversized")
	if err := os.WriteFile(oversized, []byte("012345678901234567890123456789012"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNativeCredentialSource().ReadCredential(context.Background(), oversized); !errors.Is(err, errCredentialIntegrity) {
		t.Fatalf("oversized credential error = %v", err)
	}
	if _, err := NewNativeCredentialSource().ReadCredential(context.Background(), "relative"); !errors.Is(err, errCredentialIntegrity) {
		t.Fatalf("relative credential error = %v", err)
	}
	if _, err := NewNativeCredentialSource().ReadCredential(context.Background(), filepath.Join(root, "missing")); !errors.Is(err, errCredentialUnavailable) {
		t.Fatalf("missing credential error = %v", err)
	}
	if err := os.Chmod(root, 0o755); err != nil { // #nosec G302 -- intentionally creates an unsafe parent for rejection testing.
		t.Fatal(err)
	}
	if _, err := NewNativeCredentialSource().ReadCredential(context.Background(), target); err == nil {
		t.Fatal("credential source accepted a non-private final parent")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewNativeCredentialSource().ReadCredential(cancelled, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if _, err := (*NativeCredentialSource)(nil).ReadCredential(context.Background(), target); err == nil {
		t.Fatal("nil source returned credential bytes")
	}
	var nilContext context.Context
	if _, err := readNativeCredential(nilContext, target); !errors.Is(err, errCredentialIntegrity) {
		t.Fatalf("nil context error = %v", err)
	}
}
