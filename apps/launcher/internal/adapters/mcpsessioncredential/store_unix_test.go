//go:build darwin || linux

package mcpsessioncredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPF005CredentialFileStorePublishesReadOnlyAndDeletesExactDigest(t *testing.T) {
	t.Parallel()
	root := filepath.Join(canonicalTemporaryDirectory(t), "credentials")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x73}, credentialBytes)
	path, err := store.Write(t.Context(), credentialScope().SessionID, secret)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 || info.Size() != credentialBytes {
		t.Fatalf("credential info=%#v error=%v", info, err)
	}
	digestBytes := sha256.Sum256(secret)
	digest := hex.EncodeToString(digestBytes[:])
	if err := store.Delete(t.Context(), path, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("deleted path error=%v", err)
	}
	if err := store.Delete(t.Context(), path, digest); err != nil {
		t.Fatalf("idempotent Delete() error=%v", err)
	}
}

func TestPF005CredentialFileStoreRejectsUnsafeRootPathAndSubstitution(t *testing.T) {
	t.Parallel()
	if _, err := NewFileStore("relative"); err == nil {
		t.Fatal("NewFileStore(relative) error=nil")
	}
	root := filepath.Join(canonicalTemporaryDirectory(t), "credentials")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, _ := NewFileStore(root)
	secret := bytes.Repeat([]byte{1}, credentialBytes)
	path, err := store.Write(t.Context(), credentialScope().SessionID, secret)
	if err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("wrong"))
	if err := store.Delete(t.Context(), path, hex.EncodeToString(wrong[:])); err == nil {
		t.Fatal("Delete(wrong digest) error=nil")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("wrong digest removed credential: %v", err)
	}
	if err := os.Chmod(root, 0o755); err != nil { //nolint:gosec // Deliberately weaken permissions to prove rejection.
		t.Fatal(err)
	}
	if _, err := store.Write(context.Background(), "019d2b4e-7a10-7def-8abc-0123456789ac", secret); err == nil {
		t.Fatal("Write(unsafe root) error=nil")
	}

	base := canonicalTemporaryDirectory(t)
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(realParent, "credentials")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	linked, err := NewFileStore(filepath.Join(alias, "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linked.Write(
		t.Context(), "019d2b4e-7a10-7def-8abc-0123456789ac", secret,
	); err == nil {
		t.Fatal("ancestor symlink reached credential publication")
	}
}

func TestPF005CredentialFileStoreRejectsInvalidCallsBeforeFilesystemAccess(t *testing.T) {
	t.Parallel()
	root := filepath.Join(canonicalTemporaryDirectory(t), "credentials")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{1}, credentialBytes)
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if _, err := store.Write(nil, credentialScope().SessionID, secret); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("Write(nil context) error=nil")
	}
	if _, err := store.Write(t.Context(), "invalid", secret); err == nil {
		t.Fatal("Write(invalid session) error=nil")
	}
	if _, err := store.Write(t.Context(), credentialScope().SessionID, secret[:1]); err == nil {
		t.Fatal("Write(short secret) error=nil")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Write(ctx, credentialScope().SessionID, secret); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write(cancelled)=%v", err)
	}
	path := filepath.Join(root, credentialScope().SessionID+".credential")
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if err := store.Delete(nil, path, strings.Repeat("a", 64)); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("Delete(nil context) error=nil")
	}
	if err := store.Delete(t.Context(), filepath.Join(filepath.Dir(root), "foreign"), strings.Repeat("a", 64)); err == nil {
		t.Fatal("Delete(foreign path) error=nil")
	}
	if err := store.Delete(t.Context(), path, "invalid"); err == nil {
		t.Fatal("Delete(invalid digest) error=nil")
	}
	if err := store.Delete(ctx, path, strings.Repeat("a", 64)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete(cancelled)=%v", err)
	}
	if validStorePath(root, path+"/../foreign") || canonicalUUID(strings.ToUpper(credentialScope().SessionID)) ||
		canonicalUUID("019d2b4e7a107def8abc0123456789abxxxx") ||
		mcpsessionDigest(strings.Repeat("a", 63)) || mcpsessionDigest(strings.Repeat("g", 64)) {
		t.Fatal("invalid store identity accepted")
	}
}

func canonicalTemporaryDirectory(t testing.TB) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
