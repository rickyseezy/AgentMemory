//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativePrivilegeProtectedWriterPublishesExactRootEquivalentFilesIdempotently(t *testing.T) {
	t.Parallel()
	uid, gid := privilegeWriterTestOwner(t)
	root := t.TempDir()
	transactions := filepath.Join(root, "transactions")
	destination := filepath.Join(root, "configuration")
	if err := os.Mkdir(transactions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o755); err != nil { // #nosec G301 -- mirrors production root-owned repository directory mode.
		t.Fatal(err)
	}
	writer, err := newNativePrivilegeProtectedFileWriter(
		[]string{destination}, transactions, uid, gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(destination, "agentmemory.sources")
	configuration := []byte("signed configuration\n")
	if !writer.authorizesDestination(configurationPath) {
		t.Fatal("test destination was not authorized")
	}
	if err := ensurePrivilegeProtectedDirectory(destination, uid, gid); err != nil {
		t.Fatalf("test destination directory rejected: %v", err)
	}
	changed, err := writer.EnsurePrivilegeFile(t.Context(), configurationPath, configuration, 0o644)
	if err != nil || !changed {
		t.Fatalf("configuration changed=%t error=%v", changed, err)
	}
	changed, err = writer.EnsurePrivilegeFile(t.Context(), configurationPath, configuration, 0o644)
	if err != nil || changed {
		t.Fatalf("configuration replay changed=%t error=%v", changed, err)
	}

	transaction := filepath.Join(transactions, runtimeinstall.Sum([]byte("request")).String())
	if err := os.Mkdir(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	key := []byte("signed repository key")
	keySource := filepath.Join(transaction, "repository-key")
	if err := os.WriteFile(keySource, key, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := PrivilegeTransactionArtifact{
		artifactID: "repo-docker-stable-signing_key", targetPath: keySource,
		sha256: runtimeinstall.Sum(key), size: uint64(len(key)),
	}
	keyPath := filepath.Join(destination, "agentmemory.gpg")
	changed, err = writer.EnsurePrivilegeArtifactFile(t.Context(), keyPath, artifact, 0o644)
	if err != nil || !changed {
		t.Fatalf("key changed=%t error=%v", changed, err)
	}
	changed, err = writer.EnsurePrivilegeArtifactFile(t.Context(), keyPath, artifact, 0o644)
	if err != nil || changed {
		t.Fatalf("key replay changed=%t error=%v", changed, err)
	}
	if raw, readError := os.ReadFile(keyPath); readError != nil || string(raw) != string(key) { // #nosec G304 -- path is test-owned.
		t.Fatalf("published key=%q error=%v", raw, readError)
	}
}

func TestPF006NativePrivilegeProtectedWriterRejectsSymlinksForeignRootsAndDigestMismatch(t *testing.T) {
	t.Parallel()
	uid, gid := privilegeWriterTestOwner(t)
	root := t.TempDir()
	transactions := filepath.Join(root, "transactions")
	destination := filepath.Join(root, "configuration")
	if err := os.Mkdir(transactions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o755); err != nil { // #nosec G301 -- mirrors production root-owned repository directory mode.
		t.Fatal(err)
	}
	writer, err := newNativePrivilegeProtectedFileWriter([]string{destination}, transactions, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign")
	if changed, writeError := writer.EnsurePrivilegeFile(
		t.Context(), filepath.Join(foreign, "file"), []byte("content"), 0o644,
	); !errors.Is(writeError, runtimeport.ErrPrivilegeIntegrity) || changed {
		t.Fatalf("foreign changed=%t error=%v", changed, writeError)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(destination, "agentmemory.sources")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if changed, writeError := writer.EnsurePrivilegeFile(
		t.Context(), symlink, []byte("content"), 0o644,
	); !errors.Is(writeError, runtimeport.ErrPrivilegeIntegrity) || changed {
		t.Fatalf("symlink changed=%t error=%v", changed, writeError)
	}
	transaction := filepath.Join(transactions, runtimeinstall.Sum([]byte("request")).String())
	if err := os.Mkdir(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(transaction, "key")
	if err := os.WriteFile(source, []byte("actual"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := PrivilegeTransactionArtifact{
		artifactID: "repo-docker-stable-signing_key", targetPath: source,
		sha256: runtimeinstall.Sum([]byte("foreign")), size: uint64(len("actual")),
	}
	if changed, writeError := writer.EnsurePrivilegeArtifactFile(
		t.Context(), filepath.Join(destination, "key.gpg"), artifact, 0o644,
	); !errors.Is(writeError, runtimeport.ErrPrivilegeIntegrity) || changed {
		t.Fatalf("digest substitution changed=%t error=%v", changed, writeError)
	}
	if writer, err := newNativePrivilegeProtectedFileWriter(nil, transactions, uid, gid); writer != nil || err == nil {
		t.Fatal("missing destination roots accepted")
	}
	if writer, err := newNativePrivilegeProtectedFileWriter([]string{destination}, "relative", uid, gid); writer != nil || err == nil {
		t.Fatal("relative transaction root accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if changed, writeError := writer.EnsurePrivilegeFile(
		cancelled, filepath.Join(destination, "cancelled"), []byte("content"), 0o644,
	); !errors.Is(writeError, context.Canceled) || changed {
		t.Fatalf("cancelled changed=%t error=%v", changed, writeError)
	}
}

func privilegeWriterTestOwner(t testing.TB) (uint32, uint32) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 || gid < 0 || uint64(uid) > math.MaxUint32 || uint64(gid) > math.MaxUint32 {
		t.Fatal("test owner is out of range")
	}
	return uint32(uid), uint32(gid) // #nosec G115 -- ranges are proven above.
}
