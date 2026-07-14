//go:build darwin || linux

package productfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"golang.org/x/sys/unix"
)

func TestPF001ProductFilesystemRejectsInvalidAndWeakenedNativeBoundaries(t *testing.T) {
	t.Parallel()
	var absent *Ensurer
	if _, err := absent.EnsureDirectories(context.Background(), productinstall.DirectoryCommand{}); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("nil directory ensurer error = %v", err)
	}
	if _, err := absent.EnsureSecrets(context.Background(), productinstall.SecretCommand{}); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("nil secret ensurer error = %v", err)
	}
	if _, err := NewEnsurer().EnsureDirectories(context.Background(), productinstall.DirectoryCommand{}); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("zero directory command error = %v", err)
	}
	if _, err := NewEnsurer().EnsureSecrets(context.Background(), productinstall.SecretCommand{}); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("zero secret command error = %v", err)
	}

	t.Run("weak managed root", func(t *testing.T) {
		root := unixTestRoot(t)
		if err := os.Mkdir(root, 0o755); err != nil { //nolint:gosec // Deliberately weak directory fixture.
			t.Fatal(err)
		}
		_, err := NewEnsurer().EnsureDirectories(context.Background(), unixDirectoryCommand(t, root))
		if !errors.Is(err, productinstall.ErrIntegrity) {
			t.Fatalf("weak root error = %v", err)
		}
	})

	t.Run("writable ancestor", func(t *testing.T) {
		parent, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil { //nolint:gosec // Deliberately unsafe fixture.
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(parent, 0o700) }() //nolint:gosec // Owner-only test cleanup.
		root := filepath.Join(parent, "agentmemory")
		_, err = NewEnsurer().EnsureDirectories(context.Background(), unixDirectoryCommand(t, root))
		if !errors.Is(err, productinstall.ErrIntegrity) {
			t.Fatalf("unsafe ancestor error = %v", err)
		}
	})

	if _, err := commonManagedRoot([]string{"/alpha/private", "/beta/private"}); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("root-only common path error = %v", err)
	}
	for _, relative := range []string{"", ".", "../escape", "/absolute", "a/../escape"} {
		if validRelativeTree(relative) {
			t.Fatalf("invalid relative tree %q was accepted", relative)
		}
	}
}

func TestPF001ProductFilesystemNativeDescriptorEdgesFailClosed(t *testing.T) {
	t.Parallel()
	uid := uint32(os.Geteuid()) //nolint:gosec // Native UID fixture.
	if _, valid := productDeviceIdentity(nil); valid {
		t.Fatal("nil native device identity was accepted")
	}
	if _, err := privateDirectoryIdentity(context.Background(), nil, uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("nil private directory error = %v", err)
	}
	if err := verifyNativeACL(nil); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("nil ACL descriptor error = %v", err)
	}
	if err := syncNativeFile(nil); err == nil {
		t.Fatal("nil durability descriptor was accepted")
	}
	if _, err := openExistingPrivateDirectory(context.Background(), "relative", uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("relative existing directory error = %v", err)
	}

	root := unixTestRoot(t)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := openExistingPrivateDirectory(context.Background(), root, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openExistingPrivateDirectory(cancelled, root, uid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled directory open error = %v", err)
	}
	if _, err := openOrCreateManagedRoot(cancelled, filepath.Join(root, "new"), uid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled directory create error = %v", err)
	}
	if _, _, err := ensurePrivateDescendant(cancelled, directory, "child", uid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled descendant error = %v", err)
	}
	if _, _, err := ensurePrivateDescendant(context.Background(), directory, "", uid); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("empty descendant error = %v", err)
	}
	if _, _, err := ensurePrivateDescendant(context.Background(), directory, "child/grandchild", uid); err != nil {
		t.Fatal(err)
	}
	weak := filepath.Join(root, "weak")
	if err := os.Mkdir(weak, 0o755); err != nil { //nolint:gosec // Deliberately weak directory fixture.
		t.Fatal(err)
	}
	if _, _, err := ensurePrivateDescendant(context.Background(), directory, "weak", uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("weak descendant error = %v", err)
	}
	regularPath := filepath.Join(root, "regular")
	if err := os.WriteFile(regularPath, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular, err := os.Open(regularPath) //nolint:gosec // Path is rooted in this test's private temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySafeAncestor(regular, uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("regular ancestor error = %v", err)
	}
	_ = regular.Close()
	closed, err := os.Open(root) //nolint:gosec // Path is rooted in this test's private temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if _, err := privateDirectoryIdentity(context.Background(), closed, uid); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("closed directory identity error = %v", err)
	}
	if _, _, err := ensurePrivateDescendant(context.Background(), closed, "child", uid); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("closed descendant root error = %v", err)
	}
	if err := syncNativeFile(closed); err == nil {
		t.Fatal("closed durability descriptor was accepted")
	}
	if _, err := openExistingPrivateDirectory(context.Background(), regularPath, uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("regular path as directory error = %v", err)
	}
	if !errors.Is(classifyPathError(unix.ELOOP), productinstall.ErrIntegrity) ||
		!errors.Is(classifyPathError(unix.ENOSPC), productinstall.ErrUnavailable) {
		t.Fatal("native path errors were not classified safely")
	}
}

func TestPF001ProductFilesystemSecretPublicationAndIdentityEdges(t *testing.T) {
	t.Parallel()
	root := unixTestRoot(t)
	ensurer := NewEnsurer()
	if _, err := ensurer.EnsureDirectories(context.Background(), unixDirectoryCommand(t, root)); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid()) //nolint:gosec // Native UID fixture.
	directory, err := openExistingPrivateDirectory(context.Background(), filepath.Join(root, "secrets"), uid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()

	if _, err := readSecretFile(context.Background(), directory, "absent", uid); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent secret error = %v", err)
	}
	target := "existing"
	if err := os.WriteFile(filepath.Join(root, "secrets", target), bytes.Repeat([]byte{0x31}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	published, err := publishSecret(
		context.Background(), directory, ".secret-collision.tmp", target, bytes.Repeat([]byte{0x42}, 32), uid,
	)
	if err != nil || published {
		t.Fatalf("exclusive collision = %v/%v", published, err)
	}
	value, err := readSecretFile(context.Background(), directory, target, uid)
	if err != nil || !bytes.Equal(value, bytes.Repeat([]byte{0x31}, 32)) {
		t.Fatal("exclusive collision replaced an existing secret")
	}
	clear(value)
	badSize := filepath.Join(root, "secrets", "bad-size")
	if err := os.WriteFile(badSize, bytes.Repeat([]byte{0x22}, 31), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(context.Background(), directory, "bad-size", uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("bad-size secret error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readSecretFile(cancelled, directory, target, uid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled secret read error = %v", err)
	}
	if _, err := publishSecret(
		cancelled, directory, ".secret-cancelled.tmp", "cancelled", bytes.Repeat([]byte{0x43}, 32), uid,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled secret publication error = %v", err)
	}
	if _, err := publishSecret(
		context.Background(), directory, ".secret-short.tmp", "short", bytes.Repeat([]byte{0x44}, 31), uid,
	); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("short secret publication error = %v", err)
	}
	closedDirectory, err := os.Open(filepath.Join(root, "secrets")) //nolint:gosec // Test-controlled private root.
	if err != nil {
		t.Fatal(err)
	}
	_ = closedDirectory.Close()
	if _, err := publishSecret(
		context.Background(), closedDirectory, ".secret-closed.tmp", "closed", bytes.Repeat([]byte{0x45}, 32), uid,
	); !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("closed secret directory error = %v", err)
	}
	closedFile, err := os.Open(filepath.Join(root, "secrets", target)) //nolint:gosec // Test-controlled private root.
	if err != nil {
		t.Fatal(err)
	}
	_ = closedFile.Close()
	if err := writeAll(closedFile, []byte("x")); err == nil {
		t.Fatal("writeAll accepted a closed descriptor")
	}

	hardlink := filepath.Join(root, "secrets", "hardlink")
	if err := os.Link(filepath.Join(root, "secrets", target), hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(context.Background(), directory, target, uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("multiply linked secret error = %v", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "secrets", target), filepath.Join(root, "secrets", "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(context.Background(), directory, "linked", uid); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("linked secret error = %v", err)
	}

	command := unixSecretCommand(t, root)
	values := make([][]byte, 7)
	for index := range values {
		values[index] = bytes.Repeat([]byte{byte(index + 1)}, 32)
	}
	defer func() {
		for _, secret := range values {
			clear(secret)
		}
	}()
	if _, err := digestSecretState(command, command.Secrets(), values[:6]); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("short state set error = %v", err)
	}
	installationRootIndex := 4
	values[installationRootIndex] = values[installationRootIndex][:31]
	if _, err := digestSecretState(command, command.Secrets(), values); !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("short installation root key error = %v", err)
	}
}
