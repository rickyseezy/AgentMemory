//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
)

func TestPF001LinuxOwnerBindingRejectsSymlinkPermissionsAndMalformedMachineID(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	validPath := filepath.Join(root, "machine-id")
	//nolint:gosec // G306: read-only system-file fixture intentionally mirrors /etc/machine-id; owner=security expiry=2027-07-13.
	if err := os.WriteFile(validPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(validPath)
	if err != nil {
		t.Fatal(err)
	}
	status := info.Sys().(*syscall.Stat_t)
	source := newLinuxOwnerBindingSource(validPath, status.Uid, os.Geteuid)
	if binding, err := source.Current(context.Background()); err != nil || binding.IsZero() {
		t.Fatalf("valid owner binding = %#v, %v", binding, err)
	}

	symlinkPath := filepath.Join(root, "machine-id-link")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	unsafePaths := make([]string, 0, 5)
	unsafePaths = append(unsafePaths, symlinkPath)
	writablePath := filepath.Join(root, "machine-id-writable")
	//nolint:gosec // G306: deliberately unsafe permission fixture verifies fail-closed behavior; owner=security expiry=2027-07-13.
	if err := os.WriteFile(writablePath, []byte("0123456789abcdef0123456789abcdef\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G302: deliberately unsafe permission fixture verifies fail-closed behavior; owner=security expiry=2027-07-13.
	if err := os.Chmod(writablePath, 0o666); err != nil {
		t.Fatal(err)
	}
	unsafePaths = append(unsafePaths, writablePath)
	malformedPath := filepath.Join(root, "machine-id-malformed")
	//nolint:gosec // G306: read-only malformed system-file fixture; owner=security expiry=2027-07-13.
	if err := os.WriteFile(malformedPath, []byte("not-a-machine-id\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	unsafePaths = append(unsafePaths, malformedPath)
	for index, contents := range [][]byte{
		[]byte(" 0123456789abcdef0123456789abcdef\n"),
		[]byte("0123456789abcdef0123456789abcdef\n\n"),
	} {
		path := filepath.Join(root, "machine-id-noncanonical-"+strconv.Itoa(index))
		//nolint:gosec // G306: read-only malformed system-file fixture; owner=security expiry=2027-07-13.
		if err := os.WriteFile(path, contents, 0o444); err != nil {
			t.Fatal(err)
		}
		unsafePaths = append(unsafePaths, path)
	}
	for _, path := range unsafePaths {
		pathInfo, statError := os.Lstat(path)
		if statError != nil {
			t.Fatal(statError)
		}
		pathStatus := pathInfo.Sys().(*syscall.Stat_t)
		candidate := newLinuxOwnerBindingSource(path, pathStatus.Uid, os.Geteuid)
		if _, err := candidate.Current(context.Background()); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("unsafe machine identity %q error = %v", path, err)
		}
	}
}

func TestPF001CanonicalLinuxMachineIDAcceptsOnlyExactSystemdEncoding(t *testing.T) {
	t.Parallel()
	for _, input := range [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("0123456789abcdef0123456789abcdef\n"),
	} {
		if value, ok := canonicalLinuxMachineID(input); !ok || value != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("canonical machine ID = %q, %v", value, ok)
		}
	}
	for _, input := range [][]byte{
		nil,
		[]byte("0123456789abcdef0123456789abcdef\r"),
		[]byte("0123456789ABCDEF0123456789ABCDEF"),
	} {
		if _, ok := canonicalLinuxMachineID(input); ok {
			t.Fatalf("noncanonical machine ID accepted: %q", input)
		}
	}
}
