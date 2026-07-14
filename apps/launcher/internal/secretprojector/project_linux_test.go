//go:build linux

package secretprojector

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPF001LinuxProjectionRunsClosedContractAndIsReplaySafe(t *testing.T) {
	inputRoot := t.TempDir()
	outputRoot := t.TempDir()
	metadataRoot := t.TempDir()
	uid := uint32(os.Getuid()) // #nosec G115 -- Linux UIDs are nonnegative uint32 values.
	gid := uint32(os.Getgid()) // #nosec G115 -- Linux GIDs are nonnegative uint32 values.
	file := fileContract{name: "installation-key", userID: uid, groupID: gid, maxBytes: exactCryptographicSecretBytes}
	contract := []volumeContract{{purpose: "core", files: []fileContract{file}}}
	value := bytes.Repeat([]byte{0x5a}, int(exactCryptographicSecretBytes))
	input := filepath.Join(inputRoot, file.name)
	if err := os.WriteFile(input, value, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(input, 0o400); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputRoot, contract[0].purpose)
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(metadataRoot, "metadata")
	if err := os.WriteFile(metadata, []byte("fixed-process-metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolveInput := func(name string) string { return filepath.Join(inputRoot, name) }
	resolveOutput := func(purpose string) string { return filepath.Join(outputRoot, purpose) }
	for attempt := 0; attempt < 2; attempt++ {
		if err := runProjection(contract, resolveInput, resolveOutput, []string{metadata}); err != nil {
			t.Fatalf("projection attempt %d: %v", attempt+1, err)
		}
	}
	projected := filepath.Join(output, file.name)
	contents, err := os.ReadFile(projected) //nolint:gosec // G304: projected is a test-owned path under t.TempDir.
	if err != nil || !bytes.Equal(contents, value) {
		t.Fatalf("projected contents = %x, %v", contents, err)
	}
	info, err := os.Lstat(projected)
	if err != nil || info.Mode().Perm() != os.FileMode(projectedMode) {
		t.Fatalf("projected mode = %v, %v", info, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 {
		t.Fatalf("projected identity = %#v", stat)
	}
	if err := os.WriteFile(metadata, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runProjection(contract, resolveInput, resolveOutput, []string{metadata}); !errors.Is(err, errProjectionMetadata) {
		t.Fatalf("secret-bearing process metadata error = %v", err)
	}
}

func TestPF001LinuxProjectionHelpersFailClosed(t *testing.T) {
	if RunDefault() == nil {
		t.Fatal("bare test host unexpectedly satisfied the closed production projection contract")
	}
	if runProjection(nil, nil, nil, nil) == nil || exactEffectiveCapabilities() && os.Geteuid() != 0 {
		t.Fatal("invalid projection runtime or capability state was accepted")
	}
	_ = networkNamespaceIsDisabled()
	if !networkNamespaceRoutesDisabled([]byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"), nil) ||
		networkNamespaceRoutesDisabled([]byte("Iface\neth0\n"), nil) ||
		networkNamespaceRoutesDisabled([]byte("Iface\n"), []byte("0 0 0 0 0 0 0 0 0 eth0\n")) {
		t.Fatal("network namespace route policy drifted")
	}
	projected := false
	project := func() error { projected = true; return nil }
	if !errors.Is(runDefault(1, true, true, project), errProjectionCapabilities) ||
		!errors.Is(runDefault(0, false, true, project), errProjectionCapabilities) ||
		!errors.Is(runDefault(0, true, false, project), errProjectionNetwork) ||
		!errors.Is(runDefault(0, true, true, nil), errProjection) || runDefault(0, true, true, project) != nil || !projected {
		t.Fatal("default projection preconditions drifted")
	}
	if !allZero(make([]byte, 32)) || allZero([]byte{0, 1}) {
		t.Fatal("zero-secret detector drifted")
	}
	if _, err := readExactAt(-1, 0); !errors.Is(err, errProjection) {
		t.Fatalf("invalid exact read error = %v", err)
	}
	if err := writeAll(-1, []byte("value")); !errors.Is(err, errProjection) {
		t.Fatalf("invalid exact write error = %v", err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "value")
	value := []byte("bounded-value")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(descriptor) }()
	observed, err := readExactAt(descriptor, len(value))
	if err != nil || !bytes.Equal(observed, value) {
		t.Fatalf("exact read = %q, %v", observed, err)
	}
	before, err := regularFileState(descriptor)
	if err != nil || !sameFileState(before, before) {
		t.Fatalf("regular file state = %#v, %v", before, err)
	}
	if _, err := regularFileState(-1); !errors.Is(err, errProjection) {
		t.Fatalf("invalid descriptor state error = %v", err)
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(directoryFD) }()
	if err := exactDirectoryEntries(directoryFD, map[string]struct{}{"value": {}}, false); err != nil {
		t.Fatal(err)
	}
	if err := exactDirectoryEntries(directoryFD, map[string]struct{}{}, false); !errors.Is(err, errProjection) {
		t.Fatalf("unexpected directory entry error = %v", err)
	}
	temporary := temporaryName("value")
	if err := os.Rename(path, filepath.Join(directory, temporary)); err != nil {
		t.Fatal(err)
	}
	if err := exactDirectoryEntries(directoryFD, map[string]struct{}{"value": {}}, true); err != nil {
		t.Fatalf("allowed temporary entry error = %v", err)
	}
	if err := os.Rename(filepath.Join(directory, temporary), path); err != nil {
		t.Fatal(err)
	}
	protected := protectedValue{bytes: value, digest: sha256.Sum256(value)}
	if err := verifyProjectedFile(directoryFD, fileContract{
		name: "value", userID: before.Uid, groupID: before.Gid, maxBytes: uint64(len(value)),
	}, protected); !errors.Is(err, errProjection) {
		t.Fatalf("wrong-mode projected file error = %v", err)
	}
	if err := projectVolume(volumeContract{purpose: "missing"}, nil, filepath.Join(directory, "missing")); !errors.Is(err, errProjectionVolumeOpen) {
		t.Fatalf("missing volume error = %v", err)
	}
	if err := projectVolume(volumeContract{
		purpose: "existing", files: []fileContract{{name: "absent", userID: before.Uid, groupID: before.Gid, maxBytes: 32}},
	}, nil, directory); !errors.Is(err, errProjectionVolumeList) && !errors.Is(err, errProjectionVolumeWrite) {
		t.Fatalf("missing protected value error = %v", err)
	}
	if _, err := readProtectedInput(fileContract{name: "missing", maxBytes: 32}, filepath.Join(directory, "missing")); !errors.Is(err, errProjection) {
		t.Fatalf("missing protected input error = %v", err)
	}
	if _, err := readProtectedInput(fileContract{name: "value", maxBytes: uint64(len(value))}, path); !errors.Is(err, errProjection) {
		t.Fatalf("writable protected input error = %v", err)
	}
	if !processMetadataContains(map[string]protectedValue{}, []string{filepath.Join(directory, "missing")}) {
		t.Fatal("missing process metadata was accepted")
	}
}
