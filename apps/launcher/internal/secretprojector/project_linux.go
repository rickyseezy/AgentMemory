//go:build linux

package secretprojector

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	capabilityCHOWN         = uint64(1 << 0)
	capabilityDACReadSearch = uint64(1 << 2)
	maximumStatusBytes      = 64 * 1024
)

var (
	errProjection             = errors.New("protected projection failed")
	errProjectionCapabilities = errors.New("protected projection failed: capability-contract")
	errProjectionNetwork      = errors.New("protected projection failed: network-contract")
	errProjectionInput        = errors.New("protected projection failed: input-contract")
	errProjectionMetadata     = errors.New("protected projection failed: process-metadata-contract")
	errProjectionVolumeOpen   = errors.New("protected projection failed: volume-open-contract")
	errProjectionVolumeList   = errors.New("protected projection failed: volume-inventory-contract")
	errProjectionVolumeWrite  = errors.New("protected projection failed: volume-write-contract")
	errProjectionVolumeVerify = errors.New("protected projection failed: volume-verify-contract")
	errProjectionCreate       = errors.New("protected projection failed: volume-create-contract")
	errProjectionContent      = errors.New("protected projection failed: volume-content-contract")
	errProjectionOwner        = errors.New("protected projection failed: volume-owner-contract")
	errProjectionMode         = errors.New("protected projection failed: volume-mode-contract")
	errProjectionSync         = errors.New("protected projection failed: volume-sync-contract")
	errProjectionStateOwner   = errors.New("protected projection failed: volume-state-owner-contract")
	errProjectionStateMode    = errors.New("protected projection failed: volume-state-mode-contract")
	errProjectionStateLink    = errors.New("protected projection failed: volume-state-link-contract")
	errProjectionPublish      = errors.New("protected projection failed: volume-publish-contract")
)

type protectedValue struct {
	bytes  []byte
	digest [sha256.Size]byte
}

// RunDefault executes the complete fixed projection and returns no secret-
// derived receipt. The command wrapper emits only the constant token "ok".
func RunDefault() error {
	if unix.Geteuid() != 0 || !exactEffectiveCapabilities() {
		return errProjectionCapabilities
	}
	if !networkNamespaceIsDisabled() {
		return errProjectionNetwork
	}
	contract := defaultContract()
	values := make(map[string]protectedValue, 8)
	defer func() {
		for name, value := range values {
			clear(value.bytes)
			delete(values, name)
		}
	}()
	for _, volume := range contract {
		for _, file := range volume.files {
			if _, exists := values[file.name]; exists {
				continue
			}
			value, err := readProtectedInput(file)
			if err != nil {
				return errProjectionInput
			}
			values[file.name] = value
		}
	}
	if processMetadataContains(values) {
		return errProjectionMetadata
	}
	for _, volume := range contract {
		if err := projectVolume(volume, values); err != nil {
			return err
		}
	}
	return nil
}

func exactEffectiveCapabilities() bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) == 0 || len(status) > maximumStatusBytes {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "CapEff:\t") {
			continue
		}
		var parsed uint64
		encoded := strings.TrimPrefix(line, "CapEff:\t")
		if encoded == "" || len(encoded) > 16 {
			return false
		}
		for _, character := range encoded {
			parsed <<= 4
			switch {
			case character >= '0' && character <= '9':
				parsed |= uint64(character - '0')
			case character >= 'a' && character <= 'f':
				parsed |= uint64(character-'a') + 10
			default:
				return false
			}
		}
		return parsed == capabilityCHOWN|capabilityDACReadSearch
	}
	return false
}

func networkNamespaceIsDisabled() bool {
	ipv4, err := os.ReadFile("/proc/net/route")
	if err != nil || len(ipv4) > maximumStatusBytes {
		return false
	}
	ipv4Lines := strings.Split(strings.TrimSpace(string(ipv4)), "\n")
	if len(ipv4Lines) != 1 || !strings.HasPrefix(ipv4Lines[0], "Iface") {
		return false
	}
	ipv6, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil || len(ipv6) > maximumStatusBytes {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(ipv6)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[len(fields)-1] != "lo" {
			return false
		}
	}
	return true
}

func readProtectedInput(contract fileContract) (protectedValue, error) {
	descriptor, err := unix.Open(inputPath(contract.name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return protectedValue{}, errProjection
	}
	defer func() { _ = unix.Close(descriptor) }()
	before, err := regularFileState(descriptor)
	if err != nil || before.Mode&0o777 != 0o400 || before.Nlink != 1 || before.Size <= 0 ||
		uint64(before.Size) > contract.maxBytes || contract.maxBytes == exactCryptographicSecretBytes &&
		uint64(before.Size) != exactCryptographicSecretBytes {
		return protectedValue{}, errProjection
	}
	first, err := readExactAt(descriptor, int(before.Size))
	if err != nil {
		return protectedValue{}, errProjection
	}
	second, err := readExactAt(descriptor, int(before.Size))
	if err != nil || !bytes.Equal(first, second) {
		clear(first)
		clear(second)
		return protectedValue{}, errProjection
	}
	clear(second)
	after, err := regularFileState(descriptor)
	if err != nil || !sameFileState(before, after) ||
		contract.maxBytes == exactCryptographicSecretBytes && allZero(first) {
		clear(first)
		return protectedValue{}, errProjection
	}
	return protectedValue{bytes: first, digest: sha256.Sum256(first)}, nil
}

func readExactAt(descriptor int, size int) ([]byte, error) {
	if size <= 0 || size > int(maximumAttestationBytes) {
		return nil, errProjection
	}
	value := make([]byte, size)
	offset := 0
	for offset < len(value) {
		count, err := unix.Pread(descriptor, value[offset:], int64(offset))
		if err == unix.EINTR {
			continue
		}
		if err != nil || count <= 0 {
			clear(value)
			return nil, errProjection
		}
		offset += count
	}
	var extra [1]byte
	count, err := unix.Pread(descriptor, extra[:], int64(size))
	if err != nil || count != 0 {
		clear(value)
		return nil, errProjection
	}
	return value, nil
}

func allZero(value []byte) bool {
	var aggregate byte
	for _, character := range value {
		aggregate |= character
	}
	return aggregate == 0
}

func processMetadataContains(values map[string]protectedValue) bool {
	metadata := make([]byte, 0, maximumStatusBytes)
	for _, path := range []string{"/proc/self/cmdline", "/proc/self/environ"} {
		value, err := os.ReadFile(path)
		if err != nil || len(value) > maximumStatusBytes-len(metadata) {
			clear(metadata)
			return true
		}
		metadata = append(metadata, value...)
		clear(value)
	}
	defer clear(metadata)
	for _, value := range values {
		if bytes.Contains(metadata, value.bytes) {
			return true
		}
	}
	return false
}

func projectVolume(contract volumeContract, values map[string]protectedValue) error {
	directory, err := unix.Open(outputPath(contract.purpose), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errProjectionVolumeOpen
	}
	defer func() { _ = unix.Close(directory) }()
	allowed := make(map[string]struct{}, len(contract.files))
	for _, file := range contract.files {
		allowed[file.name] = struct{}{}
		_ = unix.Unlinkat(directory, temporaryName(file.name), 0)
	}
	if err := exactDirectoryEntries(directory, allowed, true); err != nil {
		return errProjectionVolumeList
	}
	for _, file := range contract.files {
		value, exists := values[file.name]
		if !exists || sha256.Sum256(value.bytes) != value.digest {
			return errProjectionVolumeWrite
		}
		if err := writeProjectedFile(directory, file, value); err != nil {
			return err
		}
	}
	if err := exactDirectoryEntries(directory, allowed, false); err != nil {
		return errProjectionVolumeList
	}
	for _, file := range contract.files {
		if err := verifyProjectedFile(directory, file, values[file.name]); err != nil {
			return errProjectionVolumeVerify
		}
	}
	return nil
}

func temporaryName(name string) string { return ".agentmemory-project-" + name + ".tmp" }

func writeProjectedFile(directory int, contract fileContract, value protectedValue) error {
	temporary := temporaryName(contract.name)
	if err := unix.Unlinkat(directory, temporary, 0); err != nil && err != unix.ENOENT {
		return errProjection
	}
	descriptor, err := unix.Openat(
		directory, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return errProjectionCreate
	}
	failed := true
	defer func() {
		if descriptor >= 0 {
			_ = unix.Close(descriptor)
		}
		if failed {
			_ = unix.Unlinkat(directory, temporary, 0)
		}
	}()
	if err := writeAll(descriptor, value.bytes); err != nil || unix.Fsync(descriptor) != nil {
		return errProjectionContent
	}
	if unix.Fchmod(descriptor, projectedMode) != nil {
		return errProjectionMode
	}
	if unix.Fchown(descriptor, int(contract.userID), int(contract.groupID)) != nil {
		return errProjectionOwner
	}
	if unix.Fsync(descriptor) != nil {
		return errProjectionSync
	}
	state, err := regularFileState(descriptor)
	if err != nil {
		return errProjectionMode
	}
	if state.Uid != contract.userID || state.Gid != contract.groupID {
		return errProjectionStateOwner
	}
	if state.Mode&0o777 != projectedMode {
		return errProjectionStateMode
	}
	if state.Nlink != 1 || state.Size != int64(len(value.bytes)) {
		return errProjectionStateLink
	}
	if err := unix.Close(descriptor); err != nil {
		return errProjectionContent
	}
	descriptor = -1
	if err := unix.Renameat(directory, temporary, directory, contract.name); err != nil || unix.Fsync(directory) != nil {
		return errProjectionPublish
	}
	failed = false
	return nil
}

func writeAll(descriptor int, value []byte) error {
	for offset := 0; offset < len(value); {
		count, err := unix.Write(descriptor, value[offset:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || count <= 0 {
			return errProjection
		}
		offset += count
	}
	return nil
}

func verifyProjectedFile(directory int, contract fileContract, expected protectedValue) error {
	descriptor, err := unix.Openat(directory, contract.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errProjection
	}
	defer func() { _ = unix.Close(descriptor) }()
	before, err := regularFileState(descriptor)
	if err != nil || before.Uid != contract.userID || before.Gid != contract.groupID ||
		before.Mode&0o777 != projectedMode || before.Nlink != 1 || before.Size != int64(len(expected.bytes)) {
		return errProjection
	}
	first, err := readExactAt(descriptor, len(expected.bytes))
	if err != nil {
		return errProjection
	}
	defer clear(first)
	second, err := readExactAt(descriptor, len(expected.bytes))
	if err != nil {
		clear(second)
		return errProjection
	}
	defer clear(second)
	after, err := regularFileState(descriptor)
	if err != nil || !sameFileState(before, after) || !bytes.Equal(first, second) ||
		sha256.Sum256(first) != expected.digest {
		return errProjection
	}
	return nil
}

func exactDirectoryEntries(directory int, allowed map[string]struct{}, allowTemporary bool) error {
	duplicate, err := unix.Dup(directory)
	if err != nil {
		return errProjection
	}
	file := os.NewFile(uintptr(duplicate), "protected-projection-directory")
	if file == nil {
		_ = unix.Close(duplicate)
		return errProjection
	}
	names, readErr := file.Readdirnames(-1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > len(allowed)*2 {
		return errProjection
	}
	sort.Strings(names)
	for index, name := range names {
		if index > 0 && names[index-1] == name {
			return errProjection
		}
		if _, exists := allowed[name]; exists {
			continue
		}
		if allowTemporary {
			matched := false
			for allowedName := range allowed {
				if name == temporaryName(allowedName) {
					matched = true
					break
				}
			}
			if matched {
				continue
			}
		}
		return errProjection
	}
	return nil
}

func regularFileState(descriptor int) (unix.Stat_t, error) {
	var state unix.Stat_t
	if descriptor < 0 || unix.Fstat(descriptor, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.Stat_t{}, errProjection
	}
	return state, nil
}

func sameFileState(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Nlink == right.Nlink && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}
