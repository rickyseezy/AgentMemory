//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const (
	maximumPrivilegeSubIDBytes = 4 << 20
	minimumPrivilegeSubIDStart = uint64(100000)
	privilegeSubIDFileMode     = uint32(0o644)
)

// PrivilegeSubordinateIDStateProbe independently observes the exact current
// account ranges under the same cross-process serialization boundary.
type PrivilegeSubordinateIDStateProbe interface {
	ObservePrivilegeSubordinateIDState(
		context.Context,
		runtimeport.LinuxAuthority,
	) (uint32, uint32, uint32, runtimeinstall.Hash, error)
}

// NativePrivilegeSubordinateIDManager owns only the signed invoking account's
// subuid/subgid entries. Foreign records are parsed, collision checked, and
// retained byte-for-byte.
type NativePrivilegeSubordinateIDManager struct {
	directory string
	uidFile   string
	gidFile   string
	lockFile  string
	ownerUID  uint32
	ownerGID  uint32
	gate      chan struct{}
}

// NewNativePrivilegeSubordinateIDManager constructs the production root-owned
// Linux allocator. It is unavailable on non-Linux hosts.
func NewNativePrivilegeSubordinateIDManager() (*NativePrivilegeSubordinateIDManager, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupportedHost
	}
	return newNativePrivilegeSubordinateIDManager(
		"/etc/subuid", "/etc/subgid", "/etc/.agentmemory-subid.lock", 0, 0,
	)
}

func newNativePrivilegeSubordinateIDManager(
	uidFile string,
	gidFile string,
	lockFile string,
	ownerUID uint32,
	ownerGID uint32,
) (*NativePrivilegeSubordinateIDManager, error) {
	directory := filepath.Dir(uidFile)
	if !canonicalPrivilegeSystemPath(uidFile) || !canonicalPrivilegeSystemPath(gidFile) ||
		!canonicalPrivilegeSystemPath(lockFile) || filepath.Dir(gidFile) != directory ||
		filepath.Dir(lockFile) != directory || filepath.Base(uidFile) == filepath.Base(gidFile) ||
		filepath.Base(uidFile) == filepath.Base(lockFile) || filepath.Base(gidFile) == filepath.Base(lockFile) {
		return nil, errors.New("canonical co-located subordinate ID paths are required")
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &NativePrivilegeSubordinateIDManager{
		directory: directory, uidFile: filepath.Base(uidFile), gidFile: filepath.Base(gidFile),
		lockFile: filepath.Base(lockFile), ownerUID: ownerUID, ownerGID: ownerGID, gate: gate,
	}, nil
}

// EnsurePrivilegeSubordinateIDs allocates each missing range from the first
// deterministic collision-free gap. Existing exact ranges are retained.
func (m *NativePrivilegeSubordinateIDManager) EnsurePrivilegeSubordinateIDs(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (bool, error) {
	if m == nil || ctx == nil || request.Operation() != runtimeport.PrivilegeConfigureSubordinateIDs ||
		request.Digest().IsZero() || !request.Authority().Valid() {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	changed := false
	err := m.withPrivilegeSubIDLock(ctx, func(directory int) error {
		authority := request.Authority()
		uidDocument, err := m.readPrivilegeSubIDDocument(directory, m.uidFile)
		if err != nil {
			return err
		}
		gidDocument, err := m.readPrivilegeSubIDDocument(directory, m.gidFile)
		if err != nil {
			return err
		}
		uidRaw, uidChanged, err := resolvePrivilegeSubIDDocument(uidDocument, authority)
		if err != nil {
			return err
		}
		gidRaw, gidChanged, err := resolvePrivilegeSubIDDocument(gidDocument, authority)
		if err != nil {
			return err
		}
		if uidChanged {
			if err := m.writePrivilegeSubIDFile(directory, m.uidFile, uidRaw); err != nil {
				return err
			}
		}
		if gidChanged {
			if err := m.writePrivilegeSubIDFile(directory, m.gidFile, gidRaw); err != nil {
				return err
			}
		}
		changed = uidChanged || gidChanged
		_, _, _, _, err = m.observePrivilegeSubordinateIDStateLocked(directory, authority)
		return err
	})
	if err != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	return changed, nil
}

// ObservePrivilegeSubordinateIDState serializes with mutation and derives a
// canonical digest from the exact account, starts, and signed count.
func (m *NativePrivilegeSubordinateIDManager) ObservePrivilegeSubordinateIDState(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (uint32, uint32, uint32, runtimeinstall.Hash, error) {
	if m == nil || ctx == nil || !authority.Valid() {
		return 0, 0, 0, runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, err
	}
	var uidStart, gidStart, count uint32
	var digest runtimeinstall.Hash
	err := m.withPrivilegeSubIDLock(ctx, func(directory int) error {
		var observeError error
		uidStart, gidStart, count, digest, observeError = m.observePrivilegeSubordinateIDStateLocked(directory, authority)
		return observeError
	})
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, privilegeOperationContextOrIntegrity(ctx)
	}
	return uidStart, gidStart, count, digest, nil
}

func (m *NativePrivilegeSubordinateIDManager) observePrivilegeSubordinateIDStateLocked(
	directory int,
	authority runtimeport.LinuxAuthority,
) (uint32, uint32, uint32, runtimeinstall.Hash, error) {
	uidDocument, err := m.readPrivilegeSubIDDocument(directory, m.uidFile)
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, err
	}
	gidDocument, err := m.readPrivilegeSubIDDocument(directory, m.gidFile)
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, err
	}
	uidStart, err := exactPrivilegeSubIDRange(uidDocument, authority)
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, err
	}
	gidStart, err := exactPrivilegeSubIDRange(gidDocument, authority)
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, err
	}
	count := authority.SubordinateIDCount()
	encoded, err := json.Marshal(struct {
		Account  string `json:"account"`
		GIDStart uint32 `json:"gid_start"`
		Range    uint32 `json:"range"`
		UID      uint32 `json:"uid"`
		UIDStart uint32 `json:"uid_start"`
	}{
		Account: authority.AccountName(), GIDStart: gidStart, Range: count,
		UID: authority.InvokingUID(), UIDStart: uidStart,
	})
	if err != nil {
		return 0, 0, 0, runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	return uidStart, gidStart, count, runtimeinstall.Sum(encoded), nil
}

func (m *NativePrivilegeSubordinateIDManager) withPrivilegeSubIDLock(
	ctx context.Context,
	operation func(int) error,
) error {
	if m == nil || ctx == nil || operation == nil || m.gate == nil {
		return runtimeport.ErrPrivilegeIntegrity
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.gate:
	}
	defer func() { m.gate <- struct{}{} }()
	directory, err := unix.Open(m.directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(directory) }()
	if !privilegeSubIDDirectoryMatches(directory, m.ownerUID, m.ownerGID) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	lock, err := unix.Openat(
		directory, m.lockFile, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(lock) }()
	if !privilegeSubIDDescriptorMatches(lock, m.ownerUID, m.ownerGID, 0o600, math.MaxInt64) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	for {
		err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()
	return operation(directory)
}

type privilegeSubIDEntry struct {
	identity string
	start    uint32
	count    uint32
}

type privilegeSubIDDocument struct {
	raw     []byte
	entries []privilegeSubIDEntry
}

func (m *NativePrivilegeSubordinateIDManager) readPrivilegeSubIDDocument(
	directory int,
	name string,
) (privilegeSubIDDocument, error) {
	descriptor, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return privilegeSubIDDocument{}, nil
	}
	if err != nil {
		return privilegeSubIDDocument{}, err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-subid")
	if file == nil {
		_ = unix.Close(descriptor)
		return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = file.Close() }()
	if !privilegeSubIDDescriptorMatches(
		descriptor, m.ownerUID, m.ownerGID, privilegeSubIDFileMode, maximumPrivilegeSubIDBytes,
	) {
		return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPrivilegeSubIDBytes+1))
	if err != nil || len(raw) > maximumPrivilegeSubIDBytes {
		return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return parsePrivilegeSubIDDocument(raw)
}

func parsePrivilegeSubIDDocument(raw []byte) (privilegeSubIDDocument, error) {
	if len(raw) > maximumPrivilegeSubIDBytes || len(raw) != 0 && raw[len(raw)-1] != '\n' {
		return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	document := privilegeSubIDDocument{raw: append([]byte(nil), raw...)}
	if len(raw) == 0 {
		return document, nil
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	for _, line := range lines {
		if len(line) > 4096 || strings.ContainsAny(line, "\x00\r") {
			return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 3 || !validPrivilegeSubIDIdentity(fields[0]) {
			return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
		}
		start, err := parsePrivilegeSubIDNumber(fields[1], true)
		if err != nil {
			return privilegeSubIDDocument{}, err
		}
		count, err := parsePrivilegeSubIDNumber(fields[2], false)
		if err != nil || uint64(start)+uint64(count) > uint64(math.MaxUint32)+1 {
			return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
		}
		document.entries = append(document.entries, privilegeSubIDEntry{
			identity: fields[0], start: start, count: count,
		})
	}
	if privilegeSubIDRangesOverlap(document.entries) {
		return privilegeSubIDDocument{}, runtimeport.ErrPrivilegeIntegrity
	}
	return document, nil
}

func parsePrivilegeSubIDNumber(value string, allowZero bool) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != value || !allowZero && parsed == 0 {
		return 0, runtimeport.ErrPrivilegeIntegrity
	}
	return uint32(parsed), nil
}

func validPrivilegeSubIDIdentity(value string) bool {
	if value == "" || len(value) > 256 || value != strings.TrimSpace(value) || strings.ContainsRune(value, ':') {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func privilegeSubIDRangesOverlap(entries []privilegeSubIDEntry) bool {
	ranges := append([]privilegeSubIDEntry(nil), entries...)
	slices.SortFunc(ranges, func(left, right privilegeSubIDEntry) int {
		return int64Compare(uint64(left.start), uint64(right.start))
	})
	for index := 1; index < len(ranges); index++ {
		previousEnd := uint64(ranges[index-1].start) + uint64(ranges[index-1].count)
		if uint64(ranges[index].start) < previousEnd {
			return true
		}
	}
	return false
}

func int64Compare(left uint64, right uint64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func resolvePrivilegeSubIDDocument(
	document privilegeSubIDDocument,
	authority runtimeport.LinuxAuthority,
) ([]byte, bool, error) {
	if !authority.Valid() {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	if _, found, err := findPrivilegeSubIDRange(document, authority); err != nil {
		return nil, false, err
	} else if found {
		return append([]byte(nil), document.raw...), false, nil
	}
	start, err := allocatePrivilegeSubIDRange(document.entries, authority.SubordinateIDCount())
	if err != nil {
		return nil, false, err
	}
	raw := append([]byte(nil), document.raw...)
	raw = append(raw, []byte(
		authority.AccountName()+":"+strconv.FormatUint(uint64(start), 10)+":"+
			strconv.FormatUint(uint64(authority.SubordinateIDCount()), 10)+"\n",
	)...)
	return raw, true, nil
}

func exactPrivilegeSubIDRange(
	document privilegeSubIDDocument,
	authority runtimeport.LinuxAuthority,
) (uint32, error) {
	start, found, err := findPrivilegeSubIDRange(document, authority)
	if err != nil || !found {
		return 0, runtimeport.ErrPrivilegeIntegrity
	}
	return start, nil
}

func findPrivilegeSubIDRange(
	document privilegeSubIDDocument,
	authority runtimeport.LinuxAuthority,
) (uint32, bool, error) {
	numericUID := strconv.FormatUint(uint64(authority.InvokingUID()), 10)
	var found *privilegeSubIDEntry
	for index := range document.entries {
		entry := &document.entries[index]
		if entry.identity != authority.AccountName() && entry.identity != numericUID {
			continue
		}
		if found != nil || entry.count != authority.SubordinateIDCount() || entry.start < entry.count {
			return 0, false, runtimeport.ErrPrivilegeIntegrity
		}
		found = entry
	}
	if found == nil {
		return 0, false, nil
	}
	return found.start, true, nil
}

func allocatePrivilegeSubIDRange(entries []privilegeSubIDEntry, count uint32) (uint32, error) {
	if count == 0 {
		return 0, runtimeport.ErrPrivilegeIntegrity
	}
	ranges := append([]privilegeSubIDEntry(nil), entries...)
	slices.SortFunc(ranges, func(left, right privilegeSubIDEntry) int {
		return int64Compare(uint64(left.start), uint64(right.start))
	})
	candidate := minimumPrivilegeSubIDStart
	for _, entry := range ranges {
		start := uint64(entry.start)
		end := start + uint64(entry.count)
		if candidate+uint64(count) <= start {
			break
		}
		if candidate < end {
			candidate = end
		}
	}
	if candidate < uint64(count) || candidate+uint64(count) > uint64(math.MaxUint32)+1 {
		return 0, runtimeport.ErrPrivilegeIntegrity
	}
	return uint32(candidate), nil
}

func (m *NativePrivilegeSubordinateIDManager) writePrivilegeSubIDFile(
	directory int,
	name string,
	raw []byte,
) error {
	if len(raw) == 0 || len(raw) > maximumPrivilegeSubIDBytes {
		return runtimeport.ErrPrivilegeIntegrity
	}
	digest := runtimeinstall.Sum(raw)
	temporary := "." + name + ".agentmemory." + digest.String() + ".partial"
	if err := removePrivilegeSubIDTemporary(directory, temporary, m.ownerUID, m.ownerGID); err != nil {
		return err
	}
	descriptor, err := unix.Openat(
		directory, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-subid-target")
	if file == nil {
		_ = unix.Close(descriptor)
		_ = unix.Unlinkat(directory, temporary, 0)
		return runtimeport.ErrPrivilegeIntegrity
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = unix.Unlinkat(directory, temporary, 0)
		}
	}()
	written, err := file.Write(raw)
	if err != nil || written != len(raw) || file.Sync() != nil || file.Chmod(os.FileMode(privilegeSubIDFileMode)) != nil ||
		file.Close() != nil || unix.Renameat(directory, temporary, directory, name) != nil || unix.Fsync(directory) != nil {
		return runtimeport.ErrPrivilegeIntegrity
	}
	committed = true
	return nil
}

func removePrivilegeSubIDTemporary(directory int, name string, uid uint32, gid uint32) error {
	var metadata unix.Stat_t
	err := unix.Fstatat(directory, name, &metadata, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Uid != uid || metadata.Gid != gid ||
		metadata.Nlink != 1 || nativePrivilegeStatMode(&metadata)&0o7777 != 0o600 {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return unix.Unlinkat(directory, name, 0)
}

func privilegeSubIDDirectoryMatches(descriptor int, uid uint32, gid uint32) bool {
	var metadata unix.Stat_t
	return unix.Fstat(descriptor, &metadata) == nil && metadata.Mode&unix.S_IFMT == unix.S_IFDIR &&
		metadata.Uid == uid && metadata.Gid == gid && nativePrivilegeStatMode(&metadata)&0o022 == 0
}

func privilegeSubIDDescriptorMatches(
	descriptor int,
	uid uint32,
	gid uint32,
	mode uint32,
	maximumSize int64,
) bool {
	var metadata unix.Stat_t
	return unix.Fstat(descriptor, &metadata) == nil && metadata.Mode&unix.S_IFMT == unix.S_IFREG &&
		metadata.Uid == uid && metadata.Gid == gid && metadata.Nlink == 1 && metadata.Size >= 0 &&
		metadata.Size <= maximumSize && nativePrivilegeStatMode(&metadata)&0o7777 == mode
}

var _ PrivilegeSubordinateIDManager = (*NativePrivilegeSubordinateIDManager)(nil)
var _ PrivilegeSubordinateIDStateProbe = (*NativePrivilegeSubordinateIDManager)(nil)
