//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"golang.org/x/sys/unix"
)

const maximumProcProcesses = 1048576

// NativeEndpointProbe proves socket ownership and daemon-process listener state.
type NativeEndpointProbe struct{}

// NewNativeEndpointProbe constructs the production Linux endpoint probe.
func NewNativeEndpointProbe() *NativeEndpointProbe { return &NativeEndpointProbe{} }

// ProbeLinuxEndpoint accepts only the plan-derived /run/user/UID/docker.sock.
func (*NativeEndpointProbe) ProbeLinuxEndpoint(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (EndpointEvidence, error) {
	if ctx == nil {
		return EndpointEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return EndpointEvidence{}, err
	}
	if !authority.Valid() || validateOwnerDirectory(authority.RuntimeDirectory(), authority.InvokingUID(), true) != nil {
		return EndpointEvidence{}, ErrProvisionIntegrity
	}
	for _, rootfulPath := range []string{"/run/docker.sock", "/var/run/docker.sock"} {
		if _, rootfulError := os.Lstat(rootfulPath); rootfulError == nil {
			return EndpointEvidence{}, ErrRuntimeConflict
		} else if !errors.Is(rootfulError, os.ErrNotExist) {
			return EndpointEvidence{}, ErrProbeFailed
		}
	}
	path := authority.RuntimeDirectory() + "/docker.sock"
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewEndpointEvidence(false, 0, 0, false)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return EndpointEvidence{}, ErrRuntimeConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	permissions := uint32(info.Mode().Perm())
	if !ok || stat.Uid != authority.InvokingUID() || stat.Gid != authority.InvokingGID() ||
		permissions&0o600 != 0o600 || permissions&0o007 != 0 || permissions&0o110 != 0 {
		return EndpointEvidence{}, ErrRuntimeConflict
	}
	noTCP, err := endpointProcessTreeHasNoTCP(ctx, path, authority.InvokingUID(), stat.Ino)
	if err != nil {
		return EndpointEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	return NewEndpointEvidence(true, stat.Ino, permissions, noTCP)
}

func endpointProcessTreeHasNoTCP(ctx context.Context, path string, uid uint32, inode uint64) (bool, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return false, err
	}
	defer func() { _ = connection.Close() }()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return false, ErrProbeFailed
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return false, err
	}
	var credentials *unix.Ucred
	var controlError error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, controlError = unix.GetsockoptUcred(int(descriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlError != nil || credentials == nil || credentials.Pid <= 1 || credentials.Uid != uid {
		return false, ErrProbeFailed
	}
	processes, err := sameUserProcessTree(ctx, uint32(credentials.Pid), uid)
	if err != nil {
		return false, err
	}
	sockets, err := processSocketInodes(ctx, processes)
	if err != nil {
		return false, err
	}
	listeners := make(map[uint64]struct{})
	for _, procPath := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		rawTable, readError := os.ReadFile(procPath) // #nosec G304 -- procPath comes from the fixed literal allowlist above.
		if readError != nil {
			return false, readError
		}
		parsed, parseError := parseListeningTCPInodes(rawTable)
		if parseError != nil {
			return false, parseError
		}
		for candidate := range parsed {
			listeners[candidate] = struct{}{}
		}
	}
	for candidate := range sockets {
		if _, listening := listeners[candidate]; listening {
			return false, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return false, ErrProbeFailed
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino != inode || stat.Uid != uid {
		return false, ErrProbeFailed
	}
	return true, nil
}

type processIdentity struct {
	parent uint32
	uid    uint32
}

func sameUserProcessTree(ctx context.Context, peer, uid uint32) (map[uint32]struct{}, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > maximumProcProcesses {
		return nil, ErrProbeFailed
	}
	identities := make(map[uint32]processIdentity)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pidValue, parseError := strconv.ParseUint(entry.Name(), 10, 32)
		if parseError != nil || pidValue == 0 || !entry.IsDir() {
			continue
		}
		raw, readError := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if errors.Is(readError, os.ErrNotExist) || errors.Is(readError, os.ErrPermission) {
			continue
		}
		if readError != nil {
			return nil, ErrProbeFailed
		}
		parent, processUID, statusError := parseProcStatus(raw)
		if statusError != nil {
			return nil, ErrProbeFailed
		}
		identities[uint32(pidValue)] = processIdentity{parent: parent, uid: processUID}
	}
	if identity, present := identities[peer]; !present || identity.uid != uid {
		return nil, ErrProbeFailed
	}
	children := make(map[uint32][]uint32)
	for pid, identity := range identities {
		if identity.uid == uid {
			children[identity.parent] = append(children[identity.parent], pid)
		}
	}
	selected := map[uint32]struct{}{peer: {}}
	queue := []uint32{peer}
	for len(queue) != 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if _, already := selected[child]; already {
				continue
			}
			selected[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	// Include ancestors only after descendant selection so unrelated sibling
	// services under the user's systemd manager cannot create false authority.
	current := peer
	for current > 1 {
		identity, present := identities[current]
		if !present || identity.parent <= 1 {
			break
		}
		parent, present := identities[identity.parent]
		if !present || parent.uid != uid {
			break
		}
		selected[identity.parent] = struct{}{}
		current = identity.parent
	}
	return selected, nil
}

func processSocketInodes(ctx context.Context, processes map[uint32]struct{}) (map[uint64]struct{}, error) {
	result := make(map[uint64]struct{})
	for pid := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fdPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/fd"
		entries, err := os.ReadDir(fdPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// Production endpoint verification remains fail-closed when procfs
			// hides a member of the peer process tree. Normalize host policy
			// details so callers never receive a private procfs error.
			return nil, ErrProbeFailed
		}
		for _, entry := range entries {
			target, readError := os.Readlink(filepath.Join(fdPath, entry.Name()))
			if errors.Is(readError, os.ErrNotExist) {
				// File descriptors may close between ReadDir and Readlink. A
				// vanished descriptor cannot retain a listening socket, while
				// every descriptor that still exists remains fail-closed below.
				continue
			}
			if readError != nil {
				return nil, ErrProbeFailed
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			value := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			inode, parseError := strconv.ParseUint(value, 10, 64)
			if parseError != nil || inode == 0 {
				return nil, ErrProbeFailed
			}
			result[inode] = struct{}{}
		}
	}
	return result, nil
}

var _ EndpointProbe = (*NativeEndpointProbe)(nil)
