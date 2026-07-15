//go:build darwin && cgo

package dockercli

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
	uint64_t left;
	uint64_t right;
} am_socket_pair;

static int am_exact_unix_path(const struct sockaddr_un *address, const char *wanted) {
	if (address == NULL || wanted == NULL || address->sun_family != AF_UNIX) {
		return 0;
	}
	size_t wanted_length = strlen(wanted);
	if (wanted_length == 0 || wanted_length >= sizeof(address->sun_path)) {
		return 0;
	}
	return memcmp(address->sun_path, wanted, wanted_length) == 0 &&
		address->sun_path[wanted_length] == '\0';
}

static int am_append_pair(
	am_socket_pair *pairs,
	int capacity,
	int *count,
	uint64_t socket_id,
	uint64_t peer_id
) {
	uint64_t left = socket_id < peer_id ? socket_id : peer_id;
	uint64_t right = socket_id < peer_id ? peer_id : socket_id;
	if (left == 0 || right == 0 || left == right) {
		return -1;
	}
	for (int index = 0; index < *count; index++) {
		if (pairs[index].left == left && pairs[index].right == right) {
			return 0;
		}
	}
	if (*count >= capacity) {
		return -1;
	}
	pairs[*count].left = left;
	pairs[*count].right = right;
	(*count)++;
	return 0;
}

static int am_scan_unix_clients(
	const char *wanted,
	am_socket_pair *pairs,
	int capacity,
	int *pair_count,
	uint64_t *listener_id
) {
	if (wanted == NULL || pairs == NULL || capacity <= 0 || pair_count == NULL || listener_id == NULL) {
		return -1;
	}
	*pair_count = 0;
	*listener_id = 0;
	int pid_capacity = proc_listallpids(NULL, 0);
	if (pid_capacity <= 0 || pid_capacity > (1 << 20)) {
		return -1;
	}
	pid_t *pids = calloc((size_t)pid_capacity, sizeof(pid_t));
	if (pids == NULL) {
		return -1;
	}
	int pid_count = proc_listallpids(pids, pid_capacity * (int)sizeof(pid_t));
	if (pid_count <= 0 || pid_count > pid_capacity) {
		free(pids);
		return -1;
	}
	uid_t current_uid = geteuid();
	for (int pid_index = 0; pid_index < pid_count; pid_index++) {
		pid_t pid = pids[pid_index];
		if (pid <= 0) {
			continue;
		}
		struct proc_bsdinfo bsd;
		memset(&bsd, 0, sizeof(bsd));
		int bsd_bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd));
		if (bsd_bytes != (int)sizeof(bsd) || bsd.pbi_uid != current_uid) {
			continue;
		}
		int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
		if (fd_bytes <= 0 || fd_bytes > (1 << 24)) {
			if (errno == ESRCH) {
				continue;
			}
			free(pids);
			return -1;
		}
		struct proc_fdinfo *fds = calloc(1, (size_t)fd_bytes);
		if (fds == NULL) {
			free(pids);
			return -1;
		}
		fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_bytes);
		if (fd_bytes <= 0) {
			free(fds);
			if (errno == ESRCH) {
				continue;
			}
			free(pids);
			return -1;
		}
		int fd_count = fd_bytes / (int)sizeof(struct proc_fdinfo);
		for (int fd_index = 0; fd_index < fd_count; fd_index++) {
			if (fds[fd_index].proc_fdtype != PROX_FDTYPE_SOCKET) {
				continue;
			}
			struct socket_fdinfo socket_info;
			memset(&socket_info, 0, sizeof(socket_info));
			int socket_bytes = proc_pidfdinfo(
				pid, fds[fd_index].proc_fd, PROC_PIDFDSOCKETINFO,
				&socket_info, sizeof(socket_info)
			);
			if (socket_bytes != (int)sizeof(socket_info)) {
				if (errno == EBADF || errno == ESRCH) {
					continue;
				}
				free(fds);
				free(pids);
				return -1;
			}
			if (socket_info.psi.soi_kind != SOCKINFO_UN || socket_info.psi.soi_type != SOCK_STREAM) {
				continue;
			}
			struct un_sockinfo *unix_info = &socket_info.psi.soi_proto.pri_un;
			int bound = am_exact_unix_path(&unix_info->unsi_addr.ua_sun, wanted);
			int connected = am_exact_unix_path(&unix_info->unsi_caddr.ua_sun, wanted);
			if (!bound && !connected) {
				continue;
			}
			if (unix_info->unsi_conn_so == 0) {
				if (!bound || *listener_id != 0 && *listener_id != socket_info.psi.soi_so) {
					free(fds);
					free(pids);
					return -1;
				}
				*listener_id = socket_info.psi.soi_so;
				continue;
			}
			if (am_append_pair(pairs, capacity, pair_count, socket_info.psi.soi_so, unix_info->unsi_conn_so) != 0) {
				free(fds);
				free(pids);
				return -1;
			}
		}
		free(fds);
	}
	free(pids);
	return *listener_id == 0 ? -1 : 0;
}
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumDarwinActiveClientPairs = 4096

type darwinSocketPair struct{ left, right uint64 }

type darwinSocketSnapshot struct {
	listener uint64
	pairs    []darwinSocketPair
}

// NativeActiveRuntimeClientScanner uses libproc socket metadata without
// invoking lsof, netstat, a shell, or any ambient executable.
type NativeActiveRuntimeClientScanner struct {
	inspect func(string) (darwinSocketSnapshot, error)
}

var _ ActiveRuntimeClientScanner = (*NativeActiveRuntimeClientScanner)(nil)

// NewNativeActiveRuntimeClientScanner constructs the native macOS observer.
func NewNativeActiveRuntimeClientScanner() *NativeActiveRuntimeClientScanner {
	return &NativeActiveRuntimeClientScanner{inspect: inspectDarwinUnixClients}
}

// ScanActiveRuntimeClients binds unique peer pairs for the exact local socket.
func (s *NativeActiveRuntimeClientScanner) ScanActiveRuntimeClients(
	ctx context.Context,
	endpoint containerengine.Endpoint,
) (ActiveClientObservation, error) {
	if s == nil || s.inspect == nil || ctx == nil || !strings.HasPrefix(endpoint.String(), "unix:///") {
		return ActiveClientObservation{}, errors.New("macOS active-client scan authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		return ActiveClientObservation{}, err
	}
	snapshot, err := s.inspect(strings.TrimPrefix(endpoint.String(), "unix://"))
	if err != nil || snapshot.listener == 0 || len(snapshot.pairs) > maximumDarwinActiveClientPairs {
		return ActiveClientObservation{}, errors.New("macOS active-client observation is unavailable")
	}
	records := make([]string, 0, len(snapshot.pairs)+1)
	records = append(records, fmt.Sprintf("listener:%016x", snapshot.listener))
	seen := make(map[darwinSocketPair]struct{}, len(snapshot.pairs))
	for _, pair := range snapshot.pairs {
		if pair.left == 0 || pair.right == 0 || pair.left >= pair.right {
			return ActiveClientObservation{}, errors.New("macOS active-client pair is invalid")
		}
		if _, duplicate := seen[pair]; duplicate {
			return ActiveClientObservation{}, errors.New("macOS active-client pair is duplicated")
		}
		seen[pair] = struct{}{}
		records = append(records, fmt.Sprintf("pair:%016x:%016x", pair.left, pair.right))
	}
	slices.Sort(records)
	evidence := sha256.Sum256([]byte("agentmemory.darwin-active-runtime-clients.v1\n" + strings.Join(records, "\n")))
	return ActiveClientObservation{Count: uint64(len(snapshot.pairs)), EvidenceDigest: runtimeinstall.Hash(evidence)}, nil
}

func inspectDarwinUnixClients(socketPath string) (darwinSocketSnapshot, error) {
	if socketPath == "" || !strings.HasPrefix(socketPath, "/") || strings.ContainsAny(socketPath, "\x00\r\n") {
		return darwinSocketSnapshot{}, errors.New("macOS Docker socket path is invalid")
	}
	wanted := C.CString(socketPath)
	defer C.free(unsafe.Pointer(wanted))
	pairs := make([]C.am_socket_pair, maximumDarwinActiveClientPairs)
	var count C.int
	var listener C.uint64_t
	if C.am_scan_unix_clients(
		wanted, &pairs[0], C.int(len(pairs)), &count, &listener,
	) != 0 || count < 0 || int(count) > len(pairs) {
		return darwinSocketSnapshot{}, errors.New("macOS libproc socket scan failed")
	}
	result := darwinSocketSnapshot{listener: uint64(listener), pairs: make([]darwinSocketPair, 0, int(count))}
	for index := range int(count) {
		result.pairs = append(result.pairs, darwinSocketPair{
			left: uint64(pairs[index].left), right: uint64(pairs[index].right),
		})
	}
	return result, nil
}
