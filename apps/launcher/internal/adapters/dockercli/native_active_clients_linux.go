//go:build linux

package dockercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumProcUnixBytes = 8 << 20

// NativeActiveRuntimeClientScanner reads the kernel Unix-socket table without
// invoking an ambient executable or opening a new Docker connection.
type NativeActiveRuntimeClientScanner struct {
	read func() ([]byte, error)
}

var _ ActiveRuntimeClientScanner = (*NativeActiveRuntimeClientScanner)(nil)

// NewNativeActiveRuntimeClientScanner constructs the Linux kernel observer.
func NewNativeActiveRuntimeClientScanner() *NativeActiveRuntimeClientScanner {
	return &NativeActiveRuntimeClientScanner{read: readLinuxProcUnix}
}

// ScanActiveRuntimeClients counts exact-path connecting/connected server-side
// stream sockets and binds the full exact-path kernel observation.
func (s *NativeActiveRuntimeClientScanner) ScanActiveRuntimeClients(
	ctx context.Context,
	endpoint containerengine.Endpoint,
) (ActiveClientObservation, error) {
	if s == nil || s.read == nil || ctx == nil || !strings.HasPrefix(endpoint.String(), "unix:///") {
		return ActiveClientObservation{}, errors.New("linux active-client scan authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		return ActiveClientObservation{}, err
	}
	raw, err := s.read()
	if err != nil || len(raw) == 0 || len(raw) > maximumProcUnixBytes {
		return ActiveClientObservation{}, errors.New("linux Unix-socket table is unavailable")
	}
	observation, err := parseLinuxProcUnix(raw, strings.TrimPrefix(endpoint.String(), "unix://"))
	if err != nil {
		return ActiveClientObservation{}, err
	}
	return observation, nil
}

func readLinuxProcUnix() ([]byte, error) {
	file, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(io.LimitReader(file, maximumProcUnixBytes+1))
}

func parseLinuxProcUnix(raw []byte, socketPath string) (ActiveClientObservation, error) {
	if socketPath == "" || !strings.HasPrefix(socketPath, "/") || strings.ContainsAny(socketPath, "\x00\r\n") {
		return ActiveClientObservation{}, errors.New("linux Docker socket path is invalid")
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) < 2 || string(lines[0]) != "Num       RefCount Protocol Flags    Type St Inode Path" {
		return ActiveClientObservation{}, errors.New("linux Unix-socket table schema is unsupported")
	}
	records := make([]string, 0, 4)
	connected := make(map[string]struct{})
	listeners := uint64(0)
	for _, rawLine := range lines[1:] {
		fields := strings.Fields(string(rawLine))
		if len(fields) < 7 {
			return ActiveClientObservation{}, errors.New("linux Unix-socket record is truncated")
		}
		if len(fields) == 7 {
			continue
		}
		path := strings.Join(fields[7:], " ")
		if path != socketPath {
			continue
		}
		if !validLinuxSocketHex(fields[0], true) || !validLinuxSocketHex(fields[1], false) ||
			!validLinuxSocketHex(fields[2], false) || !validLinuxSocketHex(fields[3], false) ||
			fields[4] != "0001" || !slices.Contains([]string{"01", "02", "03"}, fields[5]) {
			return ActiveClientObservation{}, errors.New("linux Docker socket record is ambiguous")
		}
		if _, err := strconv.ParseUint(fields[6], 10, 64); err != nil || fields[6] == "0" {
			return ActiveClientObservation{}, errors.New("linux Docker socket inode is invalid")
		}
		records = append(records, strings.Join(fields[:7], "|")+"|"+path)
		if fields[5] == "01" {
			listeners++
			continue
		}
		connected[fields[6]] = struct{}{}
	}
	if listeners != 1 {
		return ActiveClientObservation{}, errors.New("linux Docker socket listener identity is ambiguous")
	}
	slices.Sort(records)
	evidence := sha256.Sum256([]byte("agentmemory.linux-active-runtime-clients.v1\n" + strings.Join(records, "\n")))
	return ActiveClientObservation{Count: uint64(len(connected)), EvidenceDigest: runtimeinstall.Hash(evidence)}, nil
}

func validLinuxSocketHex(value string, colon bool) bool {
	if colon {
		if !strings.HasSuffix(value, ":") {
			return false
		}
		value = strings.TrimSuffix(value, ":")
	}
	if len(value) != 8 {
		return false
	}
	if _, err := strconv.ParseUint(value, 16, 32); err != nil {
		return false
	}
	return true
}

func linuxSocketRecord(
	number, refCount, flags, socketType, state, inode, path string,
) string {
	return fmt.Sprintf("%s: %s 00000000 %s %s %s %s %s", number, refCount, flags, socketType, state, inode, path)
}
