//go:build windows

package dockercli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

type windowsPipeSnapshot struct {
	State            uint32
	CurrentInstances uint32
	MaximumInstances uint32
	InboundBytes     uint32
	OutboundBytes    uint32
}

// NativeActiveRuntimeClientScanner observes the named-pipe instance count
// through kernel32 and conservatively treats every instance other than its
// own short-lived observation connection as an active dependency.
type NativeActiveRuntimeClientScanner struct {
	inspect func(string) (windowsPipeSnapshot, error)
}

var _ ActiveRuntimeClientScanner = (*NativeActiveRuntimeClientScanner)(nil)

// NewNativeActiveRuntimeClientScanner constructs the Windows named-pipe observer.
func NewNativeActiveRuntimeClientScanner() *NativeActiveRuntimeClientScanner {
	return &NativeActiveRuntimeClientScanner{inspect: inspectWindowsNamedPipe}
}

// ScanActiveRuntimeClients never undercounts an already-created pipe
// instance; pre-created listening instances may conservatively block removal.
func (s *NativeActiveRuntimeClientScanner) ScanActiveRuntimeClients(
	ctx context.Context,
	endpoint containerengine.Endpoint,
) (ActiveClientObservation, error) {
	const prefix = "npipe:////./pipe/"
	if s == nil || s.inspect == nil || ctx == nil || !strings.HasPrefix(endpoint.String(), prefix) {
		return ActiveClientObservation{}, errors.New("Windows active-client scan authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		return ActiveClientObservation{}, err
	}
	pipeName := strings.TrimPrefix(endpoint.String(), prefix)
	snapshot, err := s.inspect(`\\.\pipe\` + pipeName)
	if err != nil || snapshot.CurrentInstances == 0 || snapshot.MaximumInstances == 0 ||
		snapshot.CurrentInstances > snapshot.MaximumInstances {
		return ActiveClientObservation{}, errors.New("Windows named-pipe observation is unavailable")
	}
	document := struct {
		Schema           string `json:"schema"`
		State            uint32 `json:"state"`
		CurrentInstances uint32 `json:"current_instances"`
		MaximumInstances uint32 `json:"maximum_instances"`
		InboundBytes     uint32 `json:"inbound_bytes"`
		OutboundBytes    uint32 `json:"outbound_bytes"`
	}{
		Schema: "agentmemory.windows-active-runtime-clients.v1", State: snapshot.State,
		CurrentInstances: snapshot.CurrentInstances, MaximumInstances: snapshot.MaximumInstances,
		InboundBytes: snapshot.InboundBytes, OutboundBytes: snapshot.OutboundBytes,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return ActiveClientObservation{}, errors.New("Windows named-pipe evidence is unavailable")
	}
	evidence := sha256.Sum256(encoded)
	return ActiveClientObservation{
		Count: uint64(snapshot.CurrentInstances - 1), EvidenceDigest: runtimeinstall.Hash(evidence),
	}, nil
}

func inspectWindowsNamedPipe(path string) (windowsPipeSnapshot, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windowsPipeSnapshot{}, err
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0,
	)
	if err != nil {
		return windowsPipeSnapshot{}, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var snapshot windowsPipeSnapshot
	if err := windows.GetNamedPipeHandleState(
		handle, &snapshot.State, &snapshot.CurrentInstances, nil, nil, nil, 0,
	); err != nil {
		return windowsPipeSnapshot{}, err
	}
	if err := windows.GetNamedPipeInfo(
		handle, nil, &snapshot.OutboundBytes, &snapshot.InboundBytes, &snapshot.MaximumInstances,
	); err != nil {
		return windowsPipeSnapshot{}, err
	}
	return snapshot, nil
}
