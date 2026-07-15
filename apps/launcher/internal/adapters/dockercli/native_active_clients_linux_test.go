//go:build linux

package dockercli

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

const procUnixHeader = "Num       RefCount Protocol Flags    Type St Inode Path\n"

func TestPF001LinuxActiveRuntimeClientScannerCountsExactSocketConnections(t *testing.T) {
	t.Parallel()
	raw := procUnixHeader +
		linuxSocketRecord("00000001", "00000002", "00000000", "00010000", "0001", "01", "100", "/run/user/1000/docker.sock") + "\n" +
		linuxSocketRecord("00000002", "00000003", "00000000", "00000000", "0001", "03", "101", "/run/user/1000/docker.sock") + "\n" +
		linuxSocketRecord("00000003", "00000003", "00000000", "00000000", "0001", "03", "101", "/run/user/1000/docker.sock") + "\n" +
		linuxSocketRecord("00000004", "00000003", "00000000", "00000000", "0001", "03", "102", "/run/user/1000/other.sock") + "\n" +
		"00000005: 00000002 00000000 00000000 0001 03 103\n"
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	scanner := &NativeActiveRuntimeClientScanner{read: func() ([]byte, error) { return []byte(raw), nil }}
	observation, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint)
	if err != nil || observation.Count != 1 || observation.EvidenceDigest.IsZero() {
		t.Fatalf("observation = %+v/%v", observation, err)
	}
}

func TestPF001LinuxActiveRuntimeClientScannerFailsClosedOnAmbiguousKernelState(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	for name, raw := range map[string]string{
		"header": "unsupported\n",
		"missing listener": procUnixHeader +
			linuxSocketRecord("00000001", "00000002", "00000000", "00000000", "0001", "03", "100", "/run/user/1000/docker.sock") + "\n",
		"duplicate listener": procUnixHeader +
			linuxSocketRecord("00000001", "00000002", "00000000", "00010000", "0001", "01", "100", "/run/user/1000/docker.sock") + "\n" +
			linuxSocketRecord("00000002", "00000002", "00000000", "00010000", "0001", "01", "101", "/run/user/1000/docker.sock") + "\n",
		"datagram": procUnixHeader +
			linuxSocketRecord("00000001", "00000002", "00000000", "00010000", "0002", "01", "100", "/run/user/1000/docker.sock") + "\n",
		"state": procUnixHeader +
			linuxSocketRecord("00000001", "00000002", "00000000", "00010000", "0001", "04", "100", "/run/user/1000/docker.sock") + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			scanner := &NativeActiveRuntimeClientScanner{read: func() ([]byte, error) { return []byte(raw), nil }}
			if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
				t.Fatal("ambiguous kernel state was accepted")
			}
		})
	}
	scanner := &NativeActiveRuntimeClientScanner{read: func() ([]byte, error) { return nil, errors.New("denied") }}
	if _, err := scanner.ScanActiveRuntimeClients(context.Background(), endpoint); err == nil {
		t.Fatal("unreadable kernel table was accepted")
	}
}
