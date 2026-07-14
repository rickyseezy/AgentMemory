//go:build windows

package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestWindowsDesktopNativeOutputParsersAreClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		output  []byte
		enabled bool
		valid   bool
	}{
		{name: "enabled", output: []byte("Feature Name : VirtualMachinePlatform\r\nState : Enabled\r\n"), enabled: true, valid: true},
		{name: "disabled", output: []byte("State : Disabled\r\n"), valid: true},
		{name: "enable pending", output: []byte("State : Enable Pending\r\n"), valid: true},
		{name: "disable pending", output: []byte("State : Disable Pending\r\n"), valid: true},
		{name: "unknown", output: []byte("State : Unknown\r\n")},
		{name: "localized", output: []byte("Etat : Enabled\r\n")},
		{name: "case drift", output: []byte("State : enabled\r\n")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			enabled, err := parseDISMFeatureState(test.output)
			if test.valid && (err != nil || enabled != test.enabled) {
				t.Fatalf("DISM state = %t, %v", enabled, err)
			}
			if !test.valid && !errors.Is(err, ErrProvisionIntegrity) {
				t.Fatalf("invalid DISM state error = %v", err)
			}
		})
	}

	utf16Output := windowsUTF16LE("WSL version: 2.1.5.0\r\nKernel version: 6.6.36.6\r\n")
	for _, test := range []struct {
		name    string
		output  []byte
		want    string
		wantErr bool
	}{
		{name: "UTF-8", output: []byte("WSL version: 2.1.5\r\n"), want: "2.1.5"},
		{name: "UTF-16", output: utf16Output, want: "2.1.5"},
		{name: "absent", output: []byte("Kernel version: 6.6.36.6\r\n")},
		{name: "short", output: []byte("WSL version: 2.1\r\n"), wantErr: true},
		{name: "long", output: []byte("WSL version: 2.1.5.9.1\r\n"), wantErr: true},
		{name: "non-numeric", output: []byte("WSL version: 2.one.5\r\n"), wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observed, err := parseWSLVersion(test.output)
			if test.wantErr && !errors.Is(err, ErrProvisionIntegrity) {
				t.Fatalf("invalid WSL version error = %v", err)
			}
			if !test.wantErr && (err != nil || observed != test.want) {
				t.Fatalf("WSL version = %q, %v", observed, err)
			}
		})
	}
}

func TestWindowsDesktopBoundedIOAndArtifactDigest(t *testing.T) {
	t.Parallel()
	buffer := &windowsBoundedBuffer{maximum: 4}
	if written, err := buffer.Write([]byte("ab")); err != nil || written != 2 {
		t.Fatalf("first write = %d, %v", written, err)
	}
	if written, err := buffer.Write([]byte("cdef")); err != nil || written != 4 || !buffer.exceeded ||
		string(buffer.bytes()) != "abcd" {
		t.Fatalf("overflow write = %d, %v, exceeded=%t, bytes=%q", written, err, buffer.exceeded, buffer.bytes())
	}
	copyOfBytes := buffer.bytes()
	copyOfBytes[0] = 'z'
	if string(buffer.bytes()) != "abcd" {
		t.Fatal("bounded buffer returned mutable storage")
	}
	if written, err := buffer.Write([]byte("ignored")); err != nil || written != len("ignored") {
		t.Fatalf("post-overflow write = %d, %v", written, err)
	}

	content := []byte("signed-windows-desktop-artifact")
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path) // #nosec G304 -- test opens its own private temporary file.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	digest, read, err := digestWindowsDesktopArtifact(context.Background(), file, uint64(len(content)))
	if err != nil || digest != runtimeinstall.Sum(content) || read != uint64(len(content)) {
		t.Fatalf("artifact digest = %s bytes=%d err=%v", digest, read, err)
	}
	if _, _, err := digestWindowsDesktopArtifact(context.Background(), nil, 1); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil artifact error = %v", err)
	}
	if _, _, err := digestWindowsDesktopArtifact(context.Background(), file, uint64(len(content))-1); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("oversized artifact error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := digestWindowsDesktopArtifact(cancelled, file, uint64(len(content))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled artifact error = %v", err)
	}
	reader := &contextReader{ctx: context.Background(), reader: bytes.NewReader(content)}
	observed := make([]byte, len(content))
	if read, err := reader.Read(observed); err != nil || read != len(content) || !bytes.Equal(observed, content) {
		t.Fatalf("context reader = %d, %v, %q", read, err, observed)
	}
}

func TestWindowsDesktopNativeBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewNativeDesktopHostProbe(DesktopHostProbeDependencies{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("missing encryption attestor error = %v", err)
	}
	if _, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("missing artifact dependencies error = %v", err)
	}
	if _, err := NewNativeDesktopInstalledApplicationProbe(DesktopInstalledApplicationProbeDependencies{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("missing application signer error = %v", err)
	}
	launcher, err := NewNativeDesktopRuntimeLauncher()
	if err != nil || launcher == nil {
		t.Fatalf("runtime launcher = %#v, %v", launcher, err)
	}
	if _, err := launcher.LaunchDesktopRuntime(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("invalid launch authority error = %v", err)
	}
	var nilContext context.Context
	if _, err := prepareNativeDesktopProbeWorkspace(nilContext, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil workspace context error = %v", err)
	}
	if _, err := prepareNativeDesktopProbeWorkspace(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("invalid workspace authority error = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.exe")
	if verifyWindowsAuthenticode(missing) {
		t.Fatal("missing executable passed Authenticode")
	}
	if version, err := windowsDesktopFileVersion(missing); err == nil || version != "" {
		t.Fatalf("missing executable version = %q, %v", version, err)
	}
}

func windowsUTF16LE(value string) []byte {
	characters := utf16.Encode([]rune(value))
	result := make([]byte, 2, 2+len(characters)*2)
	result[0], result[1] = 0xff, 0xfe
	for _, character := range characters {
		result = binary.LittleEndian.AppendUint16(result, character)
	}
	return result
}
