//go:build darwin && cgo

package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDarwinDesktopNativeParsersAndClosedToolPolicy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		version string
		want    uint32
		valid   bool
	}{
		{version: "26", want: 26_000, valid: true},
		{version: "26.1", want: 26_100, valid: true},
		{version: "26.1.4", want: 26_104, valid: true},
		{version: "", valid: false},
		{version: "0", valid: false},
		{version: "26.1.4.1", valid: false},
		{version: "26.beta", valid: false},
		{version: "26.1000", valid: false},
	} {
		observed, err := numericDesktopBuild(test.version)
		if test.valid && (err != nil || observed != test.want) {
			t.Fatalf("numericDesktopBuild(%q) = %d, %v", test.version, observed, err)
		}
		if !test.valid && err == nil {
			t.Fatalf("numericDesktopBuild(%q) accepted invalid version", test.version)
		}
	}

	validPlist := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><dict><key>dev-entry</key><string>/dev/disk9</string><key>mount-point</key><string>/Volumes/Docker</string></dict></array></plist>`)
	if mount, err := parseHdiutilMountPoint(validPlist); err != nil || mount != "/Volumes/Docker" {
		t.Fatalf("mount point = %q, %v", mount, err)
	}
	for _, raw := range [][]byte{
		nil,
		[]byte(`<plist><dict><key>dev-entry</key><string>/dev/disk9</string></dict></plist>`),
		[]byte(`<plist><dict><key>mount-point</key><string></string></dict></plist>`),
		[]byte(`<plist><dict><key>mount-point</key><string>/Volumes/Docker</dict></plist>`),
	} {
		if _, err := parseHdiutilMountPoint(raw); err == nil {
			t.Fatalf("invalid hdiutil plist was accepted: %q", raw)
		}
	}

	for _, mount := range []string{"/Volumes/Docker", "/Volumes/Docker Desktop"} {
		if !safeMountPoint(mount) {
			t.Fatalf("safe mount rejected: %q", mount)
		}
	}
	for _, mount := range []string{"/Volumes", "/Volumes//Docker", "/Volumes/../tmp", "/tmp/Docker", "/Volumes/Docker\n"} {
		if safeMountPoint(mount) {
			t.Fatalf("unsafe mount accepted: %q", mount)
		}
	}
	if !safeNativeTool("/usr/bin/open") || safeNativeTool(filepath.Join(t.TempDir(), "open")) {
		t.Fatal("native tool ownership policy was not closed to root-owned regular files")
	}
	var nilContext context.Context
	if _, err := runDarwinNativeTool(nilContext, "/usr/bin/open", nil, "/var/empty", nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runDarwinNativeTool(cancelled, "/usr/bin/open", nil, "/var/empty", nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if _, err := runDarwinNativeTool(context.Background(), "/bin/sh", nil, "/var/empty", nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("ambient shell error = %v", err)
	}
}

func TestDarwinDesktopBoundedIOAndFilesystemEvidence(t *testing.T) {
	t.Parallel()
	buffer := &boundedNativeBuffer{maximum: 4}
	if written, err := buffer.Write([]byte("ab")); err != nil || written != 2 {
		t.Fatalf("first write = %d, %v", written, err)
	}
	if written, err := buffer.Write([]byte("cdef")); err != nil || written != 4 || !buffer.exceeded || string(buffer.bytes()) != "abcd" {
		t.Fatalf("overflow write = %d, %v, exceeded=%t, bytes=%q", written, err, buffer.exceeded, buffer.bytes())
	}
	copyOfBytes := buffer.bytes()
	copyOfBytes[0] = 'z'
	if string(buffer.bytes()) != "abcd" {
		t.Fatal("bounded buffer returned mutable storage")
	}
	if written, err := buffer.Write([]byte("ignored")); err != nil || written != len("ignored") || string(buffer.bytes()) != "abcd" {
		t.Fatalf("post-overflow write = %d, %v, %q", written, err, buffer.bytes())
	}

	filePath := filepath.Join(t.TempDir(), "artifact.bin")
	contents := []byte("bounded desktop artifact")
	if err := os.WriteFile(filePath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath) // #nosec G304 -- test opens its own private temporary file.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	digest, read, err := digestBoundedDesktopArtifact(context.Background(), file, uint64(len(contents)))
	if err != nil || read != uint64(len(contents)) || digest != runtimeinstall.Sum(contents) {
		t.Fatalf("artifact digest = %s bytes=%d err=%v", digest, read, err)
	}
	if _, _, err := digestBoundedDesktopArtifact(context.Background(), nil, 1); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil artifact error = %v", err)
	}
	if _, _, err := digestBoundedDesktopArtifact(context.Background(), file, uint64(len(contents))-1); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("oversized artifact error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := digestBoundedDesktopArtifact(cancelled, file, uint64(len(contents))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled artifact error = %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	free, local, err := darwinDesktopFilesystem(home)
	if err != nil || free == 0 || !local {
		t.Fatalf("filesystem = free:%d local:%t err:%v", free, local, err)
	}
	if _, _, err := darwinDesktopFilesystem(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing filesystem target was accepted")
	}
	if machine, err := nativeDarwinMachineDigest(); err != nil || machine.IsZero() {
		t.Fatalf("machine digest = %s, %v", machine, err)
	}
	if available := nativeDarwinAvailableMemory(); available == 0 {
		t.Fatal("available memory probe returned zero")
	}
	_ = nativeDarwinEncrypted(home)
	if _, _, err := observeDarwinCatalogHost(CatalogObservationInput{HostStorageTarget: home}); err != nil &&
		!errors.Is(err, ErrUnsupportedHost) && !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("catalog host probe returned an unclassified error: %v", err)
	}
}

func TestDarwinDesktopNativeConstructorsAndInvalidBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	host, err := NewNativeDesktopHostProbe(DesktopHostProbeDependencies{})
	if err != nil || host == nil {
		t.Fatalf("host probe = %#v, %v", host, err)
	}
	if _, err := NewNativeDesktopHostProbe(DesktopHostProbeDependencies{WindowsEncryption: desktopEncryptionFake{}}); err == nil {
		t.Fatal("Darwin host probe accepted a Windows attestor")
	}
	if _, err := host.ProbeDesktopHost(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("zero authority host error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	if _, err := host.ProbeDesktopHost(cancelled, authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("cancelled host error = %v", err)
	}
	actualHome, homeError := os.UserHomeDir()
	if homeError != nil {
		t.Fatal(homeError)
	}
	actualAuthority := desktopDarwinAuthorityAtHome(t, authority, actualHome)
	if evidence, probeError := host.ProbeDesktopHost(context.Background(), actualAuthority); probeError == nil && evidence.Supports(actualAuthority) != nil {
		t.Fatal("native host probe returned unbound evidence")
	}

	if _, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{}); err == nil {
		t.Fatal("artifact verifier accepted missing provenance")
	}
	if _, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{
		Provenance: &desktopArtifactFake{authority: authority}, WindowsSigner: desktopWindowsSignerFake{},
	}); err == nil {
		t.Fatal("Darwin verifier accepted a Windows signer")
	}
	verifier, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{
		Provenance: &desktopArtifactFake{authority: authority},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyDesktopArtifact(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero artifact authority error = %v", err)
	}
	if _, err := verifier.VerifyDesktopArtifact(context.Background(), authority); err == nil {
		t.Fatal("missing retained DMG was verified")
	}
	artifact := []byte("not-a-real-signed-disk-image")
	artifactHome := filepath.Join(t.TempDir(), "artifact-home")
	if err := os.MkdirAll(filepath.Join(artifactHome, "Library", "Caches", "AgentMemory", "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifactAuthority := desktopDarwinAuthorityAtHome(t, authority, artifactHome, artifact)
	if err := os.WriteFile(artifactAuthority.ArtifactPath(), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	artifactVerifier, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{
		Provenance: &desktopArtifactFake{authority: artifactAuthority},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifactVerifier.VerifyDesktopArtifact(context.Background(), artifactAuthority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("unsigned disk image error=%v", err)
	}
	if file, err := openDarwinDesktopArtifact(authority); err == nil || file != nil {
		t.Fatal("missing signed artifact was opened")
	}
	if assessDarwinDiskImage(context.Background(), filepath.Join(t.TempDir(), "missing.dmg")) {
		t.Fatal("missing DMG passed Gatekeeper")
	}
	if verifyDarwinDockerApplication(context.Background(), filepath.Join(t.TempDir(), "Docker.app"), runtimeinstall.Sum([]byte("cert"))) {
		t.Fatal("missing application passed native signing validation")
	}
	if assessDarwinTarget(context.Background(), "/tmp/../tmp/target", "open") ||
		assessDarwinTarget(context.Background(), "/tmp/target", "ambient") {
		t.Fatal("Gatekeeper assessment accepted an unsafe target or ambient assessment type")
	}
	applicationProbe, err := NewNativeDesktopInstalledApplicationProbe(DesktopInstalledApplicationProbeDependencies{})
	if err != nil || applicationProbe == nil {
		t.Fatalf("installed application probe = %#v, %v", applicationProbe, err)
	}
	if _, err := NewNativeDesktopInstalledApplicationProbe(DesktopInstalledApplicationProbeDependencies{
		WindowsSigner: desktopWindowsApplicationSignerFake{},
	}); err == nil {
		t.Fatal("Darwin installed application probe accepted a Windows signer")
	}
	if _, err := applicationProbe.ProbeDesktopInstalledApplication(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero installed application authority error = %v", err)
	}
	if _, err := applicationProbe.ProbeDesktopInstalledApplication(cancelled, authority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("cancelled installed application error = %v", err)
	}
	// The host may or may not have Docker Desktop. The fake catalog certificate
	// must prevent either ambient installation from producing valid evidence.
	if evidence, err := applicationProbe.ProbeDesktopInstalledApplication(context.Background(), authority); err == nil && evidence.Present() {
		t.Fatal("ambient Docker Desktop matched a synthetic signed projection")
	}
	if _, err := attachDarwinDiskImage(context.Background(), authority); err == nil {
		t.Fatal("missing DMG attached")
	}
	if err := detachDarwinDiskImage(context.Background(), "/tmp/not-a-volume"); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("unsafe detach error = %v", err)
	}
	if err := detachDarwinDiskImage(context.Background(), "/Volumes/AgentMemory-Definitely-Not-Mounted"); err == nil {
		t.Fatal("nonexistent volume detached")
	}

	launcher, err := NewNativeDesktopRuntimeLauncher()
	if err != nil || launcher == nil {
		t.Fatalf("runtime launcher = %#v, %v", launcher, err)
	}
	if _, err := launcher.LaunchDesktopRuntime(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero launch authority error = %v", err)
	}
}

func TestDarwinDesktopProbeWorkspaceRequiresOwnerOnlyExpectedContent(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	base := filepath.Join(parent, "AgentMemory")
	if err := ensureDarwinDesktopProbeBase(base); err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinDesktopProbeDirectory(base); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "runtime-probe-test")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(directory, "input.bin")
	content := []byte("agentmemory-runtime-probe-v1\npolicy\n")
	file, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- test-owned private path.
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSyncDesktopProbe(file, content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeDarwinDesktopProbeWorkspace(directory, inputPath, runtimeinstall.Sum(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace cleanup error = %v", err)
	}
	if err := removeDarwinDesktopProbeWorkspace(directory, inputPath, runtimeinstall.Sum(content)); err != nil {
		t.Fatalf("idempotent workspace cleanup = %v", err)
	}
	if err := writeAndSyncDesktopProbe(nil, content); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("nil workspace file error = %v", err)
	}
	if err := os.Chmod(base, 0o755); err != nil { // #nosec G302 -- intentionally creates an unsafe mode for rejection testing.
		t.Fatal(err)
	}
	if err := validateDarwinDesktopProbeDirectory(base); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("public workspace mode error = %v", err)
	}
	var nilContext context.Context
	if _, err := prepareNativeDesktopProbeWorkspace(nilContext, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil workspace context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareNativeDesktopProbeWorkspace(cancelled, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled workspace context error = %v", err)
	}
	if _, err := prepareNativeDesktopProbeWorkspace(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero workspace authority error = %v", err)
	}
	_, baseAuthority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	fakeHome := filepath.Join(t.TempDir(), "private-home")
	if err := os.MkdirAll(filepath.Join(fakeHome, "Library", "Caches"), 0o700); err != nil {
		t.Fatal(err)
	}
	authority := desktopDarwinAuthorityAtHome(t, baseAuthority, fakeHome)
	workspace, err := prepareNativeDesktopProbeWorkspace(context.Background(), authority)
	if err != nil || !workspace.valid(desktopDockerCapabilityProjection(authority).workspacePrefix, "darwin") {
		t.Fatalf("native desktop workspace = %#v, %v", workspace, err)
	}
	observed, err := os.ReadFile(workspace.inputPath)
	if err != nil || runtimeinstall.Sum(observed) != workspace.digest {
		t.Fatalf("native desktop workspace content error = %v", err)
	}
	if err := workspace.cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinDesktopMutationExchangeIsOwnerOnlyCanonicalAndCleaned(t *testing.T) {
	_, desktop := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(
		home, "Library", "Application Support", "AgentMemory", "bootstrap",
		"native-exchange-test-"+runtimeinstall.Sum([]byte(t.Name())).String()[:12], "native",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(directory)) })
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- directory must be owner-only.
		t.Fatal(err)
	}
	helper := desktopDarwinHelperAuthority(t, desktop, directory)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"desktop-native-exchange-1", 1, runtimeport.DesktopMutationInstallRuntime, desktop,
		runtimeinstall.Sum([]byte("consent")), runtimeinstall.Sum([]byte("artifact")), runtimeport.Nonce{1},
		now, now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := createNativeDesktopMutationExchange(context.Background(), helper, request)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := os.ReadFile(exchange.requestPath)
	if err != nil || !bytes.Equal(requestBytes, request.CanonicalBytes()) {
		t.Fatalf("request exchange bytes match=%t err=%v", bytes.Equal(requestBytes, request.CanonicalBytes()), err)
	}
	requestInfo, err := os.Lstat(exchange.requestPath)
	if err != nil || requestInfo.Mode().Perm() != 0o600 || !requestInfo.Mode().IsRegular() {
		t.Fatalf("request mode = %v, %v", requestInfo, err)
	}
	receipt := desktopNativeMutationReceipt(t, request, now)
	if err := os.WriteFile(exchange.receiptPath, receipt.CanonicalBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exchange.receiptPath, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exchange.readReceipt(context.Background())
	if err != nil || !bytes.Equal(raw, receipt.CanonicalBytes()) {
		t.Fatalf("receipt read match=%t err=%v", bytes.Equal(raw, receipt.CanonicalBytes()), err)
	}
	raw[0] ^= 0xff
	again, err := readDarwinMutationReceiptOnce(exchange.receiptPath)
	if err != nil || bytes.Equal(raw, again) {
		t.Fatal("receipt read returned shared storage")
	}
	exchange.cleanup()
	if _, err := os.Lstat(exchange.requestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("request cleanup error = %v", err)
	}
	if _, err := os.Lstat(exchange.receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt cleanup error = %v", err)
	}

	if _, err := openDarwinMutationDirectory(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing exchange directory was opened")
	}
	if err := os.Chmod(directory, 0o755); err != nil { // #nosec G302 -- intentionally creates an unsafe mode for rejection testing.
		t.Fatal(err)
	}
	if _, err := openDarwinMutationDirectory(directory); err == nil {
		t.Fatal("group/world-accessible exchange directory was opened")
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- restores the required owner-only directory mode.
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "empty.receipt.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDarwinMutationReceiptOnce(filepath.Join(directory, "empty.receipt.json")); err == nil {
		t.Fatal("empty receipt was accepted")
	}
}

func TestDarwinDesktopMutationBrokerRejectsUnsignedUnavailableAndInvalidHelpers(t *testing.T) {
	t.Parallel()
	if _, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{}); err == nil {
		t.Fatal("mutation broker accepted missing helper authorities")
	}
	var typedNil *desktopHelperResolverFake
	if _, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
		Authority: typedNil, Publisher: desktopHelperPublisherFake{},
	}); err == nil {
		t.Fatal("mutation broker accepted typed-nil authority")
	}
	_, desktop := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"desktop-native-broker-1", 1, runtimeport.DesktopMutationInstallRuntime, desktop,
		runtimeinstall.Sum([]byte("consent")), runtimeinstall.Sum([]byte("artifact")), runtimeport.Nonce{2},
		now, now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		resolver  runtimeport.DesktopHelperAuthorityResolver
		publisher runtimeport.DesktopHelperPublisherVerifier
		want      error
	}{
		{name: "manifest unavailable", resolver: &desktopHelperResolverFake{err: errors.New("manifest details")}, publisher: desktopHelperPublisherFake{}, want: runtimeport.ErrDesktopMutationUnavailable},
		{name: "invalid helper authority", resolver: &desktopHelperResolverFake{}, publisher: desktopHelperPublisherFake{}, want: runtimeport.ErrDesktopMutationIntegrity},
		{name: "publisher rejected", resolver: &desktopHelperResolverFake{helper: desktopDarwinHelperAuthority(t, desktop, "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/missing/native")}, publisher: desktopHelperPublisherFake{err: errors.New("signer details")}, want: runtimeport.ErrDesktopMutationIntegrity},
		{name: "exchange unavailable", resolver: &desktopHelperResolverFake{helper: desktopDarwinHelperAuthority(t, desktop, "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/missing/native")}, publisher: desktopHelperPublisherFake{}, want: runtimeport.ErrDesktopMutationUnavailable},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			broker, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
				Authority: test.resolver, Publisher: test.publisher,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := broker.ExecuteDesktopMutation(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("ExecuteDesktopMutation() error = %v, want %v", err, test.want)
			}
		})
	}

	broker, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
		Authority: &desktopHelperResolverFake{}, Publisher: desktopHelperPublisherFake{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var nilContext context.Context
	if _, err := broker.ExecuteDesktopMutation(nilContext, request); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil context mutation error = %v", err)
	}
	if _, err := broker.ExecuteDesktopMutation(context.Background(), runtimeport.DesktopMutationRequest{}); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero request mutation error = %v", err)
	}
	if !desktopMutationNil(nil) || desktopMutationNil(desktopHelperPublisherFake{}) {
		t.Fatal("mutation dependency nil detector was incorrect")
	}
}

func TestDesktopMutationExchangeCallbacksFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := (nativeDesktopMutationExchange{}).readReceipt(context.Background()); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil read callback error = %v", err)
	}
	var mu sync.Mutex
	removed := []string{}
	exchange := nativeDesktopMutationExchange{
		requestPath: "request", receiptPath: "receipt",
		read: func(context.Context, string) ([]byte, error) { return []byte("receipt"), nil },
		remove: func(path string) error {
			mu.Lock()
			defer mu.Unlock()
			removed = append(removed, path)
			return errors.New("ignored cleanup detail")
		},
	}
	if raw, err := exchange.readReceipt(context.Background()); err != nil || string(raw) != "receipt" {
		t.Fatalf("callback read = %q, %v", raw, err)
	}
	exchange.cleanup()
	if !slices.Equal(removed, []string{"receipt", "request"}) {
		t.Fatalf("cleanup order = %v", removed)
	}
	(nativeDesktopMutationExchange{}).cleanup()
}

type desktopEncryptionFake struct{}

func (desktopEncryptionFake) AttestWindowsVolumeEncryption(context.Context, string) error { return nil }

type desktopWindowsSignerFake struct{}

func (desktopWindowsSignerFake) VerifyWindowsDesktopSigner(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return runtimeinstall.Sum([]byte("signer")), nil
}

type desktopWindowsApplicationSignerFake struct{}

func (desktopWindowsApplicationSignerFake) VerifyWindowsDesktopApplicationSigner(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	return runtimeinstall.Sum([]byte("application-signer")), nil
}

type desktopHelperResolverFake struct {
	helper runtimeport.DesktopHelperAuthority
	err    error
}

func (f *desktopHelperResolverFake) ResolveDesktopHelperAuthority(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopHelperAuthority, error) {
	return f.helper, f.err
}

type desktopHelperPublisherFake struct{ err error }

func (f desktopHelperPublisherFake) VerifyDesktopHelperPublisher(
	context.Context,
	runtimeport.DesktopHelperAuthority,
) error {
	return f.err
}

func desktopDarwinHelperAuthority(
	t testing.TB,
	desktop runtimeport.DesktopAuthority,
	exchangeDirectory string,
) runtimeport.DesktopHelperAuthority {
	t.Helper()
	helper, err := runtimeport.NewDesktopHelperAuthority(runtimeport.DesktopHelperAuthorityInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: desktop.Architecture(), PlanDigest: desktop.PlanDigest(),
		PrincipalID: desktop.PrincipalID(), MachineDigest: desktop.MachineDigest(),
		CanonicalPath: "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
		SHA256:        runtimeinstall.Sum([]byte("native-helper")), PublisherIdentity: "agentmemory-runtime-helper-2026",
		PublisherCertificate:  runtimeinstall.Sum([]byte("helper-certificate")),
		ReleaseManifestDigest: runtimeinstall.Sum([]byte("signed-release-manifest")), ExchangeDirectory: exchangeDirectory,
	})
	if err != nil {
		t.Fatal(err)
	}
	return helper
}

func desktopNativeMutationReceipt(
	t testing.TB,
	request runtimeport.DesktopMutationRequest,
	now time.Time,
) runtimeport.DesktopMutationReceipt {
	t.Helper()
	signature := bytes.Repeat([]byte{0x61}, 64)
	receipt, err := runtimeport.NewDesktopMutationReceipt(runtimeport.DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(), Nonce: request.Nonce(),
		PostState: request.ExpectedState(), CompletedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func desktopDarwinAuthorityAtHome(
	t testing.TB,
	base runtimeport.DesktopAuthority,
	home string,
	artifact ...[]byte,
) runtimeport.DesktopAuthority {
	t.Helper()
	publisher := base.Publisher()
	terms := base.Terms()
	artifactDigest, artifactBytes := base.ArtifactSHA256(), base.ArtifactBytes()
	if len(artifact) == 1 {
		artifactDigest, artifactBytes = runtimeinstall.Sum(artifact[0]), uint64(len(artifact[0]))
	}
	authority, err := runtimeport.NewDesktopAuthority(runtimeport.DesktopAuthorityInput{
		PlanDigest: base.PlanDigest(), CatalogDigest: base.CatalogDigest(), Platform: base.Platform(),
		Architecture: base.Architecture(), PrincipalID: "uid:" + strconv.Itoa(os.Geteuid()), UserName: base.UserName(),
		MachineDigest: base.MachineDigest(), HomeDirectory: home, OSProduct: base.OSProduct(),
		MinimumOSVersion: base.MinimumOSVersion(), MaximumOSVersion: base.MaximumOSVersion(),
		MinimumBuild: base.MinimumBuild(), MaximumBuild: base.MaximumBuild(), MinimumCPUs: base.MinimumCPUs(),
		MinimumTotalMemory: base.MinimumTotalMemory(), MinimumAvailableMemory: base.MinimumAvailableMemory(),
		MinimumFreeDisk: base.MinimumFreeDisk(), RuntimeVersion: base.RuntimeVersion(), EngineVersion: base.EngineVersion(),
		ComposeVersion: base.ComposeVersion(), Endpoint: "unix://" + home + "/.docker/run/docker.sock",
		ArtifactPath:   filepath.Join(home, "Library", "Caches", "AgentMemory", "runtime", "Docker.dmg"),
		ArtifactSHA256: artifactDigest, ArtifactBytes: artifactBytes,
		ArtifactSourceURL: base.ArtifactSourceURL(),
		Publisher: runtimeport.DesktopPublisherInput{
			Kind: publisher.Kind(), Identity: publisher.Identity(), SigningKeyIdentity: publisher.SigningKeyIdentity(),
			PackageIdentity: publisher.PackageIdentity(), CertificateSHA256: publisher.CertificateSHA256(),
		},
		Terms:              runtimeport.DesktopTermsInput{ID: terms.ID(), Version: terms.Version(), URL: terms.URL(), Digest: terms.Digest()},
		InstallerArguments: []string{"--accept-license", "--user=" + base.UserName()},
		ApplicationPath:    base.ApplicationPath(), ApplicationExecutable: base.ApplicationExecutable(),
		DockerCLIPath: base.DockerCLIPath(), ComposePluginPath: base.ComposePluginPath(),
		DockerCLISHA256: base.DockerCLISHA256(), ComposePluginSHA256: base.ComposePluginSHA256(),
		ProbeImage: base.ProbeImage(), ProbeImageDigest: base.ProbeImageDigest(), ProbeContractVersion: base.ProbeContractVersion(),
		UnrelatedWorkloads: base.UnrelatedWorkloads(), CapabilityPolicyDigest: base.CapabilityPolicyDigest(),
		VendorUIMandatory: base.VendorUIMandatory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestDarwinReceiptPollingHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readDarwinMutationReceipt(ctx, filepath.Join(t.TempDir(), "missing.receipt.json"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("receipt polling cancellation = %v", err)
	}
}

func TestDarwinNativeHelpersRejectAmbientPathsWithoutPrompt(t *testing.T) {
	t.Parallel()
	_, desktop := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	helper := desktopDarwinHelperAuthority(
		t, desktop, "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/missing/native",
	)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := executeNativeDesktopHelper(cancelled, helper, filepath.Join(helper.ExchangeDirectory(), "request.json"), runtimeport.DesktopMutationInstallRuntime); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("cancelled helper error = %v", err)
	}
	if err := executeNativeDesktopHelper(context.Background(), helper, "/tmp/request.json", runtimeport.DesktopMutationInstallRuntime); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("ambient helper path error = %v", err)
	}
	if verifyDarwinMutationHelper(context.Background(), helper) {
		t.Fatal("missing fixed helper passed retained-file verification")
	}
}
