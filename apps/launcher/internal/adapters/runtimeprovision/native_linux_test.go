//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxNativeHostProbesUseFixedTrustedSurfaces(t *testing.T) {
	if NewNativeHostProbe() == nil || NewNativeEndpointProbe() == nil {
		t.Fatal("native Linux probe constructors returned nil")
	}
	distribution, version, err := linuxOSRelease()
	if err != nil || !validOSReleaseToken(distribution) || !validOSReleaseToken(version) {
		t.Fatalf("linuxOSRelease() = %q/%q/%v", distribution, version, err)
	}
	kernel, architecture, err := linuxKernelArchitecture()
	if err != nil || !validKernel(kernel) || architecture == runtimeinstall.ArchitectureUnknown {
		t.Fatalf("linuxKernelArchitecture() = %q/%s/%v", kernel, architecture, err)
	}
	if digest, machineError := linuxMachineDigest(); machineError == nil && digest.IsZero() {
		t.Fatal("machine-id probe returned a zero digest")
	}
	if raw, readError := readRootOwnedRegular("/usr/lib/os-release", maximumOSReleaseBytes); readError != nil || len(raw) == 0 {
		t.Fatalf("root-owned os-release read = %d/%v", len(raw), readError)
	}
	if _, readError := readRootOwnedRegular("/usr/lib/os-release", 1); readError == nil {
		t.Fatal("bounded root-owned read accepted an oversized file")
	}
	cpus, total, available, err := linuxResources()
	if err != nil || cpus == 0 || total == 0 || available == 0 || available > total {
		t.Fatalf("linuxResources() = %d/%d/%d/%v", cpus, total, available, err)
	}
	free, _, err := linuxHomeFilesystem(t.TempDir())
	if err != nil || free == 0 {
		t.Fatalf("linuxHomeFilesystem() = %d/%v", free, err)
	}
	if _, err := linuxUserNamespaces(); err != nil {
		t.Fatalf("linuxUserNamespaces() error = %v", err)
	}
	if _, err := linuxSELinuxEnforcing(); err != nil {
		t.Fatalf("linuxSELinuxEnforcing() error = %v", err)
	}
	if _, err := linuxSubordinateCount("/etc/subuid", "root"); err != nil {
		t.Fatalf("linuxSubordinateCount() error = %v", err)
	}
	if _, err := linuxDockerGroupAbsent("agentmemory", uint32(os.Getgid())); err != nil { // #nosec G115 -- Linux group IDs are nonnegative uint32 values.
		t.Fatalf("linuxDockerGroupAbsent() error = %v", err)
	}
	directory := t.TempDir()
	uid := uint32(os.Getuid())                         // #nosec G115 -- Linux user IDs are nonnegative uint32 values.
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- runtime directories must be owner-only.
		t.Fatal(err)
	}
	if err := validateOwnerDirectory(directory, uid, true); err != nil {
		t.Fatalf("owner directory rejected: %v", err)
	}
	if linuxUserSystemd(directory, uid) {
		t.Fatal("ordinary temporary directory was accepted as a systemd runtime")
	}
	if err := os.Chmod(directory, 0o755); err != nil { // #nosec G302 -- intentionally creates a non-runtime mode for rejection testing.
		t.Fatal(err)
	}
	if validateOwnerDirectory(directory, uid, true) == nil || validateOwnerDirectory(directory, uid, false) != nil {
		t.Fatal("runtime-directory mode policy drifted")
	}

	_, authority := adapterAuthority(t)
	var nilContext context.Context
	if _, err := NewNativeHostProbe().ProbeLinuxHost(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil host context error = %v", err)
	}
	if _, err := NewNativeHostProbe().ProbeLinuxHost(context.Background(), authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("mismatched invoking identity error = %v", err)
	}
	if _, err := NewNativeEndpointProbe().ProbeLinuxEndpoint(context.Background(), runtimeinstallZeroAuthority()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero endpoint authority error = %v", err)
	}
}

func TestLinuxProcessTreeAndUnixPeerEvidence(t *testing.T) {
	ctx := context.Background()
	pid := uint32(os.Getpid()) // #nosec G115 -- Linux process IDs are nonnegative and bounded by uint32.
	uid := uint32(os.Getuid()) // #nosec G115 -- Linux user IDs are nonnegative uint32 values.
	processes, err := sameUserProcessTree(ctx, pid, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := processes[pid]; !present {
		t.Fatal("current process missing from its own process tree")
	}
	if _, err := processSocketInodes(ctx, processes); err != nil {
		t.Fatalf("processSocketInodes() error = %v", err)
	}
	socketPath := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	type acceptResult struct {
		connection net.Conn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		connection, acceptError := listener.Accept()
		accepted <- acceptResult{connection: connection, err: acceptError}
	}()
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("Unix socket omitted native stat evidence")
	}
	noTCP, err := endpointProcessTreeHasNoTCP(ctx, socketPath, uid, stat.Ino)
	result := <-accepted
	if result.connection != nil {
		_ = result.connection.Close()
	}
	if errors.Is(err, ErrProbeFailed) {
		t.Log("host process visibility cannot prove the fail-closed Unix peer contract")
	} else if result.err != nil || err != nil || !noTCP {
		t.Fatalf("Unix peer proof = noTCP:%t accept:%v probe:%v", noTCP, result.err, err)
	}
	if _, err := endpointProcessTreeHasNoTCP(ctx, socketPath+"-missing", uid, stat.Ino); err == nil {
		t.Fatal("missing Unix endpoint produced peer evidence")
	}
	if _, err := sameUserProcessTree(ctx, pid, uid+1); err == nil {
		t.Fatal("wrong process UID was accepted")
	}
}

func TestLinuxProbeWorkspaceCleanupRejectsSubstitutionAndRemovesExactContent(t *testing.T) {
	_, authority := adapterAuthority(t)
	var nilContext context.Context
	if _, err := prepareNativeProbeWorkspace(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil workspace context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareNativeProbeWorkspace(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled workspace context error = %v", err)
	}
	if _, err := prepareNativeProbeWorkspace(context.Background(), runtimeinstallZeroAuthority()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero workspace authority error = %v", err)
	}
	if err := writeAndSync(nil, []byte("content")); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("nil workspace file error = %v", err)
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "workspace")
	inputPath := filepath.Join(directory, "input.bin")
	content := []byte("agentmemory-probe-content")
	digest := runtimeinstall.Sum(content)
	uid := uint32(os.Getuid()) // #nosec G115 -- Linux user IDs are nonnegative uint32 values.
	if uid == authority.InvokingUID() {
		workspace, err := prepareNativeProbeWorkspace(context.Background(), authority)
		if err != nil {
			t.Fatalf("prepareNativeProbeWorkspace() error = %v", err)
		}
		if workspace.directory == "" || workspace.inputPath == "" || workspace.digest.IsZero() || workspace.cleanup == nil {
			t.Fatal("prepared workspace omitted authenticated cleanup evidence")
		}
		if err := workspace.cleanup(); err != nil {
			t.Fatalf("prepared workspace cleanup error = %v", err)
		}
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(inputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- test-owned private path.
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSync(file, content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeExistingProbeWorkspace(directory, inputPath, uid, digest); err != nil {
		t.Fatalf("removeExistingProbeWorkspace() error = %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace remained after cleanup: %v", err)
	}
	if err := removeExistingProbeWorkspace(directory, inputPath, uid, digest); err != nil {
		t.Fatalf("idempotent cleanup error = %v", err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil { // #nosec G301 -- intentionally creates an unsafe mode for rejection testing.
		t.Fatal(err)
	}
	if err := removeExistingProbeWorkspace(directory, inputPath, uid, digest); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("unsafe workspace error = %v", err)
	}
}

func runtimeinstallZeroAuthority() runtimeport.LinuxAuthority { return runtimeport.LinuxAuthority{} }
