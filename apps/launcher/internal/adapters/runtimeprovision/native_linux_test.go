//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
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
	if count, err := linuxSubordinateCount(filepath.Join(t.TempDir(), "missing"), "root"); err != nil || count != 0 {
		t.Fatalf("missing subordinate map = %d/%v", count, err)
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
	if _, _, err := linuxHomeFilesystem(filepath.Join(directory, "missing")); err == nil ||
		linuxUserSystemd(filepath.Join(directory, "missing"), uid) {
		t.Fatal("missing Linux owner filesystem/runtime directory was accepted")
	}
	unsafeFile := filepath.Join(directory, "unsafe-root-input")
	if err := os.WriteFile(unsafeFile, []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeFile, 0o666); err != nil { //nolint:gosec // G302: deliberate unsafe root-input fixture.
		t.Fatal(err)
	}
	if _, err := readRootOwnedRegular(unsafeFile, 64); err == nil {
		t.Fatal("unsafe root-owned input mode was accepted")
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
	cancelledHost, cancelHost := context.WithCancel(context.Background())
	cancelHost()
	if _, err := NewNativeHostProbe().ProbeLinuxHost(cancelledHost, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled host context error = %v", err)
	}
	if _, err := NewNativeHostProbe().ProbeLinuxHost(context.Background(), authority); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("mismatched invoking identity error = %v", err)
	}
	if _, err := NewNativeEndpointProbe().ProbeLinuxEndpoint(context.Background(), runtimeinstallZeroAuthority()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero endpoint authority error = %v", err)
	}
	if _, err := NewNativeEndpointProbe().ProbeLinuxEndpoint(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil endpoint context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewNativeEndpointProbe().ProbeLinuxEndpoint(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled endpoint context error = %v", err)
	}
}

func TestLinuxNativeHostProbeCollectsTheInvokingPrincipal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the signed rootless authority deliberately rejects uid 0")
	}
	distribution, version, err := linuxOSRelease()
	if err != nil || distribution != "ubuntu" || version != "24.04" {
		t.Skipf("the PF-001 Linux certification cell is Ubuntu 24.04; host=%s/%s error=%v", distribution, version, err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, uidError := strconv.ParseUint(current.Uid, 10, 32)
	gid, gidError := strconv.ParseUint(current.Gid, 10, 32)
	if uidError != nil || gidError != nil || uid == 0 || gid == 0 {
		t.Fatalf("invoking principal = %q/%q (%v/%v)", current.Uid, current.Gid, uidError, gidError)
	}
	if err := validateOwnerDirectory(current.HomeDir, uint32(uid), false); err != nil { // #nosec G115 -- parsed as uint32 above.
		t.Fatalf("invoking home is not owner-controlled: %v", err)
	}
	machine, err := linuxMachineDigest()
	if err != nil {
		t.Fatal(err)
	}
	_, template := adapterAuthority(t)
	packages := make([]runtimeport.PackageInput, 0, len(template.Packages()))
	for _, item := range template.Packages() {
		packages = append(packages, runtimeport.PackageInput{
			Name: item.Name(), Version: item.Version(), Purpose: item.Purpose(), RepositoryID: item.RepositoryID(),
			NativeReceiptDigest: item.NativeReceiptDigest(),
		})
	}
	repository := template.Repository()
	architecture := runtimeinstall.ArchitectureAMD64
	if runtime.GOARCH == "arm64" {
		architecture = runtimeinstall.ArchitectureARM64
	}
	input := runtimeport.LinuxAuthorityInput{
		PlanDigest: template.PlanDigest(), CatalogDigest: template.CatalogDigest(), TermsDigest: template.TermsDigest(),
		TermsID: template.TermsID(), TermsVersion: template.TermsVersion(), TermsURL: template.TermsURL(),
		TermsPresentation: template.TermsPresentation(),
		ArtifactDigest:    template.ArtifactDigest(),
		SigningKeyID:      "agentmemory-runtime-root-2026", Architecture: architecture,
		Distribution: distribution, VersionID: version, Codename: "noble", MinimumKernel: template.MinimumKernel(),
		MinimumCPUs: template.MinimumCPUs(), MinimumTotalMemory: template.MinimumTotalMemory(),
		MinimumAvailableMemory: template.MinimumAvailableMemory(), MinimumFreeDisk: template.MinimumFreeDisk(),
		PackageManager: template.PackageManager(), PackageManagerVersion: template.PackageManagerVersion(),
		Repository: runtimeport.RepositoryInput{
			ID: repository.ID(), URL: repository.URL(), Suite: repository.Suite(), Component: repository.Component(),
			SigningKeyFingerprint: repository.SigningKeyFingerprint(), SigningKeyDigest: repository.SigningKeyDigest(),
			ConfigurationDigest: repository.ConfigurationDigest(), MetadataDigest: repository.MetadataDigest(),
		},
		Packages: packages, RuntimeVersion: template.RuntimeVersion(), ComposeVersion: template.ComposeVersion(),
		InvokingUID: uint32(uid), InvokingGID: uint32(gid), AccountName: current.Username, // #nosec G115 -- parsed as uint32 above.
		PrincipalID: "linux:uid:" + strconv.FormatUint(uid, 10), MachineDigest: machine, HomeDirectory: current.HomeDir,
		RuntimeDirectory:   "/run/user/" + strconv.FormatUint(uid, 10),
		Endpoint:           "unix:///run/user/" + strconv.FormatUint(uid, 10) + "/docker.sock",
		SubordinateIDCount: 65536, SELinuxEnforcing: true, ServiceID: template.ServiceID(),
		ServiceUnitDigest: template.ServiceUnitDigest(), RootlessToolPath: template.RootlessToolPath(),
		DockerCLIPath: template.DockerCLIPath(), DockerCLISHA256: template.DockerCLISHA256(),
		ComposePluginPath: template.ComposePluginPath(), ComposePluginSHA256: template.ComposePluginSHA256(),
		PrivilegeToolPath: template.PrivilegeToolPath(), PrivilegeToolSHA256: template.PrivilegeToolSHA256(),
		PrivilegeToolPackage:              template.PrivilegeToolPackage(),
		PrivilegeToolPackageVersion:       template.PrivilegeToolPackageVersion(),
		PrivilegeToolPackageReceiptDigest: template.PrivilegeToolPackageReceiptDigest(),
		RPMKeysPath:                       template.RPMKeysPath(), RPMKeysSHA256: template.RPMKeysSHA256(),
		RootlessToolDigest: template.RootlessToolDigest(), ProbeImage: template.ProbeImage(),
		ProbeImageDigest: template.ProbeImageDigest(), ProbeContractVersion: template.ProbeContractVersion(),
		CapabilityPolicyDigest: template.CapabilityPolicyDigest(),
	}
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewNativeHostProbe().ProbeLinuxHost(context.Background(), authority)
	if err != nil || evidence.machineDigest != machine {
		t.Fatalf("native invoking-principal evidence = %+v/%v", evidence, err)
	}
}

func TestLinuxProcessTreeAndUnixPeerEvidence(t *testing.T) {
	ctx := context.Background()
	pid := uint32(os.Getpid()) // #nosec G115 -- Linux process IDs are nonnegative and bounded by uint32.
	uid := uint32(os.Getuid()) // #nosec G115 -- Linux user IDs are nonnegative uint32 values.
	processes, err := sameUserProcessTree(ctx, pid, uid)
	if err != nil && !errors.Is(err, ErrProbeFailed) {
		t.Fatal(err)
	} else if errors.Is(err, ErrProbeFailed) {
		t.Log("host procfs policy cannot prove the process tree; production remains fail-closed")
	} else if _, present := processes[pid]; !present {
		t.Fatal("current process missing from its own process tree")
	}
	if err == nil {
		_, err = processSocketInodes(ctx, processes)
	}
	if err != nil && !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("processSocketInodes() error = %v", err)
	} else if errors.Is(err, ErrProbeFailed) {
		t.Log("host procfs policy cannot prove process socket ownership; production remains fail-closed")
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

func TestLinuxProcessSocketInventoryReadsTheExactOwnedProcess(t *testing.T) {
	ctx := context.Background()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", filepath.Join(t.TempDir(), "inventory.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	pid := uint32(os.Getpid()) // #nosec G115 -- Linux process IDs are nonnegative and bounded by uint32.
	inodes, err := processSocketInodes(ctx, map[uint32]struct{}{pid: {}})
	if err != nil || len(inodes) == 0 {
		t.Fatalf("owned process socket inventory = %#v, %v", inodes, err)
	}
	if empty, err := processSocketInodes(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty process socket inventory = %#v, %v", empty, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := processSocketInodes(cancelled, map[uint32]struct{}{pid: {}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled process socket inventory error = %v", err)
	}
}

func TestLinuxProbeWorkspaceCleanupRejectsSubstitutionAndRemovesExactContent(t *testing.T) {
	plan, authority := adapterAuthority(t)
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
	if err := os.Chmod(parent, 0o700); err != nil { // #nosec G302 -- private test directory requires owner execute for traversal.
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "workspace")
	inputPath := filepath.Join(directory, "input.bin")
	content := []byte("agentmemory-probe-content")
	digest := runtimeinstall.Sum(content)
	uid := uint32(os.Getuid()) // #nosec G115 -- Linux user IDs are nonnegative uint32 values.
	if uid != 0 {
		gid := mustTestUint32(t, os.Getgid())
		runtimeDirectory := "/run/user/" + strconv.FormatUint(uint64(uid), 10)
		nativeAuthority := adapterLinuxAuthorityForIdentity(
			t, plan, 0, uid, gid, "/home/agentmemory", runtimeDirectory,
		)
		workspace, err := prepareNativeProbeWorkspaceAt(context.Background(), nativeAuthority, parent)
		if err != nil {
			t.Fatalf(
				"prepareNativeProbeWorkspaceAt() error = %v (authority=%t root=%v)",
				err, nativeAuthority.Valid(), validateOwnerDirectory(parent, uid, true),
			)
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
