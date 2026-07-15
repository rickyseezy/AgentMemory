//go:build darwin && cgo

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

func TestPF001DarwinDesktopMutationMachineKeyStoreBindsExactOwnerBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	uid := uint32(os.Getuid()) // #nosec G115 -- Darwin uid_t fixture.
	gid := uint32(os.Getgid()) // #nosec G115 -- Darwin gid_t fixture.
	lockPath := filepath.Join(root, "receipt.lock")
	lock, err := openDarwinDesktopMutationKeyLockAt(lockPath, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	privatePath := filepath.Join(root, "receipt.key")
	private, err := loadOrCreateDarwinDesktopMutationPrivateKeyAt(privatePath, root, uid, gid)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatalf("private bytes=%d error=%v", len(private), err)
	}
	reopened, err := loadOrCreateDarwinDesktopMutationPrivateKeyAt(privatePath, root, uid, gid)
	if err != nil || !bytes.Equal(private, reopened) {
		t.Fatalf("reopened key matches=%t error=%v", bytes.Equal(private, reopened), err)
	}
	public := append(ed25519.PublicKey(nil), private[ed25519.SeedSize:]...)
	publicPath := filepath.Join(root, "receipt.pub")
	if err := ensureDarwinDesktopMutationPublicKeyAt(publicPath, root, public, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := ensureDarwinDesktopMutationPublicKeyAt(publicPath, root, public, uid, gid); err != nil {
		t.Fatalf("idempotent public key error=%v", err)
	}
	read, err := readExactDarwinDesktopMutationKey(publicPath, ed25519.PublicKeySize, 0o444, uid, gid)
	if err != nil || !bytes.Equal(read, public) {
		t.Fatalf("public key matches=%t error=%v", bytes.Equal(read, public), err)
	}
	foreignPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDarwinDesktopMutationPublicKeyAt(publicPath, root, foreignPublic, uid, gid); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("foreign public key error=%v", err)
	}
	if _, err := readExactDarwinDesktopMutationKey(publicPath, ed25519.PublicKeySize+1, 0o444, uid, gid); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("wrong size error=%v", err)
	}
	if err := writeExactDarwinDesktopMutationKey(filepath.Join(root, "wrong.key"), t.TempDir(), private, 0o600); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("foreign directory error=%v", err)
	}
	if err := writeExactDarwinDesktopMutationKey(privatePath, root, private, 0o600); err == nil {
		t.Fatal("existing private key was replaced")
	}
	clear(private)
	clear(reopened)
}

func TestPF001DarwinDesktopMutationMachineKeyStoreRejectsCorruptAndLinkedFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	uid := uint32(os.Getuid()) // #nosec G115 -- Darwin uid_t fixture.
	gid := uint32(os.Getgid()) // #nosec G115 -- Darwin gid_t fixture.
	privatePath := filepath.Join(root, "receipt.key")
	if err := os.WriteFile(privatePath, bytes.Repeat([]byte{0x5a}, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if private, err := loadOrCreateDarwinDesktopMutationPrivateKeyAt(privatePath, root, uid, gid); len(private) != 0 ||
		!errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("corrupt private bytes=%d error=%v", len(private), err)
	}
	linked := filepath.Join(root, "linked.key")
	if err := os.Symlink(privatePath, linked); err != nil {
		t.Fatal(err)
	}
	if value, err := readExactDarwinDesktopMutationKey(linked, ed25519.PrivateKeySize, 0o600, uid, gid); len(value) != 0 || err == nil {
		t.Fatalf("linked key bytes=%d error=%v", len(value), err)
	}
}

func TestPF001DarwinDesktopHelperFilePrimitivesBindExactDescriptorBytes(t *testing.T) {
	t.Parallel()
	contents := []byte("signed helper fixture")
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, contents, 0o700); err != nil { // #nosec G306 -- executable-mode helper fixture.
		t.Fatal(err)
	}
	if !safeDarwinDesktopMutationExecutable(path) {
		t.Fatal("owner executable was rejected")
	}
	file, err := os.Open(path) // #nosec G304 -- path is created under this test's private temporary root.
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestDarwinDesktopHelper(file, int64(len(contents)))
	_ = file.Close()
	if err != nil || digest != runtimeinstall.Sum(contents) {
		t.Fatalf("digest=%s error=%v", digest, err)
	}
	if digest, err := digestDarwinDesktopHelper(nil, 0); !digest.IsZero() || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil digest=%s error=%v", digest, err)
	}
	if !validDarwinDesktopHelperTeamID("9BNSXJN65R") || validDarwinDesktopHelperTeamID("9bnsxjn65r") ||
		validDarwinDesktopHelperTeamID("SHORT") {
		t.Fatal("Developer ID team validation is not closed")
	}
	if darwinDesktopMutationHelperDigestMatches(t.Context(), path, digest) {
		t.Fatal("non-root helper was accepted as installed authority")
	}
}

func TestPF001DarwinDesktopHelperSelfReachesNativeCodeTrustOnlyAfterExactReleaseBinding(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	platform, err := releaseinventory.NewPlatform("darwin", authority.Architecture().String())
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "runtime-helper-darwin-arm64", Kind: releaseinventory.ResourceKindHelper,
		Purpose: releaseinventory.ResourcePurposeNativeHelper, MediaType: releaseinventory.MediaTypeNativeExecutable,
		Platform: platform, Digest: releaseinventory.DigestBytes([]byte("helper")), Size: 4096,
		SourceRef:               "bundle://runtime-helper-darwin-arm64",
		SourceAllowlist:         []string{"bundle://runtime-helper-darwin-arm64"},
		CycloneDXSBOMResourceID: "helper-cyclonedx", SPDXSBOMResourceID: "helper-spdx",
		ProvenanceResourceID: "helper-provenance", LicenseResourceID: "helper-license",
		VulnerabilityResourceID: "helper-vulnerability",
		NativePublisherIdentity: "teamid:9BNSXJN65R", NativePublisherPolicyID: "agentmemory-developer-id-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewNativeDesktopHelperExecutableVerifier(map[string]releaseinventory.Digest{
		resource.ID(): releaseinventory.DigestBytes([]byte("leaf certificate")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if certificate, certError := verifier.expectedCertificate(resource, authority); certError != nil || certificate.IsZero() {
		t.Fatalf("certificate=%s error=%v", certificate, certError)
	}
	if digest, verifyError := verifier.VerifyDesktopHelperSelf(t.Context(), resource, authority); !digest.IsZero() ||
		!errors.Is(verifyError, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("uninstalled helper digest=%s error=%v", digest, verifyError)
	}
	created := filepath.Join(t.TempDir(), "root-owned")
	if err := ensureDarwinDesktopMutationDirectory(created, 0o700); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("unprivileged root directory error=%v", err)
	}
}

func TestPF001DarwinDesktopHelperArtifactPrimitivesRejectOwnerAndModeSubstitution(t *testing.T) {
	t.Parallel()
	contents := []byte("installer")
	digest := runtimeinstall.Sum(contents)
	path := filepath.Join(t.TempDir(), "installer.dmg")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid()) // #nosec G115 -- Darwin uid_t fixture.
	if !darwinDesktopMutationDescriptorMatches(descriptor, uid, uint64(len(contents)), 0o600) {
		t.Fatal("exact descriptor did not match")
	}
	_ = unix.Close(descriptor)
	if !darwinDesktopMutationArtifactMatches(path, uid, digest, uint64(len(contents))) ||
		darwinDesktopMutationArtifactMatches(path, uid, runtimeinstall.Sum([]byte("foreign")), uint64(len(contents))) {
		t.Fatal("artifact byte binding failed")
	}
	if parsed, ok := darwinDesktopMutationPrincipalUID("uid:501"); !ok || parsed != 501 {
		t.Fatalf("principal parsed=%d ok=%t", parsed, ok)
	}
	if _, ok := darwinDesktopMutationPrincipalUID("root"); ok {
		t.Fatal("foreign principal accepted")
	}
	if status, ok := infoSyscallStat(nil); ok || status != nil {
		t.Fatalf("nil stat=%+v ok=%t", status, ok)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := removeDarwinDesktopMutationTemporary(missing); err != nil {
		t.Fatalf("missing temporary error=%v", err)
	}
	if err := removeDarwinDesktopMutationTemporary(path); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("unprivileged temporary error=%v", err)
	}
}

func TestPF001DarwinDesktopHelperProductionConstructorsFailClosedWithoutElevationOrAuthority(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("helper"), 0o700); err != nil { // #nosec G306 -- executable-mode constructor fixture.
		t.Fatal(err)
	}
	keys, err := NewProtectedDesktopMutationReceiptPublicKeySource(path)
	if err != nil || keys == nil {
		t.Fatalf("public key source=%+v error=%v", keys, err)
	}
	if key, err := keys.LoadDesktopMutationPublicKey(t.Context(), runtimeinstall.Sum([]byte("helper"))); len(key) != 0 || !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("uninstalled helper key=%x error=%v", key, err)
	}
	if source, err := NewProtectedDesktopMutationReceiptPublicKeySource("relative"); source != nil || !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("relative source=%+v error=%v", source, err)
	}
	signer, err := NewNativeDesktopMutationReceiptSigner()
	if err != nil || signer == nil {
		t.Fatalf("signer=%+v error=%v", signer, err)
	}
	if os.Geteuid() != 0 {
		if key, err := (protectedDesktopMutationSigningKeySource{}).LoadDesktopMutationSigningKey(t.Context()); len(key) != 0 || !errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("unelevated signing key=%x error=%v", key, err)
		}
	}
	verifier, err := NewNativeDesktopHelperExecutableVerifier(map[string]releaseinventory.Digest{
		"runtime-helper-darwin-arm64": releaseinventory.DigestBytes([]byte("certificate")),
	})
	if err != nil || verifier == nil {
		t.Fatalf("verifier=%+v error=%v", verifier, err)
	}
	if digest, err := verifier.VerifyDesktopHelperSelf(t.Context(), releaseinventory.Resource{}, runtimeport.DesktopAuthority{}); !digest.IsZero() ||
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero self digest=%s error=%v", digest, err)
	}
	if verifier, err := NewNativeDesktopHelperExecutableVerifier(nil); verifier != nil || err == nil {
		t.Fatalf("nil certificates verifier=%+v error=%v", verifier, err)
	}
}

func TestPF001DarwinDesktopHelperNativeBackendsRejectUnverifiedInputsBeforeProcesses(t *testing.T) {
	t.Parallel()
	runner := &desktopMutationRunnerStub{}
	backend := newNativeDesktopMutationBackend(runner, desktopMutationReleaseSourceStub{})
	_, windowsAuthority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	request := desktopArtifactRequest(t, windowsAuthority, runtimeport.DesktopMutationInstallRuntime)
	if code, err := backend.ExecuteNativeDesktopMutation(
		t.Context(), request, DesktopMutationArtifactBinding{}, false, DesktopMutationAuthorityEvidence{},
	); code != 0 || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign backend code=%d error=%v", code, err)
	}
	if mount, err := attachDarwinDesktopMutationImage(t.Context(), "relative.dmg", t.TempDir()); mount.mountPoint != "" ||
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("relative mount=%+v error=%v", mount, err)
	}
	if safeDarwinDesktopMutationExecutable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing executable accepted")
	}
	copier := newNativeDesktopMutationArtifactCopier()
	if err := copier.CopyDesktopMutationArtifact(
		context.Background(), request, DesktopMutationTransactionArtifact{},
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign artifact copy error=%v", err)
	}
}

func TestPF001DarwinDesktopRemovalUsesOnlyVendorUninstallerAndBoundTrashTarget(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationRemoveRuntime)
	uninstaller, target, err := darwinDesktopRemovalPaths(request)
	if err != nil || uninstaller != "/Applications/Docker.app/Contents/MacOS/uninstall" ||
		target != filepath.Join(authority.HomeDirectory(), ".Trash", "Docker.app.agentmemory-"+request.Digest().String()) {
		t.Fatalf("uninstaller=%q target=%q error=%v", uninstaller, target, err)
	}
	install := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
	if _, _, err := darwinDesktopRemovalPaths(install); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("install request accepted as removal: %v", err)
	}
}

func TestPF001DarwinDesktopRemovalPrimitivesRejectUntrustedStateBeforeMutation(t *testing.T) {
	t.Parallel()
	trash := filepath.Join(t.TempDir(), "Trash")
	uid := uint32(os.Getuid()) // #nosec G115 -- Darwin uid_t fixture.
	if uid != 0 {
		if err := ensureDarwinDesktopTrashDirectory(trash, uid); err != nil {
			t.Fatalf("private trash directory error=%v", err)
		}
		if err := ensureDarwinDesktopTrashDirectory(trash, uid); err != nil {
			t.Fatalf("idempotent private trash directory error=%v", err)
		}
	}
	if err := ensureDarwinDesktopTrashDirectory("relative", uid); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("relative trash error=%v", err)
	}
	symlink := filepath.Join(t.TempDir(), "Trash")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatal(err)
	}
	if err := ensureDarwinDesktopTrashDirectory(symlink, uid); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("linked trash error=%v", err)
	}
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	removal := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationRemoveRuntime)
	if err := moveDarwinDesktopApplicationToTrash(t.Context(), removal, "/tmp/foreign"); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign trash target error=%v", err)
	}
	backend := nativeDesktopMutationBackend{
		runner: &desktopMutationRunnerStub{},
		applicationVersion: func(context.Context, string, runtimeinstall.Hash) (string, bool) {
			return "", false
		},
		safeExecutable: func(string) bool { return false },
		assessTarget:   func(context.Context, string, string) bool { return false },
		moveApplication: func(context.Context, runtimeport.DesktopMutationRequest, string) error {
			return runtimeport.ErrDesktopMutationIntegrity
		},
		attachImage: func(context.Context, string, string) (darwinDiskImageMount, error) {
			return darwinDiskImageMount{}, runtimeport.ErrDesktopMutationIntegrity
		},
		detachImage: func(context.Context, string) error { return nil },
	}
	if _, err := backend.installDarwinDesktopRuntime(
		t.Context(), authority, DesktopMutationArtifactBinding{}, false,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("missing installer error=%v", err)
	}
	if _, err := backend.removeDarwinDesktopRuntime(
		t.Context(), removal, DesktopMutationArtifactBinding{}, true,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("transported removal artifact error=%v", err)
	}
}

func TestPF001DarwinDesktopRemovalExecutesClosedCommandThenMovesVerifiedBundle(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationRemoveRuntime)
	runner := &darwinDesktopRemovalRunner{}
	moved := ""
	backend := nativeDesktopMutationBackend{
		runner: runner,
		applicationVersion: func(context.Context, string, runtimeinstall.Hash) (string, bool) {
			return authority.RuntimeVersion(), true
		},
		safeExecutable: func(path string) bool {
			return path == "/Applications/Docker.app/Contents/MacOS/uninstall"
		},
		assessTarget: func(_ context.Context, path, operation string) bool {
			return path == "/Applications/Docker.app/Contents/MacOS/uninstall" && operation == "execute"
		},
		moveApplication: func(_ context.Context, got runtimeport.DesktopMutationRequest, target string) error {
			if got.Digest() != request.Digest() {
				return errors.New("request substitution")
			}
			moved = target
			return nil
		},
		attachImage: func(context.Context, string, string) (darwinDiskImageMount, error) {
			return darwinDiskImageMount{}, runtimeport.ErrDesktopMutationIntegrity
		},
		detachImage: func(context.Context, string) error { return nil },
	}
	exitCode, err := backend.removeDarwinDesktopRuntime(
		t.Context(), request, DesktopMutationArtifactBinding{}, false,
	)
	_, wantedTarget, _ := darwinDesktopRemovalPaths(request)
	if err != nil || exitCode != 0 || runner.calls != 1 ||
		runner.command.Executable() != "/Applications/Docker.app/Contents/MacOS/uninstall" ||
		len(runner.command.Arguments()) != 0 || moved != wantedTarget {
		t.Fatalf("exit=%d calls=%d command=%+v moved=%q error=%v", exitCode, runner.calls, runner.command, moved, err)
	}
	runner.exitCode = 17
	moved = ""
	exitCode, err = backend.removeDarwinDesktopRuntime(
		t.Context(), request, DesktopMutationArtifactBinding{}, false,
	)
	if err != nil || exitCode != 17 || moved != "" {
		t.Fatalf("nonzero exit=%d moved=%q error=%v", exitCode, moved, err)
	}
	runner.exitCode = 0
	backend.moveApplication = func(context.Context, runtimeport.DesktopMutationRequest, string) error {
		return errors.New("trash unavailable")
	}
	if _, err := backend.removeDarwinDesktopRuntime(
		t.Context(), request, DesktopMutationArtifactBinding{}, false,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("move failure error=%v", err)
	}
}

func TestPF001DarwinDesktopInstallExecutesOnlyVerifiedMountedInstaller(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
	installer, err := NewDesktopMutationArtifactBinding(
		"/Library/Application Support/AgentMemory/runtime-helper/transactions/"+request.Digest().String()+"/installer.dmg",
		authority.ArtifactSHA256(), authority.ArtifactBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &darwinDesktopRemovalRunner{}
	detached := ""
	backend := nativeDesktopMutationBackend{
		runner: runner,
		applicationVersion: func(_ context.Context, path string, _ runtimeinstall.Hash) (string, bool) {
			return authority.RuntimeVersion(), path == "/Volumes/AgentMemory-Docker/Docker.app"
		},
		safeExecutable: func(path string) bool {
			return path == "/Volumes/AgentMemory-Docker/Docker.app/Contents/MacOS/install"
		},
		assessTarget: func(_ context.Context, path, operation string) bool {
			return path == installer.Path() && operation == "open"
		},
		moveApplication: func(context.Context, runtimeport.DesktopMutationRequest, string) error { return nil },
		attachImage: func(_ context.Context, path, home string) (darwinDiskImageMount, error) {
			if path != installer.Path() || home != authority.HomeDirectory() {
				return darwinDiskImageMount{}, errors.New("mount substitution")
			}
			return darwinDiskImageMount{mountPoint: "/Volumes/AgentMemory-Docker"}, nil
		},
		detachImage: func(_ context.Context, mount string) error {
			detached = mount
			return nil
		},
	}
	exitCode, err := backend.ExecuteNativeDesktopMutation(
		t.Context(), request, installer, true, DesktopMutationAuthorityEvidence{},
	)
	if err != nil || exitCode != 0 || runner.calls != 1 || detached != "/Volumes/AgentMemory-Docker" ||
		runner.command.Executable() != "/Volumes/AgentMemory-Docker/Docker.app/Contents/MacOS/install" ||
		!slices.Equal(runner.command.Arguments(), authority.InstallerArguments()) {
		t.Fatalf("exit=%d calls=%d command=%+v detached=%q error=%v", exitCode, runner.calls, runner.command, detached, err)
	}
}

type darwinDesktopRemovalRunner struct {
	command  DesktopMutationCommand
	exitCode uint32
	err      error
	calls    int
}

func (r *darwinDesktopRemovalRunner) RunDesktopMutationCommand(
	_ context.Context,
	command DesktopMutationCommand,
) (uint32, error) {
	r.calls++
	r.command = command
	return r.exitCode, r.err
}
