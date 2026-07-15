//go:build darwin && cgo

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
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
