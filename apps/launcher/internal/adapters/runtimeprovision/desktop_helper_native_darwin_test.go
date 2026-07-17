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
	"strings"
	"syscall"
	"testing"
	"time"

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
	for name, candidate := range map[string]struct {
		uid  uint32
		size uint64
		mode uint32
	}{
		"owner": {uid: uid + 1, size: uint64(len(contents)), mode: 0o600},
		"size":  {uid: uid, size: uint64(len(contents)) + 1, mode: 0o600},
		"mode":  {uid: uid, size: uint64(len(contents)), mode: 0o644},
	} {
		if darwinDesktopMutationDescriptorMatches(descriptor, candidate.uid, candidate.size, candidate.mode) {
			t.Fatalf("descriptor with wrong %s was accepted", name)
		}
	}
	_ = unix.Close(descriptor)
	if !darwinDesktopMutationArtifactMatches(path, uid, digest, uint64(len(contents))) ||
		darwinDesktopMutationArtifactMatches(path, uid, runtimeinstall.Sum([]byte("foreign")), uint64(len(contents))) ||
		darwinDesktopMutationArtifactMatches(path, uid, digest, uint64(len(contents))+1) {
		t.Fatal("artifact byte binding failed")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyDescriptor, err := unix.Open(empty, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !darwinDesktopMutationDescriptorMatches(emptyDescriptor, uid, 0, 0o600) ||
		!darwinDesktopMutationArtifactMatches(empty, uid, runtimeinstall.Sum(nil), 0) {
		t.Fatal("zero-byte native boundary was rejected")
	}
	_ = unix.Close(emptyDescriptor)
	if parsed, ok := darwinDesktopMutationPrincipalUID("uid:501"); !ok || parsed != 501 {
		t.Fatalf("principal parsed=%d ok=%t", parsed, ok)
	}
	for principal, expected := range map[string]struct {
		uid   uint32
		valid bool
	}{
		"uid:1":          {uid: 1, valid: true},
		"uid:4294967295": {uid: ^uint32(0), valid: true},
		"uid:0":          {},
		"uid:4294967296": {},
		"uid:not-a-uid":  {},
		"root":           {},
	} {
		uid, valid := darwinDesktopMutationPrincipalUID(principal)
		if uid != expected.uid || valid != expected.valid {
			t.Fatalf("principal=%q uid=%d valid=%t", principal, uid, valid)
		}
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

func TestPF001DarwinDesktopHelperArtifactCopyValidationBindsEveryInput(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
	target, err := desktopMutationArtifactTarget(runtimeinstall.PlatformDarwin, request.Digest())
	if err != nil {
		t.Fatal(err)
	}
	valid := DesktopMutationTransactionArtifact{
		sourcePath: authority.ArtifactPath(), targetPath: target,
		sha256: request.ArtifactDigest(), size: authority.ArtifactBytes(),
	}
	uid, err := validateDarwinDesktopMutationArtifactCopy(t.Context(), 0, request, valid)
	if err != nil || uid != 501 {
		t.Fatalf("validated uid=%d error=%v", uid, err)
	}

	foreignSource := valid
	foreignSource.sourcePath += ".foreign"
	foreignTarget := valid
	foreignTarget.targetPath += ".foreign"
	foreignDigest := valid
	foreignDigest.sha256 = runtimeinstall.Sum([]byte("foreign"))
	foreignSize := valid
	foreignSize.size++
	_, _, windowsRequest := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	for name, candidate := range map[string]struct {
		ctx      context.Context
		euid     int
		request  runtimeport.DesktopMutationRequest
		artifact DesktopMutationTransactionArtifact
	}{
		"nil context":    {ctx: nil, euid: 0, request: request, artifact: valid},
		"not root":       {ctx: t.Context(), euid: 1, request: request, artifact: valid},
		"zero request":   {ctx: t.Context(), euid: 0, artifact: valid},
		"wrong platform": {ctx: t.Context(), euid: 0, request: windowsRequest, artifact: valid},
		"source":         {ctx: t.Context(), euid: 0, request: request, artifact: foreignSource},
		"target":         {ctx: t.Context(), euid: 0, request: request, artifact: foreignTarget},
		"digest":         {ctx: t.Context(), euid: 0, request: request, artifact: foreignDigest},
		"size":           {ctx: t.Context(), euid: 0, request: request, artifact: foreignSize},
	} {
		t.Run(name, func(t *testing.T) {
			gotUID, validationError := validateDarwinDesktopMutationArtifactCopy(
				candidate.ctx, candidate.euid, candidate.request, candidate.artifact,
			)
			if gotUID != 0 || !errors.Is(validationError, runtimeport.ErrDesktopMutationIntegrity) {
				t.Fatalf("validated uid=%d error=%v", gotUID, validationError)
			}
		})
	}
}

func TestPF001DarwinDesktopHelperArtifactCopyExecutesExactProtectedTransaction(t *testing.T) {
	t.Parallel()
	contents := []byte("signed installer payload")
	_, authority := desktopAdapterAuthorityWithArtifact(
		t, runtimeinstall.PlatformDarwin, runtimeinstall.Sum(contents), uint64(len(contents)),
	)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
	target, err := desktopMutationArtifactTarget(runtimeinstall.PlatformDarwin, request.Digest())
	if err != nil {
		t.Fatal(err)
	}
	artifact := DesktopMutationTransactionArtifact{
		sourcePath: authority.ArtifactPath(), targetPath: target,
		sha256: request.ArtifactDigest(), size: authority.ArtifactBytes(),
	}
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	targetPath := filepath.Join(root, "target")
	if err := os.WriteFile(sourcePath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	var ensured []struct {
		path string
		mode os.FileMode
	}
	matchCalls := 0
	renameCalls := 0
	syncCalls := 0
	operations := newDarwinDesktopMutationArtifactOperations()
	operations.effectiveUID = func() int { return 0 }
	operations.ensureDirectory = func(path string, mode os.FileMode) error {
		ensured = append(ensured, struct {
			path string
			mode os.FileMode
		}{path: path, mode: mode})
		return nil
	}
	operations.artifactMatches = func(
		path string,
		uid uint32,
		digest runtimeinstall.Hash,
		size uint64,
	) bool {
		matchCalls++
		if path != artifact.targetPath || uid != 0 || digest != artifact.sha256 || size != artifact.size {
			t.Fatalf("artifact match path=%q uid=%d digest=%s size=%d", path, uid, digest, size)
		}
		return matchCalls == 2
	}
	operations.open = func(path string, flags int, mode uint32) (int, error) {
		switch path {
		case artifact.sourcePath:
			if flags != unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW || mode != 0 {
				t.Fatalf("source flags=%d mode=%o", flags, mode)
			}
			return unix.Open(sourcePath, flags, mode)
		default:
			if !strings.HasSuffix(path, ".partial") ||
				flags != unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW || mode != 0o600 {
				t.Fatalf("target path=%q flags=%d mode=%o", path, flags, mode)
			}
			return unix.Open(targetPath, flags, mode)
		}
	}
	operations.descriptorMatches = func(descriptor int, uid uint32, size uint64, mode uint32) bool {
		if descriptor < 0 || uid != 501 || size != uint64(len(contents)) || mode != 0o600 {
			t.Fatalf("descriptor=%d uid=%d size=%d mode=%o", descriptor, uid, size, mode)
		}
		return true
	}
	operations.removeTemporary = func(path string) error {
		if !strings.HasSuffix(path, ".partial") {
			t.Fatalf("temporary path=%q", path)
		}
		return nil
	}
	operations.remove = func(path string) error {
		t.Fatalf("committed transaction removed %q", path)
		return nil
	}
	operations.renameNoReplace = func(source, destination string) error {
		renameCalls++
		if !strings.HasSuffix(source, ".partial") || destination != artifact.targetPath {
			t.Fatalf("rename source=%q destination=%q", source, destination)
		}
		return nil
	}
	operations.syncDirectory = func(path string) error {
		syncCalls++
		if path != filepath.Dir(artifact.targetPath) {
			t.Fatalf("synced directory=%q", path)
		}
		return nil
	}
	copier := nativeDesktopMutationArtifactCopier{operations: operations}
	if err := copier.CopyDesktopMutationArtifact(t.Context(), request, artifact); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(targetPath) // #nosec G304 -- private test path.
	if err != nil || !bytes.Equal(written, contents) {
		t.Fatalf("written=%q error=%v", written, err)
	}
	wantDirectories := []struct {
		path string
		mode os.FileMode
	}{
		{path: "/Library/Application Support/AgentMemory", mode: 0o755},
		{path: "/Library/Application Support/AgentMemory/runtime-helper", mode: 0o755},
		{path: darwinDesktopMutationTransactionRoot, mode: 0o700},
		{path: filepath.Dir(artifact.targetPath), mode: 0o700},
	}
	if !slices.Equal(ensured, wantDirectories) || matchCalls != 2 || renameCalls != 1 || syncCalls != 1 {
		t.Fatalf("ensured=%v matches=%d renames=%d syncs=%d", ensured, matchCalls, renameCalls, syncCalls)
	}
}

func TestPF001DarwinDesktopHelperArtifactCopyFailsBeforeUnauthorizedMutation(t *testing.T) {
	t.Parallel()
	contents := []byte("installer")
	_, authority := desktopAdapterAuthorityWithArtifact(
		t, runtimeinstall.PlatformDarwin, runtimeinstall.Sum(contents), uint64(len(contents)),
	)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
	target, err := desktopMutationArtifactTarget(runtimeinstall.PlatformDarwin, request.Digest())
	if err != nil {
		t.Fatal(err)
	}
	artifact := DesktopMutationTransactionArtifact{
		sourcePath: authority.ArtifactPath(), targetPath: target,
		sha256: request.ArtifactDigest(), size: authority.ArtifactBytes(),
	}

	operations := newDarwinDesktopMutationArtifactOperations()
	ensureCalls := 0
	operations.ensureDirectory = func(string, os.FileMode) error {
		ensureCalls++
		return nil
	}
	operations.effectiveUID = func() int { return 1 }
	if err := (nativeDesktopMutationArtifactCopier{operations: operations}).CopyDesktopMutationArtifact(
		t.Context(), request, artifact,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || ensureCalls != 0 {
		t.Fatalf("unelevated error=%v ensure calls=%d", err, ensureCalls)
	}

	operations.effectiveUID = func() int { return 0 }
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (nativeDesktopMutationArtifactCopier{operations: operations}).CopyDesktopMutationArtifact(
		cancelled, request, artifact,
	); !errors.Is(err, context.Canceled) || ensureCalls != 0 {
		t.Fatalf("cancelled error=%v ensure calls=%d", err, ensureCalls)
	}

	openFailure := errors.New("native source open failed")
	operations.artifactMatches = func(string, uint32, runtimeinstall.Hash, uint64) bool { return false }
	operations.open = func(string, int, uint32) (int, error) { return -1, openFailure }
	if err := (nativeDesktopMutationArtifactCopier{operations: operations}).CopyDesktopMutationArtifact(
		t.Context(), request, artifact,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || errors.Is(err, openFailure) || ensureCalls != 4 {
		t.Fatalf("open error=%v ensure calls=%d", err, ensureCalls)
	}
}

func TestPF001DarwinDesktopHelperArtifactOperationsRequireEveryNativeCapability(t *testing.T) {
	t.Parallel()
	operations := newDarwinDesktopMutationArtifactOperations()
	if !operations.valid() {
		t.Fatal("complete native operation set was rejected")
	}
	missing := []func(*darwinDesktopMutationArtifactOperations){
		func(o *darwinDesktopMutationArtifactOperations) { o.effectiveUID = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.ensureDirectory = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.artifactMatches = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.open = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.newFile = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.closeDescriptor = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.descriptorMatches = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.removeTemporary = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.remove = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.renameNoReplace = nil },
		func(o *darwinDesktopMutationArtifactOperations) { o.syncDirectory = nil },
	}
	for index, remove := range missing {
		candidate := operations
		remove(&candidate)
		if candidate.valid() {
			t.Fatalf("missing native capability %d was accepted", index)
		}
	}
	if err := (nativeDesktopMutationArtifactCopier{}).CopyDesktopMutationArtifact(
		t.Context(), runtimeport.DesktopMutationRequest{}, DesktopMutationTransactionArtifact{},
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero copier error=%v", err)
	}
	production, ok := newNativeDesktopMutationArtifactCopier().(nativeDesktopMutationArtifactCopier)
	if !ok || !production.operations.valid() {
		t.Fatalf("production copier=%+v valid=%t", production, ok)
	}
}

func TestPF001DarwinDesktopHelperFilesystemPoliciesRejectEachWeakenedAttribute(t *testing.T) {
	t.Parallel()
	rootStatus := &syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}
	directory := darwinMutationFileInfo{mode: os.ModeDir | 0o700, directory: true, native: rootStatus}
	if !darwinDesktopMutationDirectorySafe(directory, rootStatus, true, 0o700) {
		t.Fatal("exact protected directory was rejected")
	}
	for name, candidate := range map[string]struct {
		info        os.FileInfo
		status      *syscall.Stat_t
		statusValid bool
		mode        os.FileMode
	}{
		"nil info":     {status: rootStatus, statusValid: true, mode: 0o700},
		"nil stat":     {info: directory, statusValid: true, mode: 0o700},
		"foreign stat": {info: directory, status: rootStatus, mode: 0o700},
		"regular": {info: darwinMutationFileInfo{mode: 0o700, native: rootStatus},
			status: rootStatus, statusValid: true, mode: 0o700},
		"symlink": {info: darwinMutationFileInfo{
			mode: os.ModeDir | os.ModeSymlink | 0o700, directory: true, native: rootStatus,
		}, status: rootStatus, statusValid: true, mode: 0o700},
		"mode":  {info: directory, status: rootStatus, statusValid: true, mode: 0o755},
		"owner": {info: directory, status: &syscall.Stat_t{Uid: 1}, statusValid: true, mode: 0o700},
		"group": {info: directory, status: &syscall.Stat_t{Gid: 1}, statusValid: true, mode: 0o700},
	} {
		t.Run("directory "+name, func(t *testing.T) {
			if darwinDesktopMutationDirectorySafe(candidate.info, candidate.status, candidate.statusValid, candidate.mode) {
				t.Fatal("unsafe directory was accepted")
			}
		})
	}

	regular := darwinMutationFileInfo{mode: 0o600, native: rootStatus}
	if !darwinDesktopMutationTemporarySafe(regular, rootStatus, true) {
		t.Fatal("exact protected temporary was rejected")
	}
	for name, candidate := range map[string]struct {
		info        os.FileInfo
		status      *syscall.Stat_t
		statusValid bool
	}{
		"nil info":     {status: rootStatus, statusValid: true},
		"nil stat":     {info: regular, statusValid: true},
		"foreign stat": {info: regular, status: rootStatus},
		"directory":    {info: directory, status: rootStatus, statusValid: true},
		"symlink": {info: darwinMutationFileInfo{
			mode: os.ModeSymlink | 0o600, native: rootStatus,
		}, status: rootStatus, statusValid: true},
		"mode":  {info: darwinMutationFileInfo{mode: 0o644, native: rootStatus}, status: rootStatus, statusValid: true},
		"owner": {info: regular, status: &syscall.Stat_t{Uid: 1, Nlink: 1}, statusValid: true},
		"group": {info: regular, status: &syscall.Stat_t{Gid: 1, Nlink: 1}, statusValid: true},
		"links": {info: regular, status: &syscall.Stat_t{Nlink: 2}, statusValid: true},
	} {
		t.Run("temporary "+name, func(t *testing.T) {
			if darwinDesktopMutationTemporarySafe(candidate.info, candidate.status, candidate.statusValid) {
				t.Fatal("unsafe temporary was accepted")
			}
		})
	}
}

type darwinMutationFileInfo struct {
	mode      os.FileMode
	directory bool
	native    any
}

func (darwinMutationFileInfo) Name() string        { return "native" }
func (darwinMutationFileInfo) Size() int64         { return 0 }
func (i darwinMutationFileInfo) Mode() os.FileMode { return i.mode }
func (darwinMutationFileInfo) ModTime() time.Time  { return time.Time{} }
func (i darwinMutationFileInfo) IsDir() bool       { return i.directory }
func (i darwinMutationFileInfo) Sys() any          { return i.native }

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
