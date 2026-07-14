//go:build windows

package windowssecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPF001WindowsNativeIdentityAndDPAPIBoundaries(t *testing.T) {
	t.Parallel()
	if _, sid, err := CurrentUserSID(context.Background()); err != nil || sid == "" {
		t.Fatalf("invoking SID = %q, %v", sid, err)
	}
	if guid, err := MachineGUID(context.Background()); err != nil || guid == "" {
		t.Fatalf("machine GUID = %q, %v", guid, err)
	}
	plaintext := bytes.Repeat([]byte{0x51}, 32)
	entropy := bytes.Repeat([]byte{0x62}, 32)
	protected, err := ProtectUser(context.Background(), plaintext, entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	if bytes.Contains(protected, plaintext) {
		t.Fatal("DPAPI output exposed the plaintext operation key")
	}
	unprotected, err := UnprotectUser(context.Background(), protected, entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unprotected)
	if !bytes.Equal(unprotected, plaintext) {
		t.Fatal("DPAPI round trip changed plaintext")
	}
	wrongEntropy := bytes.Repeat([]byte{0x63}, 32)
	if value, err := UnprotectUser(context.Background(), protected, wrongEntropy); err == nil {
		clear(value)
		t.Fatal("DPAPI accepted the wrong operation/owner entropy")
	}
}

func TestPF001WindowsPathPolicyRejectsUNCADSAndTraversal(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		`\\server\share\AgentMemory`,
		`C:\AgentMemory\journal.json:attack`,
		`relative\AgentMemory`,
		`\\?\C:\AgentMemory`,
	} {
		if err := ValidateLocalPath(path); err == nil {
			t.Fatalf("unsafe Windows path %q was accepted", path)
		}
	}
	if !validOperationDigestSegment("sha256-" + string(bytes.Repeat([]byte{'a'}, 64))) {
		t.Fatal("valid digest-only operation segment was rejected")
	}
	if validOperationDigestSegment("sha256-" + string(bytes.Repeat([]byte{'g'}, 64))) {
		t.Fatal("non-hex operation segment was accepted")
	}
	if windowsDriveTypeLocal(windows.DRIVE_REMOTE) || windowsDriveTypeLocal(windows.DRIVE_CDROM) ||
		!windowsDriveTypeLocal(windows.DRIVE_FIXED) {
		t.Fatal("mapped/network or non-writable Windows drive type policy is unsafe")
	}
}

func TestPF001WindowsDescriptorProofRejectsForeignOwnerAndDACL(t *testing.T) {
	t.Parallel()
	expected, _ := windows.StringToSid("S-1-5-18")
	foreignOwner, err := windows.SecurityDescriptorFromString(
		"O:S-1-1-0G:S-1-1-0D:P(A;;FA;;;S-1-1-0)",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnerDescriptor(foreignOwner, expected); err == nil {
		t.Fatal("foreign Windows owner was accepted")
	}
	foreignDACL, err := windows.SecurityDescriptorFromString(
		"O:S-1-5-18G:S-1-5-18D:P(A;;FA;;;S-1-1-0)",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDACL(foreignDACL, expected); err == nil {
		t.Fatal("foreign Windows DACL principal was accepted")
	}
	if err := verifyPrivateDACLMask(foreignDACL, expected, ownerMutexAccessMask); err == nil {
		t.Fatal("foreign Windows kernel-object DACL principal was accepted")
	}
	unprotectedDACL, err := windows.SecurityDescriptorFromString(
		"O:S-1-5-18G:S-1-5-18D:(A;;0x001F0001;;;S-1-5-18)",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDACLMask(unprotectedDACL, expected, ownerMutexAccessMask); err == nil {
		t.Fatal("unprotected default-style Windows kernel-object DACL was accepted")
	}
}

func TestPF001LockedReadHandleDeniesConcurrentWriteAndDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "locked-read")
	if err := CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "secret")
	created, err := CreatePrivateFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.Write([]byte("protected")); err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	locked, _, err := OpenVerifiedLockedRead(context.Background(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		t.Fatal("concurrent writer opened a locked protected file")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("locked protected file was deleted")
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("delete after locked handle close: %v", err)
	}
}

func TestPF001RelativePrivateChildNeverResolvesAnAbsolutePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "relative-child")
	if err := CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	directory, _, err := OpenVerifiedLockedRead(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if err := os.Rename(root, root+"-renamed"); err == nil {
		t.Fatal("retained generation directory permitted ancestor substitution")
	}
	child, created, err := OpenOrCreatePrivateChildSharedRead(
		context.Background(), directory, "installation-key",
	)
	if err != nil || !created {
		t.Fatalf("relative create result = %t/%v", created, err)
	}
	if _, err := child.Write([]byte("protected")); err != nil {
		t.Fatal(err)
	}
	if err := Flush(child); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "installation-key")
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	if reader, err := os.Open(path); err != nil {
		t.Fatalf("shared reader open: %v", err)
	} else if closeError := reader.Close(); closeError != nil {
		t.Fatal(closeError)
	}
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		t.Fatal("relative protected child permitted a concurrent writer")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("relative protected child permitted concurrent deletion")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, created, err := OpenOrCreatePrivateChildSharedRead(
		context.Background(), directory, "installation-key",
	)
	if err != nil || created {
		t.Fatalf("relative no-replace reopen result = %t/%v", created, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"..", `subdir\key`, "key:stream"} {
		if opened, _, err := OpenOrCreatePrivateChildSharedRead(context.Background(), directory, name); err == nil {
			_ = opened.Close()
			t.Fatalf("unsafe relative child %q was accepted", name)
		}
	}
}

func TestPF001DirectoryPathGuardRetainsEveryAncestor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "path-guard")
	first := filepath.Join(root, "first")
	leaf := filepath.Join(first, "leaf")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	guard, err := AcquireDirectoryPathGuard(context.Background(), leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(first, first+"-substituted"); err == nil {
		_ = guard.Close()
		t.Fatal("guarded Windows ancestor permitted rename/substitution")
	}
	if err := guard.Verify(context.Background()); err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(first, first+"-after-close"); err != nil {
		t.Fatalf("ancestor rename after guard close: %v", err)
	}
	if _, err := AcquireDirectoryPathGuard(context.Background(), `C:\unsafe\..\escape`); err == nil {
		t.Fatal("non-canonical guarded path was accepted")
	}
}

func TestPF001WindowsNativeSecurityIntegration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	operationDirectory := filepath.Join(root, "AgentMemory", "bootstrap", "sha256-"+string(bytes.Repeat([]byte{'a'}, 64)))
	if err := EnsureOperationDirectory(context.Background(), root, operationDirectory); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(operationDirectory, "first.tmp")
	first, err := CreatePrivateFile(context.Background(), firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := Flush(first); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(operationDirectory, "state.bin")
	if err := AtomicReplace(context.Background(), firstPath, targetPath, false); err != nil {
		t.Fatal(err)
	}
	target, firstIdentity, err := OpenVerified(context.Background(), targetPath, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	secondPath := filepath.Join(operationDirectory, "second.tmp")
	second, err := CreatePrivateFile(context.Background(), secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := AtomicReplace(context.Background(), secondPath, targetPath, true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPathIdentity(context.Background(), targetPath, firstIdentity, true); err == nil {
		t.Fatal("substituted Windows path retained the old file identity")
	}
	//nolint:gosec // G304: targetPath is confined to the integration test's TempDir operation tree.
	contents, err := os.ReadFile(targetPath)
	if err != nil || string(contents) != "second" {
		t.Fatalf("atomic replacement = %q, %v", contents, err)
	}
	publishCandidatePath := filepath.Join(operationDirectory, "publish-candidate.tmp")
	publishCandidate, err := CreatePrivateFile(context.Background(), publishCandidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishCandidate.Write([]byte("winner")); err != nil {
		t.Fatal(err)
	}
	if err := publishCandidate.Close(); err != nil {
		t.Fatal(err)
	}
	publishedPath := filepath.Join(operationDirectory, "published.bin")
	published, err := AtomicPublishNoReplace(context.Background(), publishCandidatePath, publishedPath)
	if err != nil || !published {
		t.Fatalf("initial no-replace publication = %v, %v", published, err)
	}
	loserPath := filepath.Join(operationDirectory, "publish-loser.tmp")
	loser, err := CreatePrivateFile(context.Background(), loserPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := loser.Close(); err != nil {
		t.Fatal(err)
	}
	published, err = AtomicPublishNoReplace(context.Background(), loserPath, publishedPath)
	if err != nil || published {
		t.Fatalf("competing no-replace publication = %v, %v", published, err)
	}

	t.Run("symbolic link", func(t *testing.T) {
		symlinkPath := filepath.Join(operationDirectory, "reparse-link")
		if err := os.Symlink(targetPath, symlinkPath); err != nil {
			t.Skipf("runner lacks Windows symbolic-link capability: %v", err)
		}
		if opened, _, err := OpenVerified(context.Background(), symlinkPath, false, false, true); err == nil {
			_ = opened.Close()
			t.Fatal("Windows reparse-point link was accepted")
		}
	})
	junctionTarget := filepath.Join(t.TempDir(), "junction-target")
	if err := os.Mkdir(junctionTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	junctionPath := filepath.Join(operationDirectory, "junction-link")
	//nolint:gosec // G204: fixed cmd.exe/mklink command; both variable arguments are test-owned TempDir paths.
	output, err := exec.CommandContext(
		context.Background(),
		"cmd.exe",
		"/d",
		"/c",
		"mklink",
		"/J",
		junctionPath,
		junctionTarget,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("certification runner could not create a directory junction: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if opened, _, err := OpenVerified(context.Background(), junctionPath, true, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("Windows directory junction was accepted")
	}

	credentialTarget := "AgentMemory/tests/PF001/" + strings.ReplaceAll(t.Name(), "/", "-")
	_ = DeleteGenericCredential(context.Background(), credentialTarget)
	t.Cleanup(func() { _ = DeleteGenericCredential(context.Background(), credentialTarget) })
	secret := bytes.Repeat([]byte{0x93}, 64)
	if err := WriteGenericCredential(context.Background(), credentialTarget, "PF001-test", secret); err != nil {
		t.Fatal(err)
	}
	credential, err := ReadGenericCredential(context.Background(), credentialTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credential)
	if !bytes.Equal(credential, secret) {
		t.Fatal("Windows Credential Manager changed the DPAPI ciphertext")
	}
	if err := DeleteGenericCredential(context.Background(), credentialTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGenericCredential(context.Background(), credentialTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted generic credential read = %v", err)
	}

	guard, err := AcquireOperationDirectory(context.Background(), root, operationDirectory, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(operationDirectory, operationDirectory+"-substituted"); err == nil {
		_ = guard.Close()
		t.Fatal("Windows operation directory path changed while guarded")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("operation guard is not idempotent: %v", err)
	}

	mutexDigest := sha256.Sum256([]byte(root))
	mutexName := ownerMutexNamePrefix + hex.EncodeToString(mutexDigest[:])
	invocations := 0
	if err := WithOwnerMutex(context.Background(), mutexName, func() error {
		invocations++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if invocations != 1 {
		t.Fatalf("owner mutex action count = %d", invocations)
	}
	mutexGuard, err := AcquireOwnerMutex(context.Background(), mutexName)
	if err != nil {
		t.Fatal(err)
	}
	releasedFromAnotherGoroutine := make(chan error, 1)
	go func() { releasedFromAnotherGoroutine <- mutexGuard.Release() }()
	select {
	case err := <-releasedFromAnotherGoroutine:
		if err != nil {
			t.Fatalf("cross-goroutine owner mutex release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cross-goroutine owner mutex release blocked")
	}
	if err := mutexGuard.Release(); err != nil {
		t.Fatalf("idempotent owner mutex release: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- WithOwnerMutex(context.Background(), mutexName, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-firstResult:
		t.Fatalf("first owner mutex acquisition failed: %v", err)
	}
	waitContext, cancelWait := context.WithTimeout(
		context.Background(),
		time.Duration(ownerMutexPollMilliseconds)*time.Millisecond,
	)
	defer cancelWait()
	if err := WithOwnerMutex(waitContext, mutexName, func() error {
		return errors.New("contended owner mutex unexpectedly ran")
	}); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("contended owner mutex cancellation = %v", err)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationDirectory(context.Background(), root, operationDirectory); err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := CurrentUserSID(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled SID lookup = %v", err)
	}
}

func TestPF001WindowsNativeRejectsUnsafeFilesAndBoundaryInputs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	operationDirectory := filepath.Join(root, "AgentMemory", "bootstrap", "sha256-"+strings.Repeat("b", 64))
	if err := EnsureOperationDirectory(context.Background(), root, operationDirectory); err != nil {
		t.Fatal(err)
	}

	unsafePath := filepath.Join(operationDirectory, "default-dacl.bin")
	if err := os.WriteFile(unsafePath, []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := OpenVerified(context.Background(), unsafePath, false, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("default Windows DACL was accepted")
	}

	protectedPath := filepath.Join(operationDirectory, "protected.bin")
	protected, err := CreatePrivateFile(context.Background(), protectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protected.Write([]byte("protected")); err != nil {
		t.Fatal(err)
	}
	if err := protected.Close(); err != nil {
		t.Fatal(err)
	}
	hardlinkPath := filepath.Join(operationDirectory, "hardlink.bin")
	if err := os.Link(protectedPath, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := OpenVerified(context.Background(), protectedPath, false, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("multiply-linked protected file was accepted")
	}
	if err := os.Remove(hardlinkPath); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: deliberate ADS attack is confined to this test's TempDir protected file.
	stream, err := os.OpenFile(protectedPath+":attack", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := OpenVerified(context.Background(), protectedPath, false, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("alternate data stream was accepted")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WithOwnerMutex(cancelled, ownerMutexNamePrefix+strings.Repeat("c", 64), func() error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled owner mutex = %v", err)
	}
	if err := WithOwnerMutex(context.Background(), "unsafe-name", func() error { return nil }); err == nil {
		t.Fatal("unsafe owner mutex name was accepted")
	}
	if err := WithOwnerMutex(context.Background(), ownerMutexNamePrefix+strings.Repeat("d", 64), nil); err == nil {
		t.Fatal("nil owner mutex action was accepted")
	}
	if err := WithOperationDirectory(context.Background(), root, operationDirectory, false, nil); err == nil {
		t.Fatal("nil guarded filesystem action was accepted")
	}
	if err := Flush(nil); err == nil {
		t.Fatal("nil durability descriptor was accepted")
	}
	if err := WriteGenericCredential(context.Background(), "", "user", []byte("secret")); err == nil {
		t.Fatal("empty credential target was accepted")
	}
	if err := WriteGenericCredential(context.Background(), "target", "user", nil); err == nil {
		t.Fatal("empty credential secret was accepted")
	}
	if _, err := ReadGenericCredential(cancelled, "target"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential read = %v", err)
	}
	if err := DeleteGenericCredential(cancelled, "target"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential delete = %v", err)
	}
	if err := CreatePrivateDirectory(context.Background(), "relative"); err == nil {
		t.Fatal("relative private directory path was accepted")
	}
	if _, err := CreatePrivateFile(context.Background(), "relative"); err == nil {
		t.Fatal("relative private file path was accepted")
	}
	if _, _, err := OpenVerified(context.Background(), "relative", false, false, true); err == nil {
		t.Fatal("relative verified path was accepted")
	}
}
