//go:build darwin || linux

package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001UnixExecutableOwnerParserRejectsAmbiguousIdentities(t *testing.T) {
	t.Parallel()
	for _, owner := range []string{"0", "gid:0", "uid:", "uid:-1", "uid:01", "uid:4294967296"} {
		owner := owner
		t.Run(owner, func(t *testing.T) {
			t.Parallel()
			if _, err := parseUnixOwner(owner); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
				t.Fatalf("parseUnixOwner(%q) error = %v", owner, err)
			}
		})
	}
}

func TestPF001UnixExecutableLeaseRejectsInvalidContextAndOwner(t *testing.T) {
	t.Parallel()
	authority := testExecutableAuthority(t, testCurrentExecutable(t))
	//lint:ignore SA1012 Deliberate nil-context attack proves executable acquisition fails closed.
	//nolint:staticcheck // SA1012: deliberate nil-context attack; owner=security expiry=2027-07-14.
	if _, err := acquireExecutableLease(nil, authority, true); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("nil context error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireExecutableLease(ctx, authority, true); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("cancelled context error = %v", err)
	}
	malformedOwner := unixAuthority(t, authority.CanonicalPath(), authority.SHA256(), "local-owner")
	if _, err := acquireExecutableLease(context.Background(), malformedOwner, true); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("malformed owner error = %v", err)
	}
}

func TestPF001UnixExecutableLeaseRejectsUnsafeObjectShapes(t *testing.T) {
	t.Parallel()
	uid := "uid:" + strconv.Itoa(os.Getuid())
	directory := filepath.Join(trustedExecutableFixtureDirectory(t), "objects")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	create := func(name string, size int64, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(directory, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- isolated test fixture.
		if err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if err := file.Truncate(size); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	empty := create("empty", 0, 0o700)
	oversized := create("oversized", maximumExecutableBytes+1, 0o700)
	nonExecutable := create("not-executable", 1, 0o600)
	hardLinked := create("hard-linked", 1, 0o700)
	if err := os.Link(hardLinked, hardLinked+".peer"); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := create("symlink-target", 1, 0o700)
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(symlinkTarget, symlink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		digest    [sha256.Size]byte
		owner     string
		wantClass error
	}{
		{name: "single path component", path: "/x", digest: sha256.Sum256([]byte("x")), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "directory", path: directory, digest: sha256.Sum256([]byte("directory")), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "empty", path: empty, digest: sha256.Sum256(nil), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "oversized", path: oversized, digest: sha256.Sum256([]byte("oversized")), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "not executable", path: nonExecutable, digest: sha256.Sum256([]byte{0}), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "multiple links", path: hardLinked, digest: sha256.Sum256([]byte{0}), owner: uid, wantClass: argvprocess.ErrInvalidInvocation},
		{name: "symlink", path: symlink, digest: sha256.Sum256([]byte{0}), owner: uid},
		{name: "wrong owner", path: symlinkTarget, digest: sha256.Sum256([]byte{0}), owner: "uid:" + strconv.Itoa(os.Getuid()+1), wantClass: argvprocess.ErrInvalidInvocation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := unixAuthority(t, test.path, test.digest, test.owner)
			lease, err := acquireExecutableLease(context.Background(), authority, true)
			if lease != nil {
				lease.close()
			}
			if err == nil {
				t.Fatal("unsafe executable shape acquired a lease")
			}
			if test.wantClass != nil && !errors.Is(err, test.wantClass) {
				t.Fatalf("lease error = %v, want %v", err, test.wantClass)
			}
		})
	}
}

func TestPF001UnixExecutableDigestRejectsInvalidObjects(t *testing.T) {
	t.Parallel()
	if _, err := digestExecutable(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil digest error = %v", err)
	}
	empty, err := os.CreateTemp(t.TempDir(), "empty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := digestExecutable(empty); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("empty digest error = %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := digestExecutable(empty); err == nil {
		t.Fatal("closed descriptor was digested")
	}
}

func TestPF001UnixExecutableSecurityPredicatesRejectInvalidMetadata(t *testing.T) {
	t.Parallel()
	if secureExecutableAncestor(nil, nil, uint32(os.Getuid())) { //nolint:gosec // G115: Unix UID ABI is an unsigned 32-bit value.
		t.Fatal("nil ancestor was secure")
	}
	if secureUnixExecutable(nil, nil, uint32(os.Getuid())) { //nolint:gosec // G115: Unix UID ABI is an unsigned 32-bit value.
		t.Fatal("nil executable was secure")
	}
	invalidSystemMetadata := unixFileInfoStub{mode: 0o700 | os.ModeDir, system: struct{}{}}
	if secureExecutableAncestor(nil, invalidSystemMetadata, uint32(os.Getuid())) { //nolint:gosec // G115: Unix UID ABI is an unsigned 32-bit value.
		t.Fatal("non-Unix ancestor metadata was secure")
	}
	foreignOwner := unixFileInfoStub{
		mode:   0o700 | os.ModeDir,
		system: &syscall.Stat_t{Uid: uint32(os.Getuid() + 1)}, //nolint:gosec // G115: bounded foreign-owner test fixture.
	}
	if secureExecutableAncestor(nil, foreignOwner, uint32(os.Getuid())) { //nolint:gosec // G115: Unix UID ABI is an unsigned 32-bit value.
		t.Fatal("foreign-owned ancestor was secure")
	}
}

func TestPF001UnixExecutableLeaseRevalidationRejectsClosedAuthority(t *testing.T) {
	t.Parallel()
	var nilLease *executableLease
	nilLease.close()
	authority := testExecutableAuthority(t, testCurrentExecutable(t))
	if err := nilLease.verify(context.Background(), authority); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("nil lease error = %v", err)
	}

	lease, err := acquireExecutableLease(context.Background(), authority, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lease.verify(ctx, authority); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		lease.close()
		t.Fatalf("cancelled revalidation error = %v", err)
	}
	if err := lease.ancestors[len(lease.ancestors)-1].file.Close(); err != nil {
		lease.close()
		t.Fatal(err)
	}
	if err := lease.verify(context.Background(), authority); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		lease.close()
		t.Fatalf("closed ancestor error = %v", err)
	}
	lease.close()

	lease, err = acquireExecutableLease(context.Background(), authority, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.file.Close(); err != nil {
		lease.close()
		t.Fatal(err)
	}
	if err := lease.verify(context.Background(), authority); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		lease.close()
		t.Fatalf("closed executable error = %v", err)
	}
	lease.close()
}

func TestPF001UnixExecutableAncestorAppendRequiresSamePathObject(t *testing.T) {
	t.Parallel()
	first := t.TempDir()
	second := t.TempDir()
	descriptor, err := os.Open(first) // #nosec G304 -- isolated test fixture.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeError := descriptor.Close(); closeError != nil {
			t.Errorf("close ancestor fixture: %v", closeError)
		}
	})
	lease := &executableLease{}
	if err := lease.appendAncestor(
		second,
		descriptor,
		uint32(os.Getuid()), //nolint:gosec // G115: Unix UID ABI is an unsigned 32-bit value.
	); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("mismatched ancestor error = %v", err)
	}
	if len(lease.ancestors) != 0 {
		t.Fatal("mismatched ancestor was retained")
	}
}

func unixAuthority(
	t *testing.T,
	path string,
	digest [sha256.Size]byte,
	owner string,
) argvprocess.ExecutableAuthority {
	t.Helper()
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "unix-test-executable", CanonicalPath: path,
		SHA256: digest, OwnerIdentity: owner,
		PublisherIdentity: "test-publisher", PublisherPolicyID: "test-policy",
		PublisherTrustDigest:  sha256.Sum256([]byte("test-publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("test-release-manifest")),
		RuntimePlanDigest:     sha256.Sum256([]byte("test-runtime-plan")),
		Role:                  argvprocess.ExecutableRoleDockerCLI,
		Platform:              runtime.GOOS,
		Architecture:          runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

type unixFileInfoStub struct {
	mode   os.FileMode
	system any
}

func (unixFileInfoStub) Name() string        { return "fixture" }
func (unixFileInfoStub) Size() int64         { return 1 }
func (f unixFileInfoStub) Mode() os.FileMode { return f.mode }
func (unixFileInfoStub) ModTime() time.Time  { return time.Time{} }
func (f unixFileInfoStub) IsDir() bool       { return f.mode.IsDir() }
func (f unixFileInfoStub) Sys() any          { return f.system }
