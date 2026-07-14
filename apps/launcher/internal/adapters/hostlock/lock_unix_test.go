//go:build darwin || linux

package hostlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPF001InstallationLockSerializesProcessesAndReleasesIdempotently(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "install.lock")
	firstPort, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	secondPort, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstPort.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := secondPort.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contending acquire error = %v", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	second, err := secondPort.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001InstallationLockRejectsSymlinkAndUnsafePermissions(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	port, err := New(symlink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := port.Acquire(context.Background()); err == nil {
		t.Fatal("symlink lock was accepted")
	}

	unsafePath := filepath.Join(directory, "unsafe")
	//nolint:gosec // G306: deliberately unsafe fixture proves fail-closed permissions.
	if err := os.WriteFile(unsafePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	port, err = New(unsafePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := port.Acquire(context.Background()); err == nil {
		t.Fatal("non-owner-only lock was accepted")
	}
}

func TestPF001InstallationLockRejectsRelativePathAndCancellation(t *testing.T) {
	t.Parallel()

	if _, err := New("relative.lock"); err == nil {
		t.Fatal("relative lock path was accepted")
	}
	port, err := New(filepath.Join(t.TempDir(), "install.lock"))
	if err != nil {
		t.Fatal(err)
	}
	missingParent, err := New(filepath.Join(t.TempDir(), "missing", "install.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingParent.Acquire(context.Background()); err == nil {
		t.Fatal("lock in a missing parent directory was accepted")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed-lock-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyLockFile(closed); err == nil {
		t.Fatal("closed lock file was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// An uncontended acquire may win before observing cancellation, so first
	// hold the lock and then prove the waiter exits via its context.
	held, err := port.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release(context.Background()) }()
	if _, err := port.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acquire error = %v", err)
	}
}
