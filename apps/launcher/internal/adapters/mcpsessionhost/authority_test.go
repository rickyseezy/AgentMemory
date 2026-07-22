package mcpsessionhost

import (
	"context"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF005HostAuthoritiesBindLockAndActiveInstallation(t *testing.T) {
	t.Parallel()
	held := &authorityHeldLock{}
	lock, err := NewInstallationLock(&authorityLockSource{held: held})
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := lock.Acquire(t.Context())
	if err != nil || acquired != held {
		t.Fatalf("Acquire()=%T,%v", acquired, err)
	}
	if err := acquired.Release(t.Context()); err != nil || !held.released {
		t.Fatalf("Release()=%v released=%t", err, held.released)
	}

	pointer := hostPointer(t)
	active, err := NewActiveRelease(&authorityPointerSource{pointer: pointer}, pointer.InstallationID())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := active.LoadActive(t.Context())
	if err != nil || !loaded.Digest().Equal(pointer.Digest()) {
		t.Fatalf("LoadActive()=%v,%v", loaded, err)
	}
}

func TestPF005HostAuthoritiesRejectNilCancellationAndForeignPointer(t *testing.T) {
	t.Parallel()
	if _, err := NewInstallationLock(nil); err == nil {
		t.Fatal("nil lock error=nil")
	}
	lock, _ := NewInstallationLock(&authorityLockSource{held: &authorityHeldLock{}})
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if _, err := lock.Acquire(nil); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("nil context error=nil")
	}
	pointer := hostPointer(t)
	active, _ := NewActiveRelease(&authorityPointerSource{pointer: pointer}, "019d2b4e-7a11-7def-8abc-0123456789ab")
	if _, err := active.LoadActive(t.Context()); err == nil {
		t.Fatal("foreign pointer error=nil")
	}
}

type authorityHeldLock struct{ released bool }

func (l *authorityHeldLock) Release(context.Context) error { l.released = true; return nil }

type authorityLockSource struct {
	held installapp.InstallationLock
	err  error
}

func (s *authorityLockSource) Acquire(context.Context) (installapp.InstallationLock, error) {
	return s.held, s.err
}

type authorityPointerSource struct {
	pointer activerelease.Pointer
	err     error
}

func (s *authorityPointerSource) Load(context.Context, string) (activerelease.Pointer, error) {
	return s.pointer, s.err
}

func hostPointer(t testing.TB) activerelease.Pointer {
	t.Helper()
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: "019f5f20-5678-7def-9123-abcdef012345", ReleaseID: "agentmemory-1.0.0",
		GenerationID:           "019f5f21-5678-7def-9123-abcdef012346",
		ManifestDigest:         install.DigestBytes([]byte("manifest")),
		ComposeDigest:          install.DigestBytes([]byte("compose")),
		ReadinessReceiptDigest: install.DigestBytes([]byte("readiness")),
		RuntimeEndpoint:        "unix:///var/run/docker.sock", ReleaseSequence: 2,
		ResourceInventoryVersion: 1, ResourceInventoryDigest: install.DigestBytes([]byte("inventory")),
		SecurityEpoch: 1, ActivatedAt: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}
