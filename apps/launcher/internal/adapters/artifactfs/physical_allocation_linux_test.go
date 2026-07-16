//go:build linux

package artifactfs

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
)

func TestPF001LinuxPhysicalAllocationFailsClosedAndReplaysExactExtent(t *testing.T) {
	t.Parallel()
	file, err := os.OpenFile(t.TempDir()+"/reservation", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })

	//lint:ignore SA1012 Deliberate nil-context allocation boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if err := allocatePhysical(nil, file, 4096); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("nil context error=%v", err)
	}
	for name, run := range map[string]func() error{
		"nil file":      func() error { return allocatePhysical(t.Context(), nil, 4096) },
		"zero size":     func() error { return allocatePhysical(t.Context(), file, 0) },
		"overflow size": func() error { return allocatePhysical(t.Context(), file, math.MaxUint64) },
		"cancelled": func() error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return allocatePhysical(ctx, file, 4096)
		},
	} {
		if err := run(); !errors.Is(err, artifactapp.ErrReservationOperation) {
			t.Fatalf("%s error=%v", name, err)
		}
	}

	if err := allocatePhysical(t.Context(), file, 4096); err != nil {
		t.Fatal(err)
	}
	if err := allocatePhysical(t.Context(), file, 4096); err != nil {
		t.Fatalf("idempotent allocation error=%v", err)
	}
	if !platformAllocationInvariant(file) {
		t.Fatal("published Linux allocation lost its platform invariant")
	}
	if platformAllocationInvariant(nil) {
		t.Fatal("nil file satisfied the platform allocation invariant")
	}
	if value, valid := nonNegativeFilesystemType(-1); valid || value != 0 {
		t.Fatalf("negative filesystem type=(%d,%t)", value, valid)
	}
	if err := durableSync(nil); err == nil {
		t.Fatal("nil durability descriptor accepted")
	}
	if err := renameSecureNoReplace(nil, file, "target"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil secure source rename error=%v", err)
	}
	if _, err := availableBytesDescriptor(nil); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil capacity descriptor error=%v", err)
	}

	closed, err := os.OpenFile(t.TempDir()+"/closed", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := allocatePhysical(t.Context(), closed, 4096); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("closed file allocation error=%v", err)
	}
	if platformAllocationInvariant(closed) {
		t.Fatal("closed file satisfied the platform allocation invariant")
	}
	if err := durableSync(closed); err == nil {
		t.Fatal("closed durability descriptor accepted")
	}
}
