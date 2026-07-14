//go:build linux

package capacityhelper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPF001LinuxCapacityStorePhysicallyReservesRevalidatesTransfersAndProvesDelete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := newLinuxStoreAt(root)
	reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
	reserved, err := store.Reserve(context.Background(), reserve)
	if err != nil || reserved.FileSizeBytes != reserve.Bytes() ||
		reserved.AllocatedBlockBytes < reserve.Bytes() || reserved.State != string(MetadataReserved) {
		t.Fatalf("Reserve()=%+v,%v", reserved, err)
	}
	metadataInfo, err := os.Lstat(filepath.Join(root, metadataName))
	if err != nil || metadataInfo.Mode().Perm() != 0o600 {
		t.Fatalf("metadata mode=%v error=%v", metadataInfo, err)
	}
	if inspected, err := store.Inspect(context.Background(), mustHelperRequest(t, helperRequestInput(OperationInspect))); err != nil || inspected.Metadata != reserved.Metadata {
		t.Fatalf("Inspect()=%+v,%v", inspected, err)
	}

	transfer := mustHelperRequest(t, withTransfer(helperRequestInput(OperationTransfer)))
	transferred, err := store.Transfer(context.Background(), transfer)
	if err != nil || transferred.Owner != transfer.NewOwner() || transferred.State != string(MetadataTransferred) {
		t.Fatalf("Transfer()=%+v,%v", transferred, err)
	}
	if replay, err := store.Transfer(context.Background(), transfer); err != nil || replay.Owner != transferred.Owner {
		t.Fatalf("Transfer replay=%+v,%v", replay, err)
	}
	deleteRequest := mustHelperRequest(t, withDelete(
		helperRequestInput(OperationDeleteProof), PriorTransferred, transfer.NewOwner(),
	))
	proof, err := store.DeleteProof(context.Background(), deleteRequest)
	if err != nil || proof.State != "delete-approved" || proof.Owner != transfer.NewOwner() ||
		proof.AllocatedBlockBytes < proof.FileSizeBytes {
		t.Fatalf("DeleteProof()=%+v,%v", proof, err)
	}
}

func TestPF001LinuxCapacityStoreActivatesProjectionToExactEmptyDirectoryAndReplays(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := newLinuxStoreAt(root)
	reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
	if _, err := store.Reserve(context.Background(), reserve); err != nil {
		t.Fatal(err)
	}
	activate := mustHelperRequest(t, withTransfer(helperRequestInput(OperationActivateProjection)))
	activated, err := store.ActivateProjection(context.Background(), activate)
	if err != nil || activated.Owner != activate.NewOwner() || activated.State != "projection-ready" ||
		activated.FileSizeBytes != 0 || activated.AllocatedBlockBytes != 0 {
		t.Fatalf("ActivateProjection()=%+v,%v", activated, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("projection entries=%+v error=%v", entries, err)
	}
	if replay, replayError := store.ActivateProjection(context.Background(), activate); replayError != nil ||
		replay.State != "projection-ready" {
		t.Fatalf("ActivateProjection replay=%+v,%v", replay, replayError)
	}
}

func TestPF001LinuxCapacityStoreProjectionActivationCompletesOnlyAuthenticInterruptedLayout(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := newLinuxStoreAt(root)
	reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
	if _, err := store.Reserve(context.Background(), reserve); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, reservationName)); err != nil {
		t.Fatal(err)
	}
	activate := mustHelperRequest(t, withTransfer(helperRequestInput(OperationActivateProjection)))
	if _, err := store.ActivateProjection(context.Background(), activate); err != nil {
		t.Fatalf("authentic metadata-only replay failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateProjection(context.Background(), activate); err == nil {
		t.Fatal("foreign projection entry accepted")
	}
}

func TestPF001LinuxCapacityStoreAcceptsEveryExactDeleteCrashProjection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		prior       PriorState
		transfer    bool
		alternate   string
		expectedOwn string
	}{
		{name: "reserve pending after allocation", prior: PriorReservePending, expectedOwn: "install-owner"},
		{name: "reserved", prior: PriorReserved, expectedOwn: "install-owner"},
		{name: "transfer pending before effect", prior: PriorTransferPending, alternate: "generation-1", expectedOwn: "install-owner"},
		{name: "transfer pending after effect", prior: PriorTransferPending, transfer: true, alternate: "generation-1", expectedOwn: "generation-1"},
		{name: "transferred", prior: PriorTransferred, transfer: true, alternate: "generation-1", expectedOwn: "generation-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newLinuxStoreAt(t.TempDir())
			reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
			if _, err := store.Reserve(context.Background(), reserve); err != nil {
				t.Fatal(err)
			}
			if test.transfer {
				transfer := mustHelperRequest(t, withTransfer(helperRequestInput(OperationTransfer)))
				if _, err := store.Transfer(context.Background(), transfer); err != nil {
					t.Fatal(err)
				}
			}
			request := mustHelperRequest(t, withDelete(
				helperRequestInput(OperationDeleteProof), test.prior, test.alternate,
			))
			proof, err := store.DeleteProof(context.Background(), request)
			if err != nil || proof.Owner != test.expectedOwn || proof.State != "delete-approved" {
				t.Fatalf("DeleteProof()=%+v,%v", proof, err)
			}
		})
	}
}

func TestPF001LinuxCapacityStoreTransferRejectsPendingAndOwnerSubstitution(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := newLinuxStoreAt(root)
	pendingDelete := mustHelperRequest(t, withDelete(
		helperRequestInput(OperationDeleteProof), PriorReservePending, "",
	))
	if _, err := store.DeleteProof(context.Background(), pendingDelete); err != nil {
		t.Fatal(err)
	}
	transfer := mustHelperRequest(t, withTransfer(helperRequestInput(OperationTransfer)))
	if _, err := store.Transfer(context.Background(), transfer); err == nil {
		t.Fatal("pending reservation transfer accepted")
	}

	root = t.TempDir()
	store = newLinuxStoreAt(root)
	reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
	if _, err := store.Reserve(context.Background(), reserve); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transfer(context.Background(), transfer); err != nil {
		t.Fatal(err)
	}
	otherInput := withTransfer(helperRequestInput(OperationTransfer))
	otherInput.NewOwner = "generation-2"
	if _, err := store.Transfer(context.Background(), mustHelperRequest(t, otherInput)); err == nil {
		t.Fatal("transferred owner substitution accepted")
	}
	if NewLinuxStore().root != MountTarget {
		t.Fatal("production store does not use the fixed mount")
	}
}

func TestPF001LinuxCapacityStoreRecoversEveryKnownPendingLayout(t *testing.T) {
	t.Parallel()
	t.Run("empty reserve pending delete", func(t *testing.T) {
		root := t.TempDir()
		store := newLinuxStoreAt(root)
		request := mustHelperRequest(t, withDelete(
			helperRequestInput(OperationDeleteProof), PriorReservePending, "",
		))
		proof, err := store.DeleteProof(context.Background(), request)
		if err != nil || proof.FileSizeBytes != 0 || proof.AllocatedBlockBytes != 0 ||
			proof.Metadata.State != string(MetadataReservePending) {
			t.Fatalf("DeleteProof()=%+v,%v", proof, err)
		}
	})

	t.Run("atomic metadata publication", func(t *testing.T) {
		root := t.TempDir()
		request := mustHelperRequest(t, helperRequestInput(OperationReserve))
		pending, _ := NewMetadata(request, request.Owner(), MetadataReservePending)
		reserved, _ := NewMetadata(request, request.Owner(), MetadataReserved)
		pendingBytes, _ := CanonicalMetadata(pending)
		reservedBytes, _ := CanonicalMetadata(reserved)
		if err := os.WriteFile(filepath.Join(root, metadataName), pendingBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // G304: root is a test-owned TempDir and the leaf is a fixed production constant.
		file, err := os.OpenFile(filepath.Join(root, reservationName), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // G115: the closed request is bounded below maximumSafeBytes.
		if err := unix.Fallocate(int(file.Fd()), 0, 0, int64(request.Bytes())); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		_ = file.Sync()
		_ = file.Close()
		if err := os.WriteFile(filepath.Join(root, metadataTemporaryName), reservedBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := newLinuxStoreAt(root).Reserve(context.Background(), request)
		if err != nil || result.Metadata.State != string(MetadataReserved) {
			t.Fatalf("Reserve recovery=%+v,%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(root, metadataTemporaryName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary metadata remains: %v", err)
		}
	})
}

func TestPF001LinuxCapacityStoreRejectsSparseForeignOrRegressedState(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		tamper func(t *testing.T, root string, request Request)
	}{
		{name: "sparse", tamper: func(t *testing.T, root string, request Request) {
			t.Helper()
			if err := os.Remove(filepath.Join(root, reservationName)); err != nil {
				t.Fatal(err)
			}
			//nolint:gosec // G304: root is a test-owned TempDir and the leaf is fixed.
			file, err := os.OpenFile(filepath.Join(root, reservationName), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			//nolint:gosec // G115: the closed request is bounded below maximumSafeBytes.
			if err := file.Truncate(int64(request.Bytes())); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "extra entry", tamper: func(t *testing.T, root string, _ Request) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe mode", tamper: func(t *testing.T, root string, _ Request) {
			t.Helper()
			//nolint:gosec // G302: deliberately unsafe attack fixture must be rejected by Inspect.
			if err := os.Chmod(filepath.Join(root, metadataName), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "foreign owner metadata", tamper: func(t *testing.T, root string, request Request) {
			t.Helper()
			metadata, _ := NewMetadata(request, request.Owner(), MetadataReserved)
			metadata.Owner = "foreign-owner"
			encoded, _ := CanonicalMetadata(metadata)
			if err := os.WriteFile(filepath.Join(root, metadataName), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "regressed temporary", tamper: func(t *testing.T, root string, request Request) {
			t.Helper()
			metadata, _ := NewMetadata(request, request.Owner(), MetadataReservePending)
			encoded, _ := CanonicalMetadata(metadata)
			if err := os.WriteFile(filepath.Join(root, metadataTemporaryName), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store := newLinuxStoreAt(root)
			reserve := mustHelperRequest(t, helperRequestInput(OperationReserve))
			if _, err := store.Reserve(context.Background(), reserve); err != nil {
				t.Fatal(err)
			}
			test.tamper(t, root, reserve)
			inspect := mustHelperRequest(t, helperRequestInput(OperationInspect))
			if _, err := store.Inspect(context.Background(), inspect); err == nil {
				t.Fatal("tampered physical reservation accepted")
			}
		})
	}
}

func TestPF001LinuxCapacityStoreRejectsLowSpaceCancellationAndInvalidAuthority(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := newLinuxStoreAt(root)
	request := mustHelperRequest(t, helperRequestInput(OperationReserve))
	//lint:ignore SA1012 Deliberate nil-context attack proves no volume mutation occurs.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := store.Reserve(nil, request); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Reserve(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var absent *LinuxStore
	if _, err := absent.Reserve(context.Background(), request); err == nil {
		t.Fatal("nil store accepted")
	}

	input := helperRequestInput(OperationReserve)
	input.Bytes = maximumSafeBytes
	tooLarge := mustHelperRequest(t, input)
	if _, err := store.Reserve(context.Background(), tooLarge); err == nil {
		t.Fatal("overcommitted reservation accepted")
	}

	deleteInput := helperRequestInput(OperationDeleteProof)
	deleteInput.PriorState = PriorTransferred
	deleteInput.AlternateOwner = "generation-1"
	deleteRequest := mustHelperRequest(t, deleteInput)
	if _, err := newLinuxStoreAt(t.TempDir()).DeleteProof(context.Background(), deleteRequest); err == nil {
		t.Fatal("missing transferred reservation accepted")
	}
}

func TestPF001LinuxCapacityStoreRejectsUnsafeRootAndInterruptsLockWait(t *testing.T) {
	t.Parallel()
	t.Run("unsafe root mode", func(t *testing.T) {
		root := t.TempDir()
		//nolint:gosec // G302: deliberately unsafe attack fixture must be rejected.
		if err := os.Chmod(root, 0o777); err != nil {
			t.Fatal(err)
		}
		request := mustHelperRequest(t, helperRequestInput(OperationReserve))
		if _, err := newLinuxStoreAt(root).Reserve(context.Background(), request); err == nil {
			t.Fatal("group/world-writable capacity root accepted")
		}
	})

	t.Run("cancelled lock wait", func(t *testing.T) {
		root := t.TempDir()
		lockFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(lockFD) }()
		if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Flock(lockFD, unix.LOCK_UN) }()

		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
		defer cancel()
		request := mustHelperRequest(t, helperRequestInput(OperationReserve))
		if _, err := newLinuxStoreAt(root).Reserve(ctx, request); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contended lock error=%v", err)
		}
	})
}

func TestPF001LinuxCapacityStoreRejectsSymlinkAndMalformedMetadata(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{name: "metadata symlink", setup: func(t *testing.T, root string) {
			t.Helper()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, metadataName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed temporary", setup: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, metadataTemporaryName), []byte(`{"bad":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized metadata", setup: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, metadataName), []byte(strings.Repeat("x", 4097)), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.setup(t, root)
			request := mustHelperRequest(t, helperRequestInput(OperationReserve))
			if _, err := newLinuxStoreAt(root).Reserve(context.Background(), request); err == nil {
				t.Fatal("malformed capacity state accepted")
			}
		})
	}
}

func TestPF001LinuxCapacityStoreClosedNativeErrorAndRecoveryClassifiers(t *testing.T) {
	t.Parallel()
	request := mustHelperRequest(t, withTransfer(helperRequestInput(OperationTransfer)))
	pending, _ := NewMetadata(request, request.Owner(), MetadataReservePending)
	reserved, _ := NewMetadata(request, request.Owner(), MetadataReserved)
	transferred, _ := NewMetadata(request, request.NewOwner(), MetadataTransferred)
	if metadataRank(pending) != 1 || metadataRank(reserved) != 2 || metadataRank(transferred) != 3 ||
		metadataRank(Metadata{}) != 0 || !recoveryOwnerAllowed(request, pending) ||
		!recoveryOwnerAllowed(request, transferred) {
		t.Fatal("closed metadata recovery classifier is inconsistent")
	}
	transferred.Owner = "foreign"
	if recoveryOwnerAllowed(request, transferred) {
		t.Fatal("foreign recovery owner accepted")
	}
	if _, err := newLinuxStoreAt("/agentmemory-capacity-missing").Reserve(context.Background(), request); err == nil {
		t.Fatal("missing fixed mount accepted")
	}
	if _, err := availableBytes(-1); err == nil {
		t.Fatal("invalid statfs descriptor accepted")
	}
	if _, err := entryPresent(-1, metadataName); err == nil {
		t.Fatal("invalid entry descriptor accepted")
	}
	if _, err := openReservation(-1, false); err == nil {
		t.Fatal("invalid reservation descriptor accepted")
	}
	if _, err := directoryEntries(-1, 0); err == nil {
		t.Fatal("invalid directory descriptor accepted")
	}
	if _, err := directoryEntries(-1, 4); err == nil {
		t.Fatal("unbounded directory enumeration accepted")
	}
	if err := validateRootDirectory(-1); err == nil {
		t.Fatal("invalid root descriptor accepted")
	}
	if err := acquireRootLock(context.Background(), -1); err == nil {
		t.Fatal("invalid root lock descriptor accepted")
	}
	if _, err := fallocateLength(0); err == nil {
		t.Fatal("zero fallocate length accepted")
	}
}
