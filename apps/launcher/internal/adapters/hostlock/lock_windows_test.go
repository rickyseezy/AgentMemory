//go:build windows

package hostlock

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func TestPF001InstallationMutexSerializesCancelsAndReleasesIdempotently(t *testing.T) {
	firstPort, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	secondPort, err := New("")
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

	// Release is cleanup: a cancelled operation context must not strand the
	// machine-global mutex, and repeated release must remain harmless.
	cancelled, cancelRelease := context.WithCancel(context.Background())
	cancelRelease()
	if err := first.Release(cancelled); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := secondPort.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(context.Background()); err != nil {
		t.Fatal(err)
	}

	//lint:ignore SA1012 Deliberate nil-context attack proves the adapter fails closed.
	//nolint:staticcheck // SA1012: deliberate nil-context attack proves the adapter fails closed; owner=security expiry=2027-07-14.
	if _, err := firstPort.Acquire(nil); err == nil {
		t.Fatal("nil installation-lock context was accepted")
	}
	preCancelled, cancelAcquire := context.WithCancel(context.Background())
	cancelAcquire()
	if _, err := firstPort.Acquire(preCancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled acquire error = %v", err)
	}
}

func TestPF001InstallationMutexNameIsCanonicalAndMachineBound(t *testing.T) {
	first := &Port{machineIdentity: func(context.Context) (string, error) {
		return "01234567-89AB-CDEF-0123-456789ABCDEF", nil
	}}
	second := &Port{machineIdentity: func(context.Context) (string, error) {
		return "11234567-89ab-cdef-0123-456789abcdef", nil
	}}
	firstName, err := first.mutexName(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	caseEquivalent := &Port{machineIdentity: func(context.Context) (string, error) {
		return "01234567-89ab-cdef-0123-456789abcdef", nil
	}}
	equivalentName, err := caseEquivalent.mutexName(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondName, err := second.mutexName(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstName != equivalentName {
		t.Fatal("machine GUID case changed the installation mutex identity")
	}
	if firstName == secondName {
		t.Fatal("different machines shared an installation mutex identity")
	}
	if !strings.HasPrefix(firstName, `Global\AgentMemory-PF001-`) || len(firstName) != len(`Global\AgentMemory-PF001-`)+64 {
		t.Fatalf("installation mutex name is not a fixed digest identity: %q", firstName)
	}
	if firstName == `Global\AgentMemory.PF001.Installation` {
		t.Fatal("legacy unbound installation mutex identity was retained")
	}

	invalid := &Port{machineIdentity: func(context.Context) (string, error) { return "not-a-guid", nil }}
	if _, err := invalid.mutexName(context.Background()); err == nil {
		t.Fatal("invalid machine identity was accepted")
	}
	failing := &Port{machineIdentity: func(context.Context) (string, error) {
		return "", errors.New("identity unavailable")
	}}
	if _, err := failing.mutexName(context.Background()); err == nil || strings.Contains(err.Error(), "identity unavailable") {
		t.Fatalf("machine identity failure was not privacy-normalized: %v", err)
	}
}

func TestPF001InstallationMutexRejectsPreExistingForeignDACL(t *testing.T) {
	port, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	name, err := port.mutexName(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, sid, err := windowssecurity.CurrentUserSID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// This deliberately squatted object is owned by the caller but grants
	// MUTEX_ALL_ACCESS to Everyone. Acquire must inspect the existing object's
	// descriptor and reject it before waiting on or trusting the mutex.
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "G:" + sid + "D:P(A;;0x001F0001;;;WD)",
	)
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateMutex(attributes, false, namePointer)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(namePointer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if lock, err := port.Acquire(ctx); err == nil {
		_ = lock.Release(context.Background())
		t.Fatal("pre-existing installation mutex with a foreign DACL was trusted")
	} else if !errors.Is(err, windowssecurity.ErrOwnerMutexSecurity) {
		t.Fatalf("squatted mutex did not fail through descriptor verification: %v", err)
	}
}
