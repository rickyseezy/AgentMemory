package launcher

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
)

func TestPF006ManagedNativeRuntimeApplicationSettlesNativeResources(t *testing.T) {
	t.Parallel()
	want := runtimeinstallapp.Result{OperationID: "019f5f9f-0000-7abc-8123-0123456789ab"}
	application := &nativeRuntimeApplicationStub{result: want}
	closer := &nativeRuntimeCloserStub{}
	managed := &managedNativeRuntimeApplication{
		application: application, closers: []nativeRuntimeResourceCloser{closer},
	}
	result, err := managed.Ensure(t.Context(), runtimeinstallapp.Command{})
	if err != nil || result != want || application.calls != 1 || closer.calls != 1 {
		t.Fatalf("result=%+v error=%v calls=%d/%d", result, err, application.calls, closer.calls)
	}
	if err := managed.Close(t.Context()); err != nil || closer.calls != 1 {
		t.Fatalf("idempotent close error=%v calls=%d", err, closer.calls)
	}
}

func TestPF006ManagedNativeRuntimeApplicationReportsCleanupFailure(t *testing.T) {
	t.Parallel()
	managed := &managedNativeRuntimeApplication{
		application: &nativeRuntimeApplicationStub{},
		closers:     []nativeRuntimeResourceCloser{&nativeRuntimeCloserStub{err: errors.New("private close")}},
	}
	if _, err := managed.Ensure(t.Context(), runtimeinstallapp.Command{}); !errors.Is(err, errNativeInstallerUnavailable) {
		t.Fatalf("cleanup failure error=%v", err)
	}
	var absent *managedNativeRuntimeApplication
	if _, err := absent.Ensure(t.Context(), runtimeinstallapp.Command{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent application error=%v", err)
	}
	if err := absent.Close(t.Context()); err != nil {
		t.Fatalf("absent close error=%v", err)
	}
}

func TestPF006NativePlatformRuntimeFactoryRejectsMissingAuthority(t *testing.T) {
	t.Parallel()
	if factory, err := newNativePlatformRuntimeFactory(nil, nil, nil); factory != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete factory=%+v error=%v", factory, err)
	}
	var absent *nativePlatformRuntimeFactory
	if application, err := absent.BuildRuntimeApplication(t.Context(), nativeVerifiedRuntimeExecution{}); application != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent platform application=%+v error=%v", application, err)
	}
	if application, err := absent.buildDesktopRuntimeApplication(t.Context(), nativeVerifiedRuntimeExecution{}); application != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent desktop application=%+v error=%v", application, err)
	}
	wantLinuxError := errNativeInstallerUnavailable
	if runtime.GOOS == "linux" {
		wantLinuxError = errNativeInstallerIntegrity
	}
	if application, err := (&nativePlatformRuntimeFactory{}).buildLinuxRuntimeApplication(
		t.Context(), nativeVerifiedRuntimeExecution{},
	); application != nil || !errors.Is(err, wantLinuxError) {
		t.Fatalf("Linux application=%+v error=%v want=%v", application, err, wantLinuxError)
	}
}

type nativeRuntimeCloserStub struct {
	calls int
	err   error
}

func (s *nativeRuntimeCloserStub) Close(context.Context) error {
	s.calls++
	return s.err
}
