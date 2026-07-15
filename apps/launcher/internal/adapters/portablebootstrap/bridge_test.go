package portablebootstrap

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

func TestPF001PortableBridgeReportsImmediatelyAndCancelsNativePackage(t *testing.T) {
	t.Parallel()
	installer := &installerStub{waitForCancellation: true}
	bridge, err := New(context.Background(), installer, &surfaceFactoryStub{})
	if err != nil {
		t.Fatal(err)
	}
	status, err := bridge.Status(context.Background())
	if err != nil || status.Sequence != 1 || status.State != string(setupprogressapp.StateRunning) ||
		status.Phase != string(setupprogressapp.PhaseVerifyRelease) || !status.Cancellable ||
		status.InstallationID != portableInstallationID || status.OperationID != portableOperationID {
		t.Fatalf("initial status = %+v, %v", status, err)
	}
	if _, err := bridge.OpenSetup(context.Background()); !errors.Is(err, errPortableUnavailable) {
		t.Fatalf("pre-install OpenSetup() error = %v", err)
	}
	result, err := bridge.Cancel(context.Background())
	if err != nil || !result.CancellationRequested || result.Status.Sequence != 2 ||
		result.Status.State != string(setupprogressapp.StateCancelled) {
		t.Fatalf("Cancel() = %+v, %v", result, err)
	}
	waited, err := bridge.WaitAfter(context.Background(), 1)
	if err != nil || waited.Sequence != 2 {
		t.Fatalf("WaitAfter() = %+v, %v", waited, err)
	}
	if _, err := bridge.Cancel(context.Background()); !errors.Is(err, errPortableConflict) {
		t.Fatalf("terminal Cancel() error = %v", err)
	}
	if _, err := bridge.ReadySurface(context.Background()); !errors.Is(err, errPortableUnavailable) {
		t.Fatalf("terminal ReadySurface() error = %v", err)
	}
	if err := bridge.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := bridge.Close(context.Background()); err != nil || installer.calls.Load() != 1 {
		t.Fatalf("second Close() error/calls = %v/%d", err, installer.calls.Load())
	}
}

func TestPF001PortableBridgeAdoptsAndSequenceMapsNativeSurface(t *testing.T) {
	t.Parallel()
	application := &applicationStub{status: nativeStatus(7, setupprogressapp.StateRunning)}
	application.wait = nativeStatus(8, setupprogressapp.StateReady)
	ready := &readyStub{surface: readySurface()}
	lifecycle := &lifecycleStub{}
	factory := &surfaceFactoryStub{surface: Surface{
		Application: application, Ready: ready, Lifecycle: lifecycle,
	}}
	bridge, err := New(context.Background(), &installerStub{}, factory)
	if err != nil {
		t.Fatal(err)
	}
	status, err := bridge.WaitAfter(context.Background(), 1)
	if err != nil || status.Sequence != 8 || status.State != string(setupprogressapp.StateRunning) {
		t.Fatalf("adopted status = %+v, %v", status, err)
	}
	waited, err := bridge.WaitAfter(context.Background(), status.Sequence)
	if err != nil || waited.Sequence != 9 || waited.State != string(setupprogressapp.StateReady) {
		t.Fatalf("mapped WaitAfter() = %+v, %v", waited, err)
	}
	opened, err := bridge.OpenSetup(context.Background())
	if err != nil || !opened.Opened || application.openCalls.Load() != 1 {
		t.Fatalf("OpenSetup() = %+v, %v calls=%d", opened, err, application.openCalls.Load())
	}
	cancelled, err := bridge.Cancel(context.Background())
	if err != nil || cancelled.Status.Sequence != 9 || application.cancelCalls.Load() != 1 {
		t.Fatalf("delegated Cancel() = %+v, %v", cancelled, err)
	}
	surface, err := bridge.ReadySurface(context.Background())
	if err != nil || len(surface.Tools) != 1 || ready.calls.Load() != 1 {
		t.Fatalf("ReadySurface() = %+v, %v calls=%d", surface, err, ready.calls.Load())
	}
	if err := bridge.Close(context.Background()); err != nil || lifecycle.calls.Load() != 1 || factory.calls.Load() != 1 {
		t.Fatalf("Close() error/lifecycle/factory = %v/%d/%d", err, lifecycle.calls.Load(), factory.calls.Load())
	}
}

func TestPF001PortableBridgeFailsClosedAtEveryCompositionAndAsyncBoundary(t *testing.T) {
	t.Parallel()
	var nilInstaller *installerStub
	var nilFactory *surfaceFactoryStub
	nilContext := func() (*Bridge, error) {
		//lint:ignore SA1012 The trust boundary must reject an adversarial nil context.
		return New(nil, &installerStub{}, &surfaceFactoryStub{}) //nolint:staticcheck // Boundary fixture; owner=launcher expiry=2027-07-15.
	}
	for name, build := range map[string]func() (*Bridge, error){
		"nil context":     nilContext,
		"nil installer":   func() (*Bridge, error) { return New(context.Background(), nil, &surfaceFactoryStub{}) },
		"typed installer": func() (*Bridge, error) { return New(context.Background(), nilInstaller, &surfaceFactoryStub{}) },
		"nil factory":     func() (*Bridge, error) { return New(context.Background(), &installerStub{}, nil) },
		"typed factory":   func() (*Bridge, error) { return New(context.Background(), &installerStub{}, nilFactory) },
	} {
		if bridge, err := build(); bridge != nil || !errors.Is(err, errPortableIntegrity) {
			t.Fatalf("%s New() = %T, %v", name, bridge, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if bridge, err := New(cancelled, &installerStub{}, &surfaceFactoryStub{}); bridge != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled New() = %T, %v", bridge, err)
	}

	for name, fixture := range map[string]struct {
		installer *installerStub
		factory   *surfaceFactoryStub
	}{
		"installer":       {installer: &installerStub{err: errors.New("private installer")}, factory: &surfaceFactoryStub{}},
		"factory":         {installer: &installerStub{}, factory: &surfaceFactoryStub{err: errors.New("private factory")}},
		"invalid surface": {installer: &installerStub{}, factory: &surfaceFactoryStub{}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bridge, err := New(context.Background(), fixture.installer, fixture.factory)
			if err != nil {
				t.Fatal(err)
			}
			status, err := bridge.WaitAfter(context.Background(), 1)
			if err != nil || status.State != string(setupprogressapp.StateFailed) ||
				status.Error == nil || status.Error.Code != "AM_DEPENDENCY_UNAVAILABLE" {
				t.Fatalf("failed status = %+v, %v", status, err)
			}
			_ = bridge.Close(context.Background())
		})
	}
}

func TestPF001PortableBridgeRejectsInvalidCallsOverflowAndCloseFailure(t *testing.T) {
	t.Parallel()
	var absent *Bridge
	if _, err := absent.Status(context.Background()); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil Status() error = %v", err)
	}
	if _, err := absent.WaitAfter(context.Background(), 0); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil WaitAfter() error = %v", err)
	}
	if _, err := absent.OpenSetup(context.Background()); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil OpenSetup() error = %v", err)
	}
	if _, err := absent.Cancel(context.Background()); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil Cancel() error = %v", err)
	}
	if _, err := absent.ReadySurface(context.Background()); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil ReadySurface() error = %v", err)
	}
	if err := absent.Close(context.Background()); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("nil Close() error = %v", err)
	}
	if _, err := mapStatus(nativeStatus(0, setupprogressapp.StateRunning), 1, nil); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("zero sequence error = %v", err)
	}
	if _, err := mapStatus(nativeStatus(2, setupprogressapp.StateRunning), math.MaxUint64-1, nil); !errors.Is(err, errPortableIntegrity) {
		t.Fatalf("overflow error = %v", err)
	}
	private := errors.New("private delegate")
	if _, err := mapStatus(mcpbootstrapapp.InstallationStatus{}, 0, private); !errors.Is(err, private) {
		t.Fatalf("delegate error = %v", err)
	}

	lifecycle := &lifecycleStub{err: private}
	bridge, err := New(context.Background(), &installerStub{}, &surfaceFactoryStub{surface: Surface{
		Application: &applicationStub{status: nativeStatus(1, setupprogressapp.StateRunning)},
		Ready:       &readyStub{surface: readySurface()}, Lifecycle: lifecycle,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.WaitAfter(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Close(context.Background()); !errors.Is(err, errPortableUnavailable) {
		t.Fatalf("sanitized Close() error = %v", err)
	}

	blocked := &installerStub{ignoreCancellation: true, release: make(chan struct{})}
	deadlineBridge, err := New(context.Background(), blocked, &surfaceFactoryStub{})
	if err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if err := deadlineBridge.Close(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline Close() error = %v", err)
	}
	close(blocked.release)
}

type installerStub struct {
	err                 error
	waitForCancellation bool
	ignoreCancellation  bool
	release             chan struct{}
	calls               atomic.Int32
}

func (s *installerStub) InstallNativePackage(ctx context.Context) error {
	s.calls.Add(1)
	if s.waitForCancellation {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.ignoreCancellation {
		<-s.release
	}
	return s.err
}

type surfaceFactoryStub struct {
	surface Surface
	err     error
	calls   atomic.Int32
}

func (s *surfaceFactoryStub) BuildInstalledSurface(context.Context) (Surface, error) {
	s.calls.Add(1)
	return s.surface, s.err
}

type applicationStub struct {
	status      mcpbootstrapapp.InstallationStatus
	wait        mcpbootstrapapp.InstallationStatus
	err         error
	openCalls   atomic.Int32
	cancelCalls atomic.Int32
}

func (s *applicationStub) Status(context.Context) (mcpbootstrapapp.InstallationStatus, error) {
	return s.status, s.err
}

func (s *applicationStub) WaitAfter(context.Context, uint64) (mcpbootstrapapp.InstallationStatus, error) {
	return s.wait, s.err
}

func (s *applicationStub) OpenSetup(context.Context) (mcpbootstrapapp.OpenSetupResult, error) {
	s.openCalls.Add(1)
	return mcpbootstrapapp.OpenSetupResult{Opened: true}, s.err
}

func (s *applicationStub) Cancel(context.Context) (mcpbootstrapapp.CancelResult, error) {
	s.cancelCalls.Add(1)
	return mcpbootstrapapp.CancelResult{CancellationRequested: true, Status: s.wait}, s.err
}

type readyStub struct {
	surface mcpbootstrap.ReadySurface
	err     error
	calls   atomic.Int32
}

func (s *readyStub) ReadySurface(context.Context) (mcpbootstrap.ReadySurface, error) {
	s.calls.Add(1)
	return s.surface, s.err
}

type lifecycleStub struct {
	err   error
	calls atomic.Int32
}

func (s *lifecycleStub) Close(context.Context) error {
	s.calls.Add(1)
	return s.err
}

func nativeStatus(sequence uint64, state setupprogressapp.State) mcpbootstrapapp.InstallationStatus {
	return mcpbootstrapapp.InstallationStatus{
		ContractVersion: setupprogressapp.ContractVersion, Sequence: sequence,
		InstallationID: "native-installation", OperationID: "native-operation",
		State: string(state), Phase: string(setupprogressapp.PhaseEnsureContainerRuntime),
		MessageKey: string(setupprogressapp.MessagePreparingRuntime),
	}
}

func readySurface() mcpbootstrap.ReadySurface {
	return mcpbootstrap.ReadySurface{Tools: []mcpbootstrap.ReadyTool{{
		Tool: &mcp.Tool{Name: "memory_status", InputSchema: map[string]any{"type": "object"}},
		Handler: func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		},
	}}}
}
