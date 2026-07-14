package installworker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
)

func TestPF001SupervisorCoalescesConcurrentExactInstallerStarts(t *testing.T) {
	installer := &blockingInstaller{entered: make(chan struct{}), release: make(chan struct{})}
	supervisor, err := New(installer)
	if err != nil {
		t.Fatal(err)
	}
	command := installapp.InstallCommand{OperationID: "019f5f1f-0000-7abc-8123-0123456789ab", CanonicalPlan: []byte("canonical")}
	const callers = 32
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			if err := supervisor.EnsureRunning(context.Background(), command); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	select {
	case <-installer.entered:
	case <-time.After(time.Second):
		t.Fatal("installer did not start")
	}
	if installer.calls.Load() != 1 {
		t.Fatalf("installer calls=%d", installer.calls.Load())
	}
	close(installer.release)
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001SupervisorOwnsCommandAndOutlivesRequestCancellation(t *testing.T) {
	installer := &capturingInstaller{done: make(chan struct{})}
	supervisor, _ := New(installer)
	canonical := []byte("canonical")
	ctx, cancel := context.WithCancel(context.Background())
	command := installapp.InstallCommand{OperationID: "019f5f1f-0000-7abc-8123-0123456789ab", CanonicalPlan: canonical}
	if err := supervisor.EnsureRunning(ctx, command); err != nil {
		t.Fatal(err)
	}
	canonical[0] = 'X'
	cancel()
	select {
	case <-installer.done:
	case <-time.After(time.Second):
		t.Fatal("worker remained request-bound")
	}
	if string(installer.command.CanonicalPlan) != "canonical" || installer.ctxErr != nil {
		t.Fatalf("captured=%q ctx=%v", installer.command.CanonicalPlan, installer.ctxErr)
	}
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001SupervisorRejectsInvalidStateAndCancelsOwnedWorkers(t *testing.T) {
	var typedNil *capturingInstaller
	if supervisor, err := New(typedNil); supervisor != nil || !errors.Is(err, ErrSupervisorUnavailable) {
		t.Fatalf("New()=%v,%v", supervisor, err)
	}
	installer := &cancellationInstaller{done: make(chan struct{})}
	supervisor, _ := New(installer)
	for _, command := range []installapp.InstallCommand{{}, {OperationID: "valid-operation", CanonicalPlan: nil}} {
		if err := supervisor.EnsureRunning(context.Background(), command); !errors.Is(err, ErrSupervisorUnavailable) {
			t.Fatalf("invalid command error=%v", err)
		}
	}
	command := installapp.InstallCommand{OperationID: "019f5f1f-0000-7abc-8123-0123456789ab", CanonicalPlan: []byte("canonical")}
	if err := supervisor.EnsureRunning(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-installer.done:
	default:
		t.Fatal("worker was not cancelled")
	}
	if err := supervisor.EnsureRunning(context.Background(), command); !errors.Is(err, ErrSupervisorUnavailable) {
		t.Fatalf("closed start error=%v", err)
	}
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatalf("idempotent close=%v", err)
	}
}

type blockingInstaller struct {
	calls            atomic.Int32
	entered, release chan struct{}
}

func (i *blockingInstaller) Install(context.Context, installapp.InstallCommand) (installapp.InstallResult, error) {
	i.calls.Add(1)
	close(i.entered)
	<-i.release
	return installapp.InstallResult{}, nil
}

type capturingInstaller struct {
	command installapp.InstallCommand
	ctxErr  error
	done    chan struct{}
}

func (i *capturingInstaller) Install(ctx context.Context, command installapp.InstallCommand) (installapp.InstallResult, error) {
	i.command = command
	i.ctxErr = ctx.Err()
	close(i.done)
	return installapp.InstallResult{}, nil
}

type cancellationInstaller struct{ done chan struct{} }

func (i *cancellationInstaller) Install(ctx context.Context, _ installapp.InstallCommand) (installapp.InstallResult, error) {
	<-ctx.Done()
	close(i.done)
	return installapp.InstallResult{}, ctx.Err()
}
