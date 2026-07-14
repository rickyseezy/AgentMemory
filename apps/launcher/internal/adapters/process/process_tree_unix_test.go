//go:build darwin || linux

package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type cancellationWriter struct {
	cancel context.CancelFunc
	once   sync.Once
}

func (w *cancellationWriter) Write(value []byte) (int, error) {
	w.once.Do(w.cancel)
	return len(value), nil
}

func TestPF001UnixProcessTreeRejectsInvalidCommand(t *testing.T) {
	unusedCommand := exec.CommandContext(context.Background(), "/not-used")
	//lint:ignore SA1012 Deliberate nil-context attack proves process supervision fails closed.
	//nolint:staticcheck // SA1012: deliberate nil-context attack; owner=security expiry=2027-07-14.
	nilContextError := runCommandInProcessTree(nil, unusedCommand)
	if !errors.Is(nilContextError, os.ErrInvalid) {
		t.Fatalf("nil context error = %v", nilContextError)
	}
	if err := runCommandInProcessTree(context.Background(), nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil command error = %v", err)
	}
	missing := exec.CommandContext(context.Background(), "/agentmemory/missing/process") // #nosec G204 -- fixed missing test path.
	if err := runCommandInProcessTree(context.Background(), missing); err == nil {
		t.Fatal("missing executable was launched")
	}
}

func TestPF001UnixProcessSupervisorKillsGroupOnObservationFailure(t *testing.T) {
	executable := testCurrentExecutable(t)
	command := exec.CommandContext(context.Background(), executable, "-test.run=^TestPF001ArgvRunnerHelper$", "--", "wait") // #nosec G204 -- current test executable and fixed argv.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	want := errors.New("process observation failed")
	err := superviseUnixProcessGroup(context.Background(), command, command.Process.Pid, func(time.Duration) (bool, error) {
		return false, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("supervisor error = %v", err)
	}
}

func TestPF001UnixProcessTreeEscalatesIgnoredTermination(t *testing.T) {
	executable := testCurrentExecutable(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestPF001ArgvRunnerHelper$", "--", "ignore-termination") // #nosec G204 -- current test executable and fixed argv.
	command.Stdout = &cancellationWriter{cancel: cancel}
	started := time.Now()
	err := runCommandInProcessTree(ctx, command)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("termination-resistant process exited successfully")
	}
	if elapsed < processTreeTerminationGrace {
		t.Fatalf("SIGKILL escalation occurred after %s, before grace %s", elapsed, processTreeTerminationGrace)
	}
	if elapsed > processTreeTerminationGrace+10*time.Second {
		t.Fatalf("SIGKILL escalation exceeded bound: %s", elapsed)
	}
}

func TestPF001ArgvRunnerCancellationLeavesNoGrandchildProcess(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	startedMarker := filepath.Join(t.TempDir(), "grandchild-started")
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "spawn-child", startedMarker,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cancellationComplete := make(chan struct{})
	go func() {
		defer close(cancellationComplete)
		for ctx.Err() == nil {
			if _, statError := os.Lstat(startedMarker); statError == nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	result, runError := mustTestRunner(t, executable).Run(ctx, invocation)
	<-cancellationComplete
	if !errors.Is(runError, context.Canceled) {
		t.Fatalf("cancellation error = %v", runError)
	}
	pid, parseError := strconv.Atoi(strings.TrimSpace(string(result.StandardOutput)))
	if parseError != nil || pid <= 0 {
		t.Fatalf("grandchild pid output = %q, %v", result.StandardOutput, parseError)
	}
	requireProcessGone(t, pid)
}

func TestPF001ArgvRunnerNormalParentExitLeavesNoGrandchildProcess(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "spawn-child-and-exit",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, runError := mustTestRunner(t, executable).Run(context.Background(), invocation)
	if runError != nil {
		t.Fatalf("normal parent exit error = %v", runError)
	}
	pid, parseError := strconv.Atoi(strings.TrimSpace(string(result.StandardOutput)))
	if parseError != nil || pid <= 0 {
		t.Fatalf("grandchild pid output = %q, %v", result.StandardOutput, parseError)
	}
	requireProcessGone(t, pid)
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if processGoneOrZombie(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("grandchild process %d survived process-tree settlement", pid)
}
