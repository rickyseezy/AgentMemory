//go:build windows

package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPF001WindowsJobBrokerPreservesExactStdioEnvironmentWorkingDirectoryAndExitCode(t *testing.T) {
	executable := testCurrentExecutable(t)
	workingDirectory := filepath.VolumeName(executable) + `\`
	command, stdout, stderr := windowsBrokerTestCommand(
		context.Background(),
		t,
		executable,
		workingDirectory,
		"stdio-exit",
		"23",
		"literal ; $(not-a-shell)",
	)
	command.Stdin = bytes.NewReader([]byte("bounded standard input"))

	runError := runCommandInProcessTree(context.Background(), command)
	if runError == nil || exitCode(runError) != 23 {
		t.Fatalf("run error/exit = %v/%d, want non-nil/23", runError, exitCode(runError))
	}
	wantOutput := strings.Join([]string{
		"argument=literal ; $(not-a-shell)",
		"explicit=present",
		"ambient-path=",
		"cwd=" + workingDirectory,
		"stdin=bounded standard input",
		"",
	}, "\n")
	if stdout.String() != wantOutput || stderr.String() != "verified stderr\n" {
		t.Fatalf("stdout/stderr = %q/%q, want %q/%q", stdout.String(), stderr.String(), wantOutput, "verified stderr\n")
	}
}

func TestPF001WindowsJobBrokerCancellationSettlesDescendantsBeforeReturn(t *testing.T) {
	executable := testCurrentExecutable(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command, _, _ := windowsBrokerTestCommand(
		ctx,
		t,
		executable,
		filepath.VolumeName(executable)+`\`,
		"spawn-child",
		"wait",
	)
	stdout := &windowsCancellationBuffer{cancel: cancel}
	command.Stdout = stdout

	runError := runCommandInProcessTree(ctx, command)
	if !errors.Is(runError, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", runError)
	}
	requireWindowsProcessSettled(t, parseWindowsHelperPID(t, stdout.String()))
}

func TestPF001WindowsJobBrokerDisallowsExplicitBreakaway(t *testing.T) {
	executable := testCurrentExecutable(t)
	command, stdout, _ := windowsBrokerTestCommand(
		context.Background(),
		t,
		executable,
		filepath.VolumeName(executable)+`\`,
		"attempt-breakaway",
	)
	if runError := runCommandInProcessTree(context.Background(), command); runError != nil {
		t.Fatalf("breakaway probe error = %v, output=%q", runError, stdout.String())
	}
	if stdout.String() != "breakaway=denied\n" {
		t.Fatalf("job allowed explicit child breakaway: %q", stdout.String())
	}
}

func TestPF001WindowsJobBrokerNormalLeaderExitSettlesDescendantsBeforeReturn(t *testing.T) {
	executable := testCurrentExecutable(t)
	command, stdout, _ := windowsBrokerTestCommand(
		context.Background(),
		t,
		executable,
		filepath.VolumeName(executable)+`\`,
		"spawn-child",
		"exit",
	)

	if runError := runCommandInProcessTree(context.Background(), command); runError != nil {
		t.Fatalf("normal leader exit error = %v", runError)
	}
	requireWindowsProcessSettled(t, parseWindowsHelperPID(t, stdout.String()))
}

func TestPF001WindowsJobBrokerInheritsOnlyExplicitStdioHandles(t *testing.T) {
	security := &windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	event, err := windows.CreateEvent(security, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(event) })

	executable := testCurrentExecutable(t)
	command, stdout, _ := windowsBrokerTestCommand(
		context.Background(),
		t,
		executable,
		filepath.VolumeName(executable)+`\`,
		"signal-handle",
		strconv.FormatUint(uint64(event), 10),
	)
	if runError := runCommandInProcessTree(context.Background(), command); runError != nil {
		t.Fatal(runError)
	}
	if stdout.String() != "inherited=false\n" {
		t.Fatalf("helper result = %q", stdout.String())
	}
	result, err := windows.WaitForSingleObject(event, 0)
	if err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("ambient event wait = %#x, %v; handle escaped into child", result, err)
	}
}

func TestPF001WindowsJobBrokerRejectsIncompleteOrCallerBroadenedCommand(t *testing.T) {
	valid := func() *exec.Cmd {
		executable := testCurrentExecutable(t)
		command, _, _ := windowsBrokerTestCommand(
			context.Background(),
			t,
			executable,
			filepath.VolumeName(executable)+`\`,
			"exit-zero",
		)
		return command
	}
	tests := []struct {
		name   string
		mutate func(*exec.Cmd)
	}{
		{name: "nil stdout", mutate: func(command *exec.Cmd) { command.Stdout = nil }},
		{name: "nil stderr", mutate: func(command *exec.Cmd) { command.Stderr = nil }},
		{name: "relative path", mutate: func(command *exec.Cmd) { command.Path = `relative.exe`; command.Args[0] = `relative.exe` }},
		{name: "argv zero mismatch", mutate: func(command *exec.Cmd) { command.Args[0] = `C:\substituted.exe` }},
		{name: "missing working directory", mutate: func(command *exec.Cmd) { command.Dir = "" }},
		{name: "caller process attributes", mutate: func(command *exec.Cmd) { command.SysProcAttr = &windows.SysProcAttr{} }},
		{name: "caller wait delay", mutate: func(command *exec.Cmd) { command.WaitDelay = time.Second }},
		{name: "unbounded input reader", mutate: func(command *exec.Cmd) { command.Stdin = strings.NewReader("not the bounded contract") }},
		{name: "oversized input", mutate: func(command *exec.Cmd) {
			command.Stdin = bytes.NewReader(make([]byte, maximumWindowsBrokerInputBytes+1))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := valid()
			test.mutate(command)
			if err := runCommandInProcessTree(context.Background(), command); !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("rejection error = %v, want os.ErrInvalid", err)
			}
		})
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves the native broker fails closed.
	//nolint:staticcheck // SA1012: deliberate nil-context attack; owner=security expiry=2027-07-14.
	if err := runCommandInProcessTree(nil, valid()); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := runCommandInProcessTree(context.Background(), nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil command error = %v", err)
	}
}

func TestPF001WindowsJobBrokerClosesNativeHandlesAcrossRepeatedRuns(t *testing.T) {
	// The race-enabled Go runtime lazily creates worker threads (and their
	// Windows synchronization handles) when the broker first exercises three
	// concurrent pipe copies. Establish that bounded runtime high-water mark
	// before measuring broker-owned handles.
	runWindowsBrokerExitBatch(t, 16)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := currentWindowsProcessHandleCount(t)
	goroutinesBefore := runtime.NumGoroutine()
	runWindowsBrokerExitBatch(t, 32)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := currentWindowsProcessHandleCount(t)
	if after > before+8 {
		t.Fatalf("process handles grew from %d to %d after the runtime warm-up", before, after)
	}
	if afterGoroutines := runtime.NumGoroutine(); afterGoroutines > goroutinesBefore+2 {
		t.Fatalf("goroutines grew from %d to %d across repeated runs", goroutinesBefore, afterGoroutines)
	}
}

func TestPF001WindowsBrokerPipeCloseReleasesEveryOwnedResource(t *testing.T) {
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdinReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
	})

	pipes := &windowsBrokerPipes{
		stdinWriter: stdinWriter, stdoutReader: stdoutReader, stderrReader: stderrReader,
	}
	if err := pipes.close(); err != nil {
		t.Fatal(err)
	}
	if pipes.stdinWriter != nil || pipes.stdoutReader != nil || pipes.stderrReader != nil {
		t.Fatalf("closed pipe ownership = %#v", pipes)
	}
	for _, file := range []*os.File{stdinWriter, stdoutReader, stderrReader} {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("owned pipe %q remains open", file.Name())
		}
	}
	if err := pipes.close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if err := (*windowsBrokerPipes)(nil).close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
}

func TestPF001WindowsBrokerChildHandleCloseZerosOnlyReleasedHandles(t *testing.T) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	pipes := &windowsBrokerPipes{childHandles: []windows.Handle{0, windows.InvalidHandle, event}}
	if err := pipes.closeChildHandles(); err != nil {
		t.Fatal(err)
	}
	if pipes.childHandles[0] != 0 || pipes.childHandles[1] != windows.InvalidHandle || pipes.childHandles[2] != 0 {
		t.Fatalf("closed child handles = %#v", pipes.childHandles)
	}
	if _, err := windows.WaitForSingleObject(event, 0); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("released event wait error = %v, want ERROR_INVALID_HANDLE", err)
	}
	if err := pipes.closeChildHandles(); err != nil {
		t.Fatalf("idempotent child handle close: %v", err)
	}
	if err := (*windowsBrokerPipes)(nil).closeChildHandles(); err != nil {
		t.Fatalf("nil child handle close: %v", err)
	}
}

func TestPF001WindowsBrokerCopyCollectionPreservesEveryFailure(t *testing.T) {
	first := errors.New("first copy")
	third := errors.New("third copy")
	results := make(chan error, 3)
	results <- first
	results <- nil
	results <- third
	result := collectWindowsBrokerCopies(results)
	if !errors.Is(result, first) || !errors.Is(result, third) {
		t.Fatalf("copy collection error = %v", result)
	}
}

func TestPF001WindowsBrokerRecognizesOnlyBenignPipeClosures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: true},
		{name: "broken pipe", err: windows.ERROR_BROKEN_PIPE, want: true},
		{name: "no data", err: windows.ERROR_NO_DATA, want: true},
		{name: "operation aborted", err: windows.ERROR_OPERATION_ABORTED, want: true},
		{name: "closed file", err: os.ErrClosed, want: true},
		{name: "closed Go pipe", err: io.ErrClosedPipe, want: true},
		{name: "wrapped closure", err: fmt.Errorf("copy: %w", windows.ERROR_BROKEN_PIPE), want: true},
		{name: "unrelated failure", err: errors.New("disk failure")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := benignWindowsPipeClosure(test.err); got != test.want {
				t.Fatalf("benignWindowsPipeClosure(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestPF001WindowsEnvironmentIsCanonicalBoundedAndNonMutating(t *testing.T) {
	values := []string{"z=last", "A=first", "m=middle"}
	original := append([]string(nil), values...)
	got, err := prepareWindowsEnvironment(values)
	if err != nil {
		t.Fatal(err)
	}
	var want []uint16
	for _, entry := range []string{"A=first", "m=middle", "z=last"} {
		encoded, encodeErr := windows.UTF16FromString(entry)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		want = append(want, encoded...)
	}
	want = append(want, 0)
	if !slices.Equal(got, want) {
		t.Fatalf("environment block = %#v, want %#v", got, want)
	}
	if !slices.Equal(values, original) {
		t.Fatalf("caller environment mutated from %#v to %#v", original, values)
	}

	empty, err := prepareWindowsEnvironment(nil)
	if err != nil || !slices.Equal(empty, []uint16{0, 0}) {
		t.Fatalf("empty environment = %#v, %v", empty, err)
	}
	for _, invalid := range [][]string{
		{"missing-separator"},
		{"=missing-key"},
		{"A=first", "a=duplicate"},
		{"A=value\x00suffix"},
	} {
		if value, err := prepareWindowsEnvironment(invalid); !errors.Is(err, os.ErrInvalid) || value != nil {
			t.Fatalf("prepareWindowsEnvironment(%q) = %#v, %v", invalid, value, err)
		}
	}
}

func TestPF001WindowsNilInterfaceDetectionRejectsTypedNilValues(t *testing.T) {
	var nilBuffer *bytes.Buffer
	if !nilInterfaceValue(nil) || !nilInterfaceValue(nilBuffer) {
		t.Fatal("nil interface values were accepted")
	}
	if nilInterfaceValue(&bytes.Buffer{}) || nilInterfaceValue(1) {
		t.Fatal("non-nil interface values were rejected")
	}
}

func runWindowsBrokerExitBatch(t *testing.T, iterations int) {
	t.Helper()
	executable := testCurrentExecutable(t)
	for iteration := 0; iteration < iterations; iteration++ {
		command, _, _ := windowsBrokerTestCommand(
			context.Background(),
			t,
			executable,
			filepath.VolumeName(executable)+`\`,
			"exit-zero",
		)
		if err := runCommandInProcessTree(context.Background(), command); err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
	}
}

func windowsBrokerTestCommand(
	ctx context.Context,
	t *testing.T,
	executable string,
	workingDirectory string,
	actionAndArguments ...string,
) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	arguments := append([]string{"-test.run=^TestPF001WindowsJobBrokerHelper$", "--"}, actionAndArguments...)
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- exact current test executable and fixed helper entrypoint.
	command.Env = []string{"AGENTMEMORY_EXPLICIT=present"}
	command.Dir = workingDirectory
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.Stdout, command.Stderr = stdout, stderr
	return command, stdout, stderr
}

type windowsCancellationBuffer struct {
	bytes.Buffer
	cancel context.CancelFunc
	once   sync.Once
}

func (b *windowsCancellationBuffer) Write(value []byte) (int, error) {
	written, err := b.Buffer.Write(value)
	if written > 0 {
		b.once.Do(b.cancel)
	}
	return written, err
}

func parseWindowsHelperPID(t *testing.T, output string) uint32 {
	t.Helper()
	value, err := strconv.ParseUint(strings.TrimSpace(output), 10, 32)
	if err != nil || value == 0 {
		t.Fatalf("helper PID output = %q, %v", output, err)
	}
	return uint32(value)
}

func requireWindowsProcessSettled(t *testing.T, processID uint32) {
	t.Helper()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	result, err := windows.WaitForSingleObject(process, 0)
	if err != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatalf("descendant %d remains active: wait=%#x error=%v", processID, result, err)
	}
}

func currentWindowsProcessHandleCount(t *testing.T) uint32 {
	t.Helper()
	procedure := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	var count uint32
	//nolint:gosec // G103: the native test passes a DWORD output address to GetProcessHandleCount.
	result, _, callError := procedure.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatalf("GetProcessHandleCount: %v", callError)
	}
	return count
}

// TestPF001WindowsJobBrokerHelper runs only in isolated child test processes.
func TestPF001WindowsJobBrokerHelper(_ *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(os.Args) {
		return
	}
	action := os.Args[separator+1]
	arguments := os.Args[separator+2:]
	switch action {
	case "stdio-exit":
		if len(arguments) != 2 {
			os.Exit(91)
		}
		exitStatus, err := strconv.Atoi(arguments[0])
		if err != nil {
			os.Exit(92)
		}
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(93)
		}
		workingDirectory, err := os.Getwd()
		if err != nil {
			os.Exit(94)
		}
		_, _ = fmt.Fprintf(os.Stdout, "argument=%s\nexplicit=%s\nambient-path=%s\ncwd=%s\nstdin=%s\n",
			arguments[1], os.Getenv("AGENTMEMORY_EXPLICIT"), os.Getenv("PATH"), workingDirectory, input)
		_, _ = os.Stderr.WriteString("verified stderr\n")
		os.Exit(exitStatus)
	case "spawn-child":
		if len(arguments) != 1 {
			os.Exit(95)
		}
		child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestPF001WindowsJobBrokerHelper$", "--", "linger") // #nosec G204,G702 -- exact current test executable and fixed helper entrypoint.
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(96)
		}
		_, _ = fmt.Fprintln(os.Stdout, child.Process.Pid)
		if arguments[0] == "wait" {
			time.Sleep(30 * time.Second)
		}
		os.Exit(0)
	case "linger":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "signal-handle":
		if len(arguments) != 1 {
			os.Exit(97)
		}
		value, err := strconv.ParseUint(arguments[0], 10, 64)
		if err != nil {
			os.Exit(98)
		}
		if err := windows.SetEvent(windows.Handle(value)); err != nil {
			_, _ = fmt.Fprintln(os.Stdout, "inherited=false")
		} else {
			_, _ = fmt.Fprintln(os.Stdout, "inherited=true")
		}
		os.Exit(0)
	case "attempt-breakaway":
		child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestPF001WindowsJobBrokerHelper$", "--", "linger") // #nosec G204,G702 -- exact current test executable and fixed helper entrypoint.
		child.Env = os.Environ()
		child.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB}
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintln(os.Stdout, "breakaway=denied")
			os.Exit(0)
		}
		_, _ = fmt.Fprintf(os.Stdout, "breakaway=allowed pid=%d\n", child.Process.Pid)
		_ = child.Process.Kill()
		_ = child.Wait()
		os.Exit(100)
	case "exit-zero":
		os.Exit(0)
	default:
		os.Exit(99)
	}
}
