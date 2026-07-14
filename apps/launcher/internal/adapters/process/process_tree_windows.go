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
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsProcessObservationInterval  = 20 * time.Millisecond
	maximumWindowsCommandLineUnits     = 32767
	maximumWindowsBrokerInputBytes     = 1024 * 1024
	windowsJobCompletionKey            = uintptr(0x50463031)
	windowsJobMessageActiveProcessZero = uint32(4)
	windowsJobTerminationExitCode      = uint32(0xc000013a)
	windowsJobProcessSnapshotLimit     = 4096

	// ProcThreadAttributeValue(13, FALSE, TRUE, FALSE). x/sys does not yet
	// export this Windows 10 / Server 2016 attribute. Update fails closed on
	// platforms that do not implement it.
	windowsProcThreadAttributeJobList = uintptr(0x0002000d)
)

type windowsProcessExitError struct {
	code uint32
}

func (e *windowsProcessExitError) Error() string {
	return fmt.Sprintf("windows process exited with code %d", e.code)
}

func (e *windowsProcessExitError) ExitCode() int { return int(e.code) }

type windowsJobCompletionPort struct {
	completionKey  uintptr
	completionPort windows.Handle
}

type windowsJobBasicAccountingInformation struct {
	totalUserTime             int64
	totalKernelTime           int64
	thisPeriodTotalUserTime   int64
	thisPeriodTotalKernelTime int64
	totalPageFaultCount       uint32
	totalProcesses            uint32
	activeProcesses           uint32
	totalTerminatedProcesses  uint32
}

type windowsJobBasicProcessIDList struct {
	numberOfAssignedProcesses uint32
	numberOfProcessIDsInList  uint32
	processIDList             [1]uintptr
}

type windowsJobResources struct {
	job            windows.Handle
	completionPort windows.Handle
}

func newWindowsJobResources() (*windowsJobResources, error) {
	resources := &windowsJobResources{}
	failed := true
	defer func() {
		if failed {
			_ = resources.close()
		}
	}()

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	resources.job = job
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if result, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), //nolint:gosec // G103: Win32 consumes the exact documented structure pointer.
		uint32(unsafe.Sizeof(limits)),
	); err != nil || result == 0 {
		return nil, errors.Join(err, os.ErrInvalid)
	}

	completionPort, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	resources.completionPort = completionPort
	association := windowsJobCompletionPort{
		completionKey:  windowsJobCompletionKey,
		completionPort: completionPort,
	}
	if result, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&association)), //nolint:gosec // G103: Win32 consumes the exact documented structure pointer.
		uint32(unsafe.Sizeof(association)),
	); err != nil || result == 0 {
		return nil, errors.Join(err, os.ErrInvalid)
	}
	runtime.KeepAlive(limits)
	runtime.KeepAlive(association)
	failed = false
	return resources, nil
}

func (r *windowsJobResources) close() error {
	if r == nil {
		return nil
	}
	var result error
	if r.job != 0 && r.job != windows.InvalidHandle {
		result = errors.Join(result, windows.CloseHandle(r.job))
		r.job = 0
	}
	if r.completionPort != 0 && r.completionPort != windows.InvalidHandle {
		result = errors.Join(result, windows.CloseHandle(r.completionPort))
		r.completionPort = 0
	}
	return result
}

type windowsBrokerPipes struct {
	stdinWriter  *os.File
	stdoutReader *os.File
	stderrReader *os.File
	childHandles []windows.Handle
}

func newWindowsBrokerPipes() (*windowsBrokerPipes, error) {
	pipes := &windowsBrokerPipes{}
	failed := true
	defer func() {
		if failed {
			_ = pipes.close()
		}
	}()

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	pipes.stdinWriter = stdinWriter
	stdinHandle, err := duplicateInheritableWindowsHandle(stdinReader)
	if err != nil {
		return nil, err
	}
	pipes.childHandles = append(pipes.childHandles, stdinHandle)

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	pipes.stdoutReader = stdoutReader
	stdoutHandle, err := duplicateInheritableWindowsHandle(stdoutWriter)
	if err != nil {
		return nil, err
	}
	pipes.childHandles = append(pipes.childHandles, stdoutHandle)

	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	pipes.stderrReader = stderrReader
	stderrHandle, err := duplicateInheritableWindowsHandle(stderrWriter)
	if err != nil {
		return nil, err
	}
	pipes.childHandles = append(pipes.childHandles, stderrHandle)
	failed = false
	return pipes, nil
}

func duplicateInheritableWindowsHandle(file *os.File) (windows.Handle, error) {
	if file == nil {
		return 0, os.ErrInvalid
	}
	currentProcess := windows.CurrentProcess()
	var duplicated windows.Handle
	duplicateError := windows.DuplicateHandle(
		currentProcess,
		windows.Handle(file.Fd()),
		currentProcess,
		&duplicated,
		0,
		true,
		windows.DUPLICATE_SAME_ACCESS,
	)
	closeError := file.Close()
	if duplicateError != nil || closeError != nil {
		if duplicated != 0 && duplicated != windows.InvalidHandle {
			_ = windows.CloseHandle(duplicated)
		}
		return 0, errors.Join(duplicateError, closeError)
	}
	return duplicated, nil
}

func (p *windowsBrokerPipes) closeChildHandles() error {
	if p == nil {
		return nil
	}
	var result error
	for index, handle := range p.childHandles {
		if handle != 0 && handle != windows.InvalidHandle {
			if err := windows.CloseHandle(handle); err != nil {
				result = errors.Join(result, err)
			} else {
				p.childHandles[index] = 0
			}
		}
	}
	return result
}

func (p *windowsBrokerPipes) close() error {
	if p == nil {
		return nil
	}
	result := p.closeChildHandles()
	for _, file := range []*os.File{p.stdinWriter, p.stdoutReader, p.stderrReader} {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	p.stdinWriter, p.stdoutReader, p.stderrReader = nil, nil, nil
	return result
}

func (p *windowsBrokerPipes) startCopies(command *exec.Cmd) <-chan error {
	results := make(chan error, 3)
	stdinWriter, stdoutReader, stderrReader := p.stdinWriter, p.stdoutReader, p.stderrReader
	p.stdinWriter, p.stdoutReader, p.stderrReader = nil, nil, nil
	go func() {
		var copyError error
		if command.Stdin != nil {
			_, copyError = io.Copy(stdinWriter, command.Stdin)
		}
		closeError := stdinWriter.Close()
		if benignWindowsPipeClosure(copyError) {
			copyError = nil
		}
		results <- errors.Join(copyError, closeError)
	}()
	go func() {
		_, copyError := io.Copy(command.Stdout, stdoutReader)
		results <- errors.Join(copyError, stdoutReader.Close())
	}()
	go func() {
		_, copyError := io.Copy(command.Stderr, stderrReader)
		results <- errors.Join(copyError, stderrReader.Close())
	}()
	return results
}

func benignWindowsPipeClosure(err error) bool {
	return err == nil || errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_OPERATION_ABORTED) || errors.Is(err, os.ErrClosed)
}

func collectWindowsBrokerCopies(results <-chan error) error {
	var result error
	for range 3 {
		result = errors.Join(result, <-results)
	}
	return result
}

// runCommandInProcessTree uses the Windows creation-time JOB_LIST attribute,
// so the first instruction in the leader and every descendant is constrained
// by a private non-breakaway Job Object. Only duplicated stdio pipe handles are
// inherited. The function retains and settles that job before returning.
func runCommandInProcessTree(ctx context.Context, command *exec.Cmd) error {
	if err := validateWindowsBrokerCommand(ctx, command); err != nil {
		return err
	}
	applicationName, commandLine, environment, currentDirectory, err := prepareWindowsProcessContract(command)
	if err != nil {
		return os.ErrInvalid
	}
	pipes, err := newWindowsBrokerPipes()
	if err != nil {
		return err
	}
	defer func() { _ = pipes.close() }()
	job, err := newWindowsJobResources()
	if err != nil {
		return err
	}
	defer func() { _ = job.close() }()

	attributeList, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return err
	}
	attributeListDeleted := false
	defer func() {
		if !attributeListDeleted {
			attributeList.Delete()
		}
	}()
	if err := attributeList.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&pipes.childHandles[0]), //nolint:gosec // G103: HANDLE_LIST requires a contiguous native HANDLE array.
		uintptr(len(pipes.childHandles))*unsafe.Sizeof(pipes.childHandles[0]),
	); err != nil {
		return err
	}
	jobHandles := []windows.Handle{job.job}
	if err := attributeList.Update(
		windowsProcThreadAttributeJobList,
		unsafe.Pointer(&jobHandles[0]), //nolint:gosec // G103: JOB_LIST requires a contiguous native HANDLE array.
		unsafe.Sizeof(jobHandles[0]),
	); err != nil {
		return err
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  pipes.childHandles[0],
			StdOutput: pipes.childHandles[1],
			StdErr:    pipes.childHandles[2],
		},
		ProcThreadAttributeList: attributeList.List(),
	}
	processInformation := windows.ProcessInformation{}
	if err := ctx.Err(); err != nil {
		return err
	}
	creationError := windows.CreateProcess(
		&applicationName[0],
		&commandLine[0],
		nil,
		nil,
		true,
		windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0],
		&currentDirectory[0],
		&startup.StartupInfo,
		&processInformation,
	)
	runtime.KeepAlive(applicationName)
	runtime.KeepAlive(commandLine)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(currentDirectory)
	runtime.KeepAlive(pipes.childHandles)
	runtime.KeepAlive(jobHandles)
	runtime.KeepAlive(startup)
	// UpdateProcThreadAttribute requires its value storage to remain valid until
	// the list is destroyed. Destroy the list before zeroing or closing any
	// handle values referenced by HANDLE_LIST or JOB_LIST.
	attributeList.Delete()
	attributeListDeleted = true
	childHandleCloseError := pipes.closeChildHandles()
	if creationError != nil {
		return errors.Join(creationError, childHandleCloseError)
	}
	if processInformation.Process == 0 || processInformation.Thread == 0 {
		var settlementError error
		if processInformation.Thread != 0 {
			settlementError = errors.Join(settlementError, windows.CloseHandle(processInformation.Thread))
		}
		if processInformation.Process != 0 {
			settlementError = errors.Join(
				settlementError,
				abortWindowsCreatedProcess(processInformation.Process, job.job, job.completionPort),
			)
		}
		return errors.Join(os.ErrInvalid, childHandleCloseError, settlementError)
	}
	threadCloseError := windows.CloseHandle(processInformation.Thread)
	if childHandleCloseError != nil || threadCloseError != nil {
		settlementError := abortWindowsCreatedProcess(
			processInformation.Process,
			job.job,
			job.completionPort,
		)
		return errors.Join(childHandleCloseError, threadCloseError, settlementError, pipes.closeChildHandles())
	}
	copyResults := pipes.startCopies(command)
	exitStatus, cancelled, supervisionError := superviseWindowsJob(
		ctx,
		processInformation.Process,
		job.job,
		job.completionPort,
	)
	copyError := collectWindowsBrokerCopies(copyResults)
	resourceCloseError := job.close()
	operationalError := errors.Join(
		childHandleCloseError,
		threadCloseError,
		supervisionError,
		copyError,
		resourceCloseError,
	)
	if operationalError != nil {
		return operationalError
	}
	if cancelled {
		return ctx.Err()
	}
	if exitStatus != 0 {
		return &windowsProcessExitError{code: exitStatus}
	}
	return nil
}

func validateWindowsBrokerCommand(ctx context.Context, command *exec.Cmd) error {
	if ctx == nil || command == nil {
		return os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if command.Err != nil || command.Process != nil ||
		command.ProcessState != nil || command.SysProcAttr != nil || command.WaitDelay != 0 ||
		len(command.ExtraFiles) != 0 || nilInterfaceValue(command.Stdout) || nilInterfaceValue(command.Stderr) ||
		len(command.Args) == 0 || command.Args[0] != command.Path || command.Path == "" || command.Dir == "" ||
		!filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path ||
		!filepath.IsAbs(command.Dir) || filepath.Clean(command.Dir) != command.Dir ||
		strings.IndexByte(command.Path, 0) >= 0 || strings.IndexByte(command.Dir, 0) >= 0 {
		return os.ErrInvalid
	}
	if command.Stdin != nil {
		input, ok := command.Stdin.(*bytes.Reader)
		if !ok || input == nil || input.Len() <= 0 || input.Len() > maximumWindowsBrokerInputBytes {
			return os.ErrInvalid
		}
	}
	for _, argument := range command.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return os.ErrInvalid
		}
	}
	return nil
}

func abortWindowsCreatedProcess(process, job, completionPort windows.Handle) error {
	processes, snapshotError := snapshotWindowsJobProcesses(job)
	defer closeWindowsProcessHandles(processes)
	result := errors.Join(snapshotError, terminateWindowsJob(job))
	waitResult, waitError := windows.WaitForSingleObject(process, windows.INFINITE)
	if waitError != nil || waitResult != windows.WAIT_OBJECT_0 {
		result = errors.Join(result, waitError, os.ErrInvalid)
	}
	result = errors.Join(result, waitForWindowsProcessHandles(processes), windows.CloseHandle(process))
	return errors.Join(result, waitForWindowsJobSettlement(job, completionPort))
}

func nilInterfaceValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() { //nolint:exhaustive // only the nil-capable reflection kinds require special handling.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func prepareWindowsProcessContract(command *exec.Cmd) (applicationName, commandLine, environment, currentDirectory []uint16, err error) {
	applicationName, err = windows.UTF16FromString(command.Path)
	if err != nil || len(applicationName) > maximumWindowsCommandLineUnits {
		return nil, nil, nil, nil, os.ErrInvalid
	}
	commandLine, err = windows.UTF16FromString(windows.ComposeCommandLine(command.Args))
	if err != nil || len(commandLine) > maximumWindowsCommandLineUnits {
		return nil, nil, nil, nil, os.ErrInvalid
	}
	environment, err = prepareWindowsEnvironment(command.Env)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	currentDirectory, err = windows.UTF16FromString(command.Dir)
	if err != nil || len(currentDirectory) > maximumWindowsCommandLineUnits {
		return nil, nil, nil, nil, os.ErrInvalid
	}
	return applicationName, commandLine, environment, currentDirectory, nil
}

func prepareWindowsEnvironment(values []string) ([]uint16, error) {
	sorted := append([]string(nil), values...)
	sort.Slice(sorted, func(left, right int) bool {
		return strings.ToUpper(sorted[left]) < strings.ToUpper(sorted[right])
	})
	seen := make(map[string]struct{}, len(sorted))
	if len(sorted) == 0 {
		return []uint16{0, 0}, nil
	}
	block := make([]uint16, 0, 128)
	for _, entry := range sorted {
		separator := strings.IndexByte(entry, '=')
		if separator <= 0 || strings.IndexByte(entry, 0) >= 0 {
			return nil, os.ErrInvalid
		}
		key := strings.ToUpper(entry[:separator])
		if _, duplicate := seen[key]; duplicate {
			return nil, os.ErrInvalid
		}
		seen[key] = struct{}{}
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, os.ErrInvalid
		}
		block = append(block, encoded...)
		if len(block) >= maximumWindowsCommandLineUnits {
			return nil, os.ErrInvalid
		}
	}
	block = append(block, 0)
	return block, nil
}

func superviseWindowsJob(
	ctx context.Context,
	process, job, completionPort windows.Handle,
) (exitStatus uint32, cancelled bool, result error) {
	leaderExited := false
	for {
		waitResult, waitError := windows.WaitForSingleObject(process, uint32(windowsProcessObservationInterval/time.Millisecond))
		if waitError != nil {
			result = errors.Join(result, waitError)
			break
		}
		if waitResult == windows.WAIT_OBJECT_0 {
			leaderExited = true
			break
		}
		if waitResult != uint32(windows.WAIT_TIMEOUT) {
			result = errors.Join(result, os.ErrInvalid)
			break
		}
		if ctx.Err() != nil {
			cancelled = true
			break
		}
	}
	if leaderExited {
		result = errors.Join(result, windows.GetExitCodeProcess(process, &exitStatus))
	}
	processes, snapshotError := snapshotWindowsJobProcesses(job)
	defer closeWindowsProcessHandles(processes)
	result = errors.Join(result, snapshotError)
	result = errors.Join(result, terminateWindowsJob(job))
	if !leaderExited {
		waitResult, waitError := windows.WaitForSingleObject(process, windows.INFINITE)
		if waitError != nil || waitResult != windows.WAIT_OBJECT_0 {
			result = errors.Join(result, waitError, os.ErrInvalid)
		} else {
			result = errors.Join(result, windows.GetExitCodeProcess(process, &exitStatus))
		}
	}
	result = errors.Join(result, waitForWindowsProcessHandles(processes), windows.CloseHandle(process))
	result = errors.Join(result, waitForWindowsJobSettlement(job, completionPort))
	return exitStatus, cancelled, result
}

// snapshotWindowsJobProcesses retains synchronization handles for every job
// member observed immediately before termination. Windows can decrement the
// job's active-process accounting just before a terminated process object is
// signaled, so accounting alone is not a sufficient return barrier.
func snapshotWindowsJobProcesses(job windows.Handle) ([]windows.Handle, error) {
	for capacity := 16; capacity <= windowsJobProcessSnapshotLimit; capacity *= 2 {
		var layout windowsJobBasicProcessIDList
		headerBytes := int(unsafe.Offsetof(layout.processIDList))
		buffer := make([]byte, headerBytes+capacity*int(unsafe.Sizeof(uintptr(0))))
		//nolint:gosec // G103: the buffer is the documented variable-length JOBOBJECT_BASIC_PROCESS_ID_LIST layout.
		information := (*windowsJobBasicProcessIDList)(unsafe.Pointer(&buffer[0]))
		var returned uint32
		queryError := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicProcessIdList,
			uintptr(unsafe.Pointer(information)), //nolint:gosec // G103: Win32 fills the reviewed native structure.
			uint32(len(buffer)),                  // #nosec G115 -- the buffer is capped at 4096 native process identifiers.
			&returned,
		)
		runtime.KeepAlive(buffer)
		if errors.Is(queryError, windows.ERROR_MORE_DATA) ||
			information.numberOfAssignedProcesses > uint32(capacity) ||
			information.numberOfProcessIDsInList > uint32(capacity) {
			continue
		}
		if queryError != nil || returned < uint32(headerBytes) {
			return nil, errors.Join(queryError, os.ErrInvalid)
		}
		count := int(information.numberOfProcessIDsInList)
		//nolint:gosec // G103: the query proved count is bounded by the allocated trailing array.
		processIDs := (*[windowsJobProcessSnapshotLimit]uintptr)(unsafe.Pointer(&information.processIDList[0]))[:count:count]
		handles := make([]windows.Handle, 0, count)
		for _, processID := range processIDs {
			if processID == 0 || processID > uintptr(^uint32(0)) {
				closeWindowsProcessHandles(handles)
				return nil, os.ErrInvalid
			}
			handle, openError := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(processID))
			if errors.Is(openError, windows.ERROR_INVALID_PARAMETER) {
				continue
			}
			if openError != nil {
				closeWindowsProcessHandles(handles)
				return nil, openError
			}
			handles = append(handles, handle)
		}
		return handles, nil
	}
	return nil, os.ErrInvalid
}

func waitForWindowsProcessHandles(processes []windows.Handle) error {
	var result error
	for _, process := range processes {
		waitResult, waitError := windows.WaitForSingleObject(process, windows.INFINITE)
		if waitError != nil || waitResult != windows.WAIT_OBJECT_0 {
			result = errors.Join(result, waitError, os.ErrInvalid)
		}
	}
	return result
}

func closeWindowsProcessHandles(processes []windows.Handle) {
	for _, process := range processes {
		if process != 0 && process != windows.InvalidHandle {
			_ = windows.CloseHandle(process)
		}
	}
}

func terminateWindowsJob(job windows.Handle) error {
	active, queryError := activeWindowsJobProcesses(job)
	if queryError == nil && active == 0 {
		return nil
	}
	terminationError := windows.TerminateJobObject(job, windowsJobTerminationExitCode)
	return errors.Join(queryError, terminationError)
}

func waitForWindowsJobSettlement(job, completionPort windows.Handle) error {
	for {
		active, err := activeWindowsJobProcesses(job)
		if err != nil {
			return err
		}
		if active == 0 {
			return nil
		}
		var message uint32
		var key uintptr
		var overlappedValue uintptr
		// GetQueuedCompletionStatus writes a process ID, not necessarily an
		// OVERLAPPED pointer, for Job Object notifications. Store it in uintptr
		// so the garbage collector never scans an arbitrary PID as a Go pointer.
		//nolint:gosec // G103: Win32's output ABI is intentionally represented by uintptr.
		overlapped := (**windows.Overlapped)(unsafe.Pointer(&overlappedValue))
		err = windows.GetQueuedCompletionStatus(
			completionPort,
			&message,
			&key,
			overlapped,
			uint32(windowsProcessObservationInterval/time.Millisecond),
		)
		if errors.Is(err, windows.WAIT_TIMEOUT) {
			continue
		}
		if err != nil {
			return err
		}
		if key != windowsJobCompletionKey {
			return os.ErrInvalid
		}
		if message == windowsJobMessageActiveProcessZero {
			continue
		}
	}
}

func activeWindowsJobProcesses(job windows.Handle) (uint32, error) {
	information := windowsJobBasicAccountingInformation{}
	var returned uint32
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&information)), //nolint:gosec // G103: Win32 fills the exact documented structure pointer.
		uint32(unsafe.Sizeof(information)),
		&returned,
	)
	if err != nil || returned != uint32(unsafe.Sizeof(information)) {
		return 0, errors.Join(err, os.ErrInvalid)
	}
	return information.activeProcesses, nil
}
