//go:build darwin

package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const processTreeTerminationGrace = 2 * time.Second

// runCommandInProcessTree observes leader exit through EVFILT_PROC without
// reaping it, keeping the PGID reserved until final group termination.
func runCommandInProcessTree(ctx context.Context, command *exec.Cmd) error {
	if ctx == nil || command == nil {
		return os.ErrInvalid
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = nil
	command.WaitDelay = 0
	if err := command.Start(); err != nil {
		return err
	}
	pid := command.Process.Pid
	if pid <= 0 {
		_ = command.Process.Kill()
		closeConversationInput(command)
		_ = command.Wait()
		return os.ErrInvalid
	}
	queue, err := unix.Kqueue()
	if err != nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		closeConversationInput(command)
		_ = command.Wait()
		return err
	}
	defer func() { _ = unix.Close(queue) }()
	change := unix.Kevent_t{
		// Cmd.Start returns a positive native PID; uint64 can represent every
		// positive int value on every supported Darwin architecture.
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(queue, []unix.Kevent_t{change}, nil, nil); err != nil {
		// A very short-lived leader can become a zombie before EVFILT_PROC is
		// registered. ESRCH is safe to recover only after the reserved group is
		// synchronously settled; Cmd.Wait then preserves the leader's exact exit
		// status instead of misreporting an observation failure.
		if errors.Is(err, syscall.ESRCH) {
			settlementError := terminateReservedProcessGroup(pid)
			closeConversationInput(command)
			waitError := command.Wait()
			if settlementError != nil {
				return errors.Join(err, settlementError)
			}
			return waitError
		}
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		closeConversationInput(command)
		_ = command.Wait()
		return err
	}
	return superviseUnixProcessGroup(ctx, command, pid, func(timeout time.Duration) (bool, error) {
		events := make([]unix.Kevent_t, 1)
		timespec := unix.NsecToTimespec(timeout.Nanoseconds())
		count, eventError := unix.Kevent(queue, nil, events, &timespec)
		if eventError != nil && !errors.Is(eventError, unix.EINTR) {
			return false, eventError
		}
		return count == 1 && events[0].Fflags&unix.NOTE_EXIT != 0, nil
	})
}

func terminateReservedProcessGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if !errors.Is(err, syscall.EPERM) {
		return err
	}
	// Darwin reports EPERM when a process group contains only its zombie
	// leader. The leader remains unreaped, so the PGID cannot be reused while
	// this process-table proof is taken.
	processes, queryError := unix.SysctlKinfoProcSlice("kern.proc.all")
	if queryError != nil {
		return err
	}
	for _, candidate := range processes {
		if int(candidate.Eproc.Pgid) == pid && int(candidate.Proc.P_pid) != pid {
			return err
		}
	}
	return nil
}
