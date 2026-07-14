//go:build linux

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

// runCommandInProcessTree observes leader exit through pidfd without reaping
// it. The unreaped leader reserves the PGID, so a final group kill cannot hit a
// reused process group. Only after all surviving members have SIGKILL pending
// is the leader reaped through Cmd.Wait.
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
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = command.Wait()
		return err
	}
	defer func() { _ = unix.Close(pidfd) }()
	if pidfd > int(^uint32(0)>>1) {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = command.Wait()
		return os.ErrInvalid
	}
	return superviseUnixProcessGroup(ctx, command, pid, func(timeout time.Duration) (bool, error) {
		milliseconds := int(timeout / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		descriptors := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}} // #nosec G115 -- pidfd is bounded to int32 above.
		_, pollError := unix.Poll(descriptors, milliseconds)
		if pollError != nil && !errors.Is(pollError, unix.EINTR) {
			return false, pollError
		}
		return descriptors[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0, nil
	})
}

func terminateReservedProcessGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
