//go:build darwin || linux

package process

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"
)

func superviseUnixProcessGroup(
	ctx context.Context,
	command *exec.Cmd,
	pid int,
	leaderExited func(time.Duration) (bool, error),
) error {
	terminationStarted := false
	terminationDeadline := time.Time{}
	for {
		exited, err := leaderExited(20 * time.Millisecond)
		if err != nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			closeConversationInput(command)
			_ = command.Wait()
			return err
		}
		if exited {
			// The leader remains unreaped here, so pid/PGID reuse is impossible
			// while surviving group members are made non-executable.
			if err := terminateReservedProcessGroup(pid); err != nil {
				closeConversationInput(command)
				_ = command.Wait()
				return err
			}
			conversationInputClosed := closeConversationInput(command)
			waitError := command.Wait()
			// Closing the internal reader is how the supervisor unblocks exec's
			// stdin copier after leader exit. If the child itself succeeded, the
			// resulting ErrClosedPipe describes that teardown, not child failure.
			if conversationInputClosed && errors.Is(waitError, io.ErrClosedPipe) &&
				command.ProcessState != nil && command.ProcessState.Success() {
				return nil
			}
			return waitError
		}
		if ctx.Err() != nil && !terminationStarted {
			terminationStarted = true
			terminationDeadline = time.Now().Add(processTreeTerminationGrace)
			if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				_ = terminateReservedProcessGroup(pid)
				closeConversationInput(command)
				_ = command.Wait()
				return err
			}
		}
		if terminationStarted && time.Now().After(terminationDeadline) {
			if err := terminateReservedProcessGroup(pid); err != nil {
				closeConversationInput(command)
				_ = command.Wait()
				return err
			}
		}
	}
}
