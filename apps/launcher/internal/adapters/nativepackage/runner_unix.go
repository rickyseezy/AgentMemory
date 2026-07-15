//go:build darwin || linux

package nativepackage

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"
)

const nativeCommandWaitDelay = 5 * time.Second

func executeNativeCommand(ctx context.Context, command Command) (int, error) {
	if ctx == nil || command.Executable == "" {
		return -1, ErrInstallation
	}
	// #nosec G204 -- NativeCommandRunner accepts only closed absolute executable
	// and argv shapes before this private function is reachable in production.
	process := exec.CommandContext(ctx, command.Executable, command.Arguments...)
	process.Stdin = nil
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.WaitDelay = nativeCommandWaitDelay
	process.Cancel = func() error {
		if process.Process == nil {
			return nil
		}
		err := syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	err := process.Run()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if err == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() >= 0 {
		return exitError.ExitCode(), nil
	}
	return -1, ErrInstallation
}
