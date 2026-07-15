//go:build windows

package nativepackage

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

func executeNativeCommand(ctx context.Context, command Command) (int, error) {
	if ctx == nil || command.Executable == "" {
		return -1, ErrInstallation
	}
	// #nosec G204 -- NativeCommandRunner accepts only the exact system32
	// msiexec path and fixed argv before this function is reachable.
	process := exec.CommandContext(ctx, command.Executable, command.Arguments...)
	process.Stdin = nil
	process.Stdout = io.Discard
	process.Stderr = io.Discard
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
