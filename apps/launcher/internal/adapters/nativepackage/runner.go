package nativepackage

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
)

type nativeCommandExecutor func(context.Context, Command) (int, error)

// NativeCommandRunner is the sole production no-shell process boundary used
// by the portable package transaction.
type NativeCommandRunner struct {
	operatingSystem string
	execute         nativeCommandExecutor
}

// NewNativeCommandRunner binds execution to the compile-time target OS.
func NewNativeCommandRunner() (*NativeCommandRunner, error) {
	return newNativeCommandRunner(runtime.GOOS, executeNativeCommand)
}

func newNativeCommandRunner(
	operatingSystem string,
	execute nativeCommandExecutor,
) (*NativeCommandRunner, error) {
	if (operatingSystem != "darwin" && operatingSystem != "linux" && operatingSystem != "windows") ||
		execute == nil {
		return nil, ErrInstallation
	}
	return &NativeCommandRunner{operatingSystem: operatingSystem, execute: execute}, nil
}

// Run independently validates the closed command shape before touching the
// process API. The transaction cannot widen this adapter into a general runner.
func (r *NativeCommandRunner) Run(ctx context.Context, command Command) (int, error) {
	if r == nil || ctx == nil || r.execute == nil || !validNativeCommand(r.operatingSystem, command) {
		return -1, ErrInstallation
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	exitCode, err := r.execute(ctx, Command{
		Executable: command.Executable, Arguments: append([]string(nil), command.Arguments...),
	})
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return -1, contextError
		}
		return -1, ErrInstallation
	}
	if exitCode < 0 {
		return -1, ErrInstallation
	}
	return exitCode, nil
}

func validNativeCommand(operatingSystem string, command Command) bool {
	switch operatingSystem {
	case "darwin":
		return command.Executable == darwinOpenExecutable && len(command.Arguments) == 2 &&
			command.Arguments[0] == "-W" && validPackagePath(command.Arguments[1], ".pkg")
	case "linux":
		if command.Executable != linuxPkexecExecutable {
			return false
		}
		return len(command.Arguments) == 3 && command.Arguments[0] == linuxDpkgExecutable &&
			command.Arguments[1] == "--install" && validPackagePath(command.Arguments[2], ".deb") ||
			len(command.Arguments) == 4 && command.Arguments[0] == linuxRPMExecutable &&
				command.Arguments[1] == "--upgrade" && command.Arguments[2] == "--replacepkgs" &&
				validPackagePath(command.Arguments[3], ".rpm")
	case "windows":
		return command.Executable == windowsMSIExecutable && len(command.Arguments) == 4 &&
			strings.EqualFold(command.Arguments[0], "/i") && validWindowsPackagePath(command.Arguments[1]) &&
			strings.EqualFold(command.Arguments[2], "/passive") &&
			strings.EqualFold(command.Arguments[3], "/norestart")
	default:
		return false
	}
}

func validPackagePath(path string, suffix string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		strings.HasSuffix(path, suffix) && !strings.ContainsRune(path, 0)
}

func validWindowsPackagePath(path string) bool {
	if len(path) < 7 || path[1] != ':' || path[2] != '\\' ||
		(path[0] < 'A' || path[0] > 'Z') && (path[0] < 'a' || path[0] > 'z') ||
		!strings.HasSuffix(strings.ToLower(path), ".msi") || strings.ContainsRune(path, 0) ||
		strings.Contains(path, "/") || strings.Contains(path[2:], ":") || strings.HasSuffix(path, `\`) {
		return false
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

var _ CommandRunner = (*NativeCommandRunner)(nil)
