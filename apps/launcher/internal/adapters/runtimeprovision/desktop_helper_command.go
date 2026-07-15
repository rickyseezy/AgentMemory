package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

const maximumDesktopMutationCommandArguments = 32

// DesktopMutationCommand is a closed helper-generated process contract. No
// inbound envelope field can directly select an executable, environment, or
// working directory.
type DesktopMutationCommand struct {
	executable  string
	arguments   []string
	environment []string
	directory   string
}

func newDesktopMutationCommand(
	executable string,
	arguments []string,
	environment []string,
	directory string,
) (DesktopMutationCommand, error) {
	if executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable ||
		directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		len(arguments) > maximumDesktopMutationCommandArguments ||
		strings.ContainsAny(executable+directory, "\x00\r\n") {
		return DesktopMutationCommand{}, errors.New("desktop mutation command is invalid")
	}
	for _, values := range [][]string{arguments, environment} {
		for _, value := range values {
			if strings.ContainsAny(value, "\x00\r\n") {
				return DesktopMutationCommand{}, errors.New("desktop mutation command value is invalid")
			}
		}
	}
	return DesktopMutationCommand{
		executable: executable, arguments: slices.Clone(arguments),
		environment: slices.Clone(environment), directory: directory,
	}, nil
}

// Executable returns the exact native or verified installer path.
func (c DesktopMutationCommand) Executable() string { return c.executable }

// Arguments returns a defensive copy of the exact argv tail.
func (c DesktopMutationCommand) Arguments() []string { return slices.Clone(c.arguments) }

// Environment returns the complete scrubbed process environment.
func (c DesktopMutationCommand) Environment() []string { return slices.Clone(c.environment) }

// Directory returns the fixed working directory.
func (c DesktopMutationCommand) Directory() string { return c.directory }

// DesktopMutationCommandRunner provides the platform process-tree primitive.
type DesktopMutationCommandRunner interface {
	RunDesktopMutationCommand(context.Context, DesktopMutationCommand) (uint32, error)
}
