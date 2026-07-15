package runtimeprovision

import (
	"slices"
	"strings"
	"testing"
)

func TestPF001DesktopMutationCommandIsClosedAndDefensivelyCopied(t *testing.T) {
	t.Parallel()
	arguments := []string{"--install", "--accept-license"}
	environment := []string{"LANG=C", "PATH=/usr/bin"}
	command, err := newDesktopMutationCommand("/usr/bin/installer", arguments, environment, "/var/empty")
	if err != nil {
		t.Fatal(err)
	}
	arguments[0] = "--foreign"
	environment[0] = "TOKEN=secret"
	if command.Executable() != "/usr/bin/installer" || command.Directory() != "/var/empty" ||
		!slices.Equal(command.Arguments(), []string{"--install", "--accept-license"}) ||
		!slices.Equal(command.Environment(), []string{"LANG=C", "PATH=/usr/bin"}) {
		t.Fatalf("command leaked caller mutation: %+v", command)
	}
	returned := command.Arguments()
	returned[0] = "--changed"
	if command.Arguments()[0] != "--install" {
		t.Fatal("Arguments() aliases command state")
	}
}

func TestPF001DesktopMutationCommandRejectsAmbientOrAmbiguousExecution(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, maximumDesktopMutationCommandArguments+1)
	for name, input := range map[string]struct {
		executable  string
		arguments   []string
		environment []string
		directory   string
	}{
		"relative executable": {executable: "installer", directory: "/var/empty"},
		"unclean executable":  {executable: "/usr/bin/../bin/installer", directory: "/var/empty"},
		"relative directory":  {executable: "/usr/bin/installer", directory: "work"},
		"unclean directory":   {executable: "/usr/bin/installer", directory: "/var/../var/empty"},
		"too many arguments":  {executable: "/usr/bin/installer", arguments: tooMany, directory: "/var/empty"},
		"argument newline":    {executable: "/usr/bin/installer", arguments: []string{"bad\nvalue"}, directory: "/var/empty"},
		"environment nul":     {executable: "/usr/bin/installer", environment: []string{"BAD=\x00"}, directory: "/var/empty"},
	} {
		t.Run(name, func(t *testing.T) {
			if command, err := newDesktopMutationCommand(input.executable, input.arguments, input.environment, input.directory); err == nil ||
				command.Executable() != "" || !strings.Contains(err.Error(), "desktop mutation command") {
				t.Fatalf("command=%+v error=%v", command, err)
			}
		})
	}
}
