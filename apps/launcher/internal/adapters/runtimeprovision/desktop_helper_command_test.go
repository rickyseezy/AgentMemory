package runtimeprovision

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestPF001DesktopMutationCommandIsClosedAndDefensivelyCopied(t *testing.T) {
	t.Parallel()
	arguments := []string{"--install", "--accept-license"}
	environment := []string{"LANG=C", "PATH=/usr/bin"}
	executable, directory := desktopMutationTestPaths()
	command, err := newDesktopMutationCommand(executable, arguments, environment, directory)
	if err != nil {
		t.Fatal(err)
	}
	arguments[0] = "--foreign"
	environment[0] = "TOKEN=secret"
	if command.Executable() != executable || command.Directory() != directory ||
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
	executable, directory := desktopMutationTestPaths()
	separator := string(filepath.Separator)
	uncleanExecutable := filepath.Dir(executable) + separator + ".." + separator +
		filepath.Base(filepath.Dir(executable)) + separator + filepath.Base(executable)
	uncleanDirectory := directory + separator + ".." + separator + filepath.Base(directory)
	for name, input := range map[string]struct {
		executable  string
		arguments   []string
		environment []string
		directory   string
	}{
		"relative executable": {executable: "installer", directory: directory},
		"unclean executable":  {executable: uncleanExecutable, directory: directory},
		"relative directory":  {executable: executable, directory: "work"},
		"unclean directory":   {executable: executable, directory: uncleanDirectory},
		"too many arguments":  {executable: executable, arguments: tooMany, directory: directory},
		"argument newline":    {executable: executable, arguments: []string{"bad\nvalue"}, directory: directory},
		"environment nul":     {executable: executable, environment: []string{"BAD=\x00"}, directory: directory},
	} {
		t.Run(name, func(t *testing.T) {
			if command, err := newDesktopMutationCommand(input.executable, input.arguments, input.environment, input.directory); err == nil ||
				command.Executable() != "" || !strings.Contains(err.Error(), "desktop mutation command") {
				t.Fatalf("command=%+v error=%v", command, err)
			}
		})
	}
}

func desktopMutationTestPaths() (string, string) {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\AgentMemory\installer.exe`, `C:\ProgramData\AgentMemory`
	}
	return "/usr/bin/installer", "/var/empty"
}
