package nativepackage

import (
	"context"
	"errors"
	"testing"
)

func TestPF001NativeCommandRunnerAcceptsOnlyClosedPlatformCommands(t *testing.T) {
	t.Parallel()
	valid := map[string]Command{
		"darwin": {Executable: darwinOpenExecutable, Arguments: []string{"-W", "/private/tmp/agentmemory.pkg"}},
		"linux": {Executable: linuxPkexecExecutable, Arguments: []string{
			linuxDpkgExecutable, "--install", "/var/tmp/agentmemory.deb",
		}},
		"windows": {Executable: windowsMSIExecutable, Arguments: []string{
			"/i", `C:\Users\User\AgentMemory.msi`, "/passive", "/norestart",
		}},
	}
	for operatingSystem, command := range valid {
		if !validNativeCommand(operatingSystem, command) {
			t.Fatalf("%s command was rejected", operatingSystem)
		}
		runner, err := newNativeCommandRunner(operatingSystem, func(_ context.Context, got Command) (int, error) {
			got.Arguments[0] = "mutated"
			return 0, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if exitCode, err := runner.Run(context.Background(), command); err != nil || exitCode != 0 ||
			command.Arguments[0] == "mutated" {
			t.Fatalf("Run() = %d, %v command=%+v", exitCode, err, command)
		}
	}
}

func TestPF001NativeCommandRunnerRejectsWideningFailureAndCancellation(t *testing.T) {
	t.Parallel()
	if runner, err := newNativeCommandRunner("plan9", func(context.Context, Command) (int, error) { return 0, nil }); runner != nil || !errors.Is(err, ErrInstallation) {
		t.Fatalf("unsupported runner = %T, %v", runner, err)
	}
	if runner, err := newNativeCommandRunner("linux", nil); runner != nil || !errors.Is(err, ErrInstallation) {
		t.Fatalf("nil executor = %T, %v", runner, err)
	}
	command := Command{Executable: linuxPkexecExecutable, Arguments: []string{
		linuxDpkgExecutable, "--install", "/var/tmp/agentmemory.deb",
	}}
	runner, err := newNativeCommandRunner("linux", func(context.Context, Command) (int, error) {
		return -1, errors.New("private process diagnostic")
	})
	if err != nil {
		t.Fatal(err)
	}
	if exitCode, err := runner.Run(context.Background(), command); exitCode != -1 ||
		!errors.Is(err, ErrInstallation) {
		t.Fatalf("executor failure = %d, %v", exitCode, err)
	}
	if exitCode, err := runner.Run(context.Background(), Command{Executable: "/bin/sh"}); exitCode != -1 ||
		!errors.Is(err, ErrInstallation) {
		t.Fatalf("widened command = %d, %v", exitCode, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if exitCode, err := runner.Run(cancelled, command); exitCode != -1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %d, %v", exitCode, err)
	}
	var absent *NativeCommandRunner
	if exitCode, err := absent.Run(context.Background(), command); exitCode != -1 ||
		!errors.Is(err, ErrInstallation) {
		t.Fatalf("nil runner = %d, %v", exitCode, err)
	}
}

func TestPF001NativeCommandRunnerBindsCompileTimeOSAndRejectsUnsafeWindowsPaths(t *testing.T) {
	t.Parallel()
	runner, err := NewNativeCommandRunner()
	if err != nil || runner == nil {
		t.Fatalf("NewNativeCommandRunner() = %T, %v", runner, err)
	}
	for _, path := range []string{
		`C:\AgentMemory\..\attacker.msi`,
		`C:\AgentMemory\folder\`,
		`C:/AgentMemory/agentmemory.msi`,
		`relative\agentmemory.msi`,
	} {
		if validWindowsPackagePath(path) {
			t.Fatalf("unsafe Windows path accepted: %q", path)
		}
	}
	if !validNativeCommand("linux", Command{Executable: linuxPkexecExecutable, Arguments: []string{
		linuxRPMExecutable, "--upgrade", "--replacepkgs", "/var/tmp/agentmemory.rpm",
	}}) {
		t.Fatal("closed RPM command was rejected")
	}
}
