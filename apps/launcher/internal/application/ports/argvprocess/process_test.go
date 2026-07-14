package argvprocess

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPF001ArgvInvocationRejectsNULAndBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		executable string
		arguments  []string
	}{
		{name: "empty executable"},
		{name: "oversized executable", executable: strings.Repeat("x", 4097)},
		{name: "NUL executable", executable: "/bin/x\x00"},
		{name: "NUL argument", executable: "/bin/x", arguments: []string{"a\x00b"}},
		{name: "oversized argument", executable: "/bin/x", arguments: []string{strings.Repeat("a", 32*1024+1)}},
		{name: "too many arguments", executable: "/bin/x", arguments: make([]string, 257)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewInvocation(test.executable, test.arguments); !errors.Is(err, ErrInvalidInvocation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPF001ArgvInvocationCopiesInputAndOutputArguments(t *testing.T) {
	t.Parallel()

	input := []string{"compose", "version"}
	invocation, err := NewInvocation(" /Applications/Docker.app/Contents/Resources/bin/docker ", input)
	if err != nil {
		t.Fatalf("NewInvocation() error = %v", err)
	}
	input[0] = "substituted"
	first := invocation.Arguments()
	first[1] = "substituted"
	second := invocation.Arguments()
	if invocation.Executable() != " /Applications/Docker.app/Contents/Resources/bin/docker " ||
		len(second) != 2 || second[0] != "compose" || second[1] != "version" {
		t.Fatalf("Invocation exposed mutable argv: executable=%q arguments=%q", invocation.Executable(), second)
	}
}

func TestPF001ArgvInvocationCarriesOnlyBoundedCopiedStandardInput(t *testing.T) {
	t.Parallel()

	input := []byte("authenticated compose bytes")
	invocation, err := NewInvocationWithStandardInput("/absolute/docker", []string{"compose", "--file", "-"}, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	first := invocation.StandardInput()
	first[0] = 'Y'
	if got := string(invocation.StandardInput()); got != "authenticated compose bytes" {
		t.Fatalf("StandardInput() = %q", got)
	}
	if _, err := NewInvocationWithStandardInput(
		"/absolute/docker", nil, []byte(strings.Repeat("x", maximumStandardInputBytes+1)),
	); !errors.Is(err, ErrInvalidInvocation) {
		t.Fatalf("oversized standard input error = %v", err)
	}
}

func TestPF006RootlessSetupInvocationHasOnlyClosedSanitizedEnvironment(t *testing.T) {
	t.Parallel()
	invocation, err := NewRootlessSetupInvocation(
		"/usr/bin/dockerd-rootless-setuptool.sh", []string{"install"},
		"/home/agentmemory", "/run/user/1000", 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	wanted := []string{
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"DOCKER_CONFIG=/run/user/1000/agentmemory-docker-cli",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"HOME=/home/agentmemory", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
		"XDG_RUNTIME_DIR=/run/user/1000",
	}
	if invocation.EnvironmentProfile() != EnvironmentProfileRootlessSetup ||
		!slices.Equal(invocation.Environment(), wanted) {
		t.Fatalf("rootless environment = %v", invocation.Environment())
	}
	environment := invocation.Environment()
	environment[0] = "LD_PRELOAD=attacker"
	if invocation.Environment()[0] != wanted[0] {
		t.Fatal("rootless environment projection was mutable")
	}
	for _, test := range []struct {
		home    string
		runtime string
		uid     uint32
	}{
		{home: "/tmp/user", runtime: "/run/user/1000", uid: 1000},
		{home: "/home/user", runtime: "/run/user/1001", uid: 1000},
		{home: "/home/../root", runtime: "/run/user/1000", uid: 1000},
		{home: "/home/user", runtime: "/run/user/0", uid: 0},
	} {
		if _, err := NewRootlessSetupInvocation("/usr/bin/tool", nil, test.home, test.runtime, test.uid); !errors.Is(err, ErrInvalidInvocation) {
			t.Fatalf("unsafe rootless environment %+v error = %v", test, err)
		}
	}
}
