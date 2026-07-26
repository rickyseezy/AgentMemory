package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPF001SecretProjectorCommandContracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		projectErr error
		wantCode   int
		wantOut    string
		wantErr    string
		wantRemote bool
	}{
		{name: "success", args: []string{"agentmemory-secret-projector"}, wantOut: "ok\n"},
		{name: "remote success", args: []string{"agentmemory-secret-projector", "remote"}, wantOut: "ok\n", wantRemote: true},
		{name: "argument rejection", args: []string{"agentmemory-secret-projector", "unexpected"}, wantCode: 1, wantErr: "argument-contract"},
		{name: "projection failure", args: []string{"agentmemory-secret-projector"}, projectErr: errors.New("protected projection failed: unavailable"), wantCode: 1, wantErr: "unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stdoutPath := temporaryFile(t)
			stderr, stderrPath := temporaryFile(t)
			defaultCalled, remoteCalled := false, false
			code := run(
				test.args,
				stdout,
				stderr,
				func() error { defaultCalled = true; return test.projectErr },
				func() error { remoteCalled = true; return test.projectErr },
			)
			if code != test.wantCode {
				t.Fatalf("run()=%d want %d", code, test.wantCode)
			}
			if err := stdout.Close(); err != nil {
				t.Fatal(err)
			}
			if err := stderr.Close(); err != nil {
				t.Fatal(err)
			}
			assertFileContains(t, stdoutPath, test.wantOut)
			assertFileContains(t, stderrPath, test.wantErr)
			if test.wantErr == "argument-contract" {
				if defaultCalled || remoteCalled {
					t.Fatal("invalid arguments reached a projection")
				}
			} else if defaultCalled == test.wantRemote || remoteCalled != test.wantRemote {
				t.Fatalf("projection selection default=%t remote=%t", defaultCalled, remoteCalled)
			}
		})
	}
}

func TestPF001SecretProjectorCommandRejectsNilCapabilities(t *testing.T) {
	t.Parallel()
	stdout, _ := temporaryFile(t)
	stderr, stderrPath := temporaryFile(t)
	defer func() { _ = stdout.Close() }()
	if code := run(
		[]string{"agentmemory-secret-projector"}, stdout, stderr, nil, func() error { return nil },
	); code != 1 {
		t.Fatalf("run()=%d", code)
	}
	if err := stderr.Close(); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, stderrPath, "argument-contract")
}

func TestPF001SecretProjectorCommandRequiresBothOwnedStreams(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		nilStdout bool
		nilStderr bool
	}{
		{name: "nil stdout", nilStdout: true},
		{name: "nil stderr", nilStderr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, _ := temporaryFile(t)
			stderr, _ := temporaryFile(t)
			ownedStdout, ownedStderr := stdout, stderr
			defer func() { _ = ownedStdout.Close(); _ = ownedStderr.Close() }()
			if test.nilStdout {
				stdout = nil
			}
			if test.nilStderr {
				stderr = nil
			}
			called := false
			if code := run(
				[]string{"agentmemory-secret-projector"},
				stdout,
				stderr,
				func() error { called = true; return nil },
				func() error { called = true; return nil },
			); code != 1 || called {
				t.Fatalf("run()=%d called=%t", code, called)
			}
		})
	}
}

func temporaryFile(t testing.TB) (*os.File, string) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "command-stream-*")
	if err != nil {
		t.Fatal(err)
	}
	return file, file.Name()
}

func assertFileContains(t testing.TB, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path) //nolint:gosec // path is returned by t.TempDir/CreateTemp.
	if err != nil {
		t.Fatal(err)
	}
	if want == "" && len(contents) != 0 || want != "" && !strings.Contains(string(contents), want) {
		t.Fatalf("contents=%q want substring %q", contents, want)
	}
}
