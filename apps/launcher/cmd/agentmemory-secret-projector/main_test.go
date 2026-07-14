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
	}{
		{name: "success", args: []string{"agentmemory-secret-projector"}, wantOut: "ok\n"},
		{name: "argument rejection", args: []string{"agentmemory-secret-projector", "unexpected"}, wantCode: 1, wantErr: "argument-contract"},
		{name: "projection failure", args: []string{"agentmemory-secret-projector"}, projectErr: errors.New("protected projection failed: unavailable"), wantCode: 1, wantErr: "unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stdoutPath := temporaryFile(t)
			stderr, stderrPath := temporaryFile(t)
			code := run(test.args, stdout, stderr, func() error { return test.projectErr })
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
		})
	}
}

func TestPF001SecretProjectorCommandRejectsNilCapabilities(t *testing.T) {
	t.Parallel()
	stdout, _ := temporaryFile(t)
	stderr, stderrPath := temporaryFile(t)
	defer func() { _ = stdout.Close() }()
	if code := run([]string{"agentmemory-secret-projector"}, stdout, stderr, nil); code != 1 {
		t.Fatalf("run()=%d", code)
	}
	if err := stderr.Close(); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, stderrPath, "argument-contract")
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
