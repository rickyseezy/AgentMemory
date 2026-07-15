package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSourceCommit = "0123456789abcdef0123456789abcdef01234567"

func TestPF001NativeBuildPublishesOnlyReproducibleManifestInputs(t *testing.T) {
	t.Parallel()
	fixture := newNativeBuildFixture(t)
	runner := &nativeBuildRunner{goVersion: requiredGoVersion, sourceCommit: testSourceCommit}
	validated := ""
	if err := Build(context.Background(), fixture.options, runner, func(value string) error {
		validated = value
		return nil
	}); err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if validated == "" || len(runner.commands) != 7 {
		t.Fatalf("validated=%q commands=%+v", validated, runner.commands)
	}
	for _, command := range runner.commands[3:] {
		if command.Name != "go" || len(command.Args) == 0 || command.Args[0] != "build" ||
			command.Env["GOOS"] != "linux" || command.Env["GOARCH"] != "arm64" ||
			command.Env["CGO_ENABLED"] != "0" || command.Env["GOENV"] != "off" ||
			command.Env["GOTOOLCHAIN"] != "local" || command.Env["GOFLAGS"] != "-mod=readonly" ||
			!strings.Contains(strings.Join(command.Args, " "), releaseTrustVariable+"="+validated) {
			t.Fatalf("build command=%+v", command)
		}
	}
	epoch := time.Unix(fixture.options.SourceEpoch, 0)
	for name, want := range map[string]string{
		"agentmemory":                "launcher deterministic bytes",
		"agentmemory-runtime-helper": "helper deterministic bytes",
	} {
		path := filepath.Join(fixture.output, name)
		content, err := os.ReadFile(path) // #nosec G304 -- closed test-owned filename set.
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || string(content) != want || info.Mode().Perm() != 0o755 ||
			info.ModTime().Unix() != epoch.Unix() {
			t.Fatalf("%s content=%q info=%+v read=%v stat=%v", name, content, info, err, statErr)
		}
	}
	raw, err := os.ReadFile(filepath.Join(fixture.output, nativeBuildMetadataName))
	if err != nil {
		t.Fatal(err)
	}
	var metadata nativeBuildMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil || metadata.SchemaVersion != 1 ||
		metadata.SourceCommit != testSourceCommit || metadata.GoVersion != requiredGoVersion ||
		metadata.OperatingSystem != "linux" || metadata.Architecture != "arm64" ||
		metadata.SourceEpoch != fixture.options.SourceEpoch || len(metadata.Artifacts) != 2 {
		t.Fatalf("metadata=%+v error=%v", metadata, err)
	}
}

func TestPF001NativeBuildRejectsNondeterminismAndNeverPublishesPartialOutput(t *testing.T) {
	t.Parallel()
	fixture := newNativeBuildFixture(t)
	runner := &nativeBuildRunner{
		goVersion: requiredGoVersion, sourceCommit: testSourceCommit, nondeterministic: true,
	}
	if err := Build(context.Background(), fixture.options, runner, acceptNativeTrust); err == nil {
		t.Fatal("Build() error=nil")
	}
	if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output exists: %v", err)
	}
}

func TestPF001NativeBuildFailsClosedForInputsAuthorityAndCommands(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*nativeBuildFixture, *nativeBuildRunner) trustValidator{
		"trust": func(_ *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			return func(string) error { return errors.New("rejected") }
		},
		"dirty": func(_ *nativeBuildFixture, runner *nativeBuildRunner) trustValidator {
			runner.dirty = true
			return acceptNativeTrust
		},
		"git": func(_ *nativeBuildFixture, runner *nativeBuildRunner) trustValidator {
			runner.gitError = errors.New("git failed")
			return acceptNativeTrust
		},
		"toolchain": func(_ *nativeBuildFixture, runner *nativeBuildRunner) trustValidator {
			runner.goVersion = "go1.99.0"
			return acceptNativeTrust
		},
		"build": func(_ *nativeBuildFixture, runner *nativeBuildRunner) trustValidator {
			runner.buildErrorAt = 1
			return acceptNativeTrust
		},
		"missing output": func(_ *nativeBuildFixture, runner *nativeBuildRunner) trustValidator {
			runner.skipBuildAt = 1
			return acceptNativeTrust
		},
		"existing output": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			if err := os.Mkdir(fixture.output, 0o700); err != nil {
				t.Fatal(err)
			}
			return acceptNativeTrust
		},
		"target": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.OperatingSystem = "plan9"
			return acceptNativeTrust
		},
		"epoch": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.SourceEpoch = 0
			return acceptNativeTrust
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newNativeBuildFixture(t)
			runner := &nativeBuildRunner{goVersion: requiredGoVersion, sourceCommit: testSourceCommit}
			if err := Build(context.Background(), fixture.options, runner, configure(fixture, runner)); err == nil {
				t.Fatal("Build() error=nil")
			}
		})
	}
}

func TestPF001NativeBuildRejectsIncompleteCapabilitiesAndInvocation(t *testing.T) {
	t.Parallel()
	if !validSourceCommit(strings.Repeat("a", 64)) || validSourceCommit(strings.Repeat("A", 40)) ||
		executableName("agentmemory", "windows") != "agentmemory.exe" {
		t.Fatal("closed source-commit or executable-name policy changed")
	}
	fixture := newNativeBuildFixture(t)
	runner := &nativeBuildRunner{goVersion: requiredGoVersion, sourceCommit: testSourceCommit}
	if err := Build(context.Background(), fixture.options, nil, acceptNativeTrust); err == nil {
		t.Fatal("Build(nil runner) error=nil")
	}
	if err := Build(context.Background(), fixture.options, runner, nil); err == nil {
		t.Fatal("Build(nil trust) error=nil")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Build(cancelled, fixture.options, runner, acceptNativeTrust); !errors.Is(err, context.Canceled) {
		t.Fatalf("Build(cancelled) error=%v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-os", "plan9"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Native build failed") {
		t.Fatalf("run(invalid)=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001NativeBuildProcessRunnerUsesClosedExecutableSet(t *testing.T) {
	runner := processRunner{}
	working := t.TempDir()
	if output, err := runner.Run(context.Background(), Command{
		Name: "git", Args: []string{"--version"}, Dir: working,
	}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("git output=%q error=%v", output, err)
	}
	if _, err := runner.Run(context.Background(), Command{Name: "sh", Dir: working}); err == nil {
		t.Fatal("disallowed executable accepted")
	}
}

type nativeBuildFixture struct {
	root    string
	trust   string
	output  string
	options BuildOptions
}

func newNativeBuildFixture(t testing.TB) *nativeBuildFixture {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(parent, "trust.json")
	if err := os.WriteFile(trust, []byte(`{"schemaVersion":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "native")
	return &nativeBuildFixture{
		root: root, trust: trust, output: output,
		options: BuildOptions{
			RepositoryRoot: root, TrustDocument: trust, Output: output,
			OperatingSystem: "linux", Architecture: "arm64", SourceEpoch: 1_784_073_600,
		},
	}
}

func acceptNativeTrust(string) error { return nil }

type nativeBuildRunner struct {
	commands         []Command
	goVersion        string
	sourceCommit     string
	dirty            bool
	gitError         error
	buildErrorAt     int
	skipBuildAt      int
	builds           int
	nondeterministic bool
}

func (r *nativeBuildRunner) Run(_ context.Context, command Command) ([]byte, error) {
	r.commands = append(r.commands, command)
	if command.Name == "git" {
		if r.gitError != nil {
			return nil, r.gitError
		}
		if len(command.Args) > 0 && command.Args[0] == "status" {
			if r.dirty {
				return []byte(" M source.go\n"), nil
			}
			return nil, nil
		}
		return []byte(r.sourceCommit + "\n"), nil
	}
	if command.Name != "go" || len(command.Args) == 0 {
		return nil, errors.New("unexpected command")
	}
	if command.Args[0] == "version" {
		return []byte("go version " + r.goVersion + " test/arch\n"), nil
	}
	r.builds++
	if r.buildErrorAt == r.builds {
		return nil, errors.New("build failed")
	}
	if r.skipBuildAt == r.builds {
		return nil, nil
	}
	output := commandArgumentAfter(command.Args, "-o")
	packagePath := command.Args[len(command.Args)-1]
	content := "launcher deterministic bytes"
	if strings.HasSuffix(packagePath, "agentmemory-runtime-helper") {
		content = "helper deterministic bytes"
	}
	if r.nondeterministic && r.builds%2 == 0 {
		content += " changed"
	}
	if output == "" {
		return nil, errors.New("missing output argument")
	}
	return nil, os.WriteFile(output, []byte(content), 0o600)
}

func commandArgumentAfter(arguments []string, name string) string {
	for index, argument := range arguments {
		if argument == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}
