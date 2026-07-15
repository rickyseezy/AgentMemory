package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPF001LinuxReleaseAssemblyPublishesNormalizedClosedStage(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	runner := &fakeCommandRunner{}
	validated := ""
	err := Assemble(context.Background(), fixture.options, runner, func(encoded string) error {
		validated = encoded
		return nil
	})
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(validated); err != nil || string(decoded) != `{"schemaVersion":1}` {
		t.Fatalf("validated trust = %q, decode error = %v", validated, err)
	}
	if len(runner.commands) != 3 || runner.commands[0].Name != "git" {
		t.Fatalf("commands = %+v, want git and two builds", runner.commands)
	}
	wantPackages := []string{"./apps/launcher/cmd/agentmemory", "./apps/launcher/cmd/agentmemory-runtime-helper"}
	resolvedRepository, err := filepath.EvalSymlinks(fixture.repository)
	if err != nil {
		t.Fatal(err)
	}
	for index, wantPackage := range wantPackages {
		command := runner.commands[index+1]
		if command.Name != "go" || command.Dir != resolvedRepository ||
			command.Env["GOOS"] != "linux" || command.Env["GOARCH"] != "arm64" ||
			command.Env["CGO_ENABLED"] != "0" || command.Args[len(command.Args)-1] != wantPackage {
			t.Fatalf("build command %d = %+v", index, command)
		}
		if !strings.Contains(strings.Join(command.Args, " "), releaseTrustVariable+"="+validated) {
			t.Fatalf("build command %d does not embed validated trust", index)
		}
	}

	epoch := time.Unix(fixture.options.SourceEpoch, 0)
	for relative, wantMode := range map[string]os.FileMode{
		".":                          0o755,
		"agentmemory":                0o755,
		"agentmemory-runtime-helper": 0o755,
		"bundle":                     0o755,
		"bundle/bootstrap":           0o755,
		"bundle/bootstrap/distribution-manifest.json": 0o644,
		"bundle/models/embedding/model.bin":           0o644,
	} {
		path := filepath.Join(fixture.output, relative)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", relative, err)
		}
		if info.Mode().Perm() != wantMode || info.ModTime().Unix() != epoch.Unix() {
			t.Errorf("%s mode=%04o mtime=%d, want %04o/%d", relative, info.Mode().Perm(), info.ModTime().Unix(), wantMode, epoch.Unix())
		}
	}
	content, err := os.ReadFile(filepath.Join(fixture.output, "bundle/models/embedding/model.bin"))
	if err != nil || string(content) != "model" {
		t.Fatalf("copied model = %q, error = %v", content, err)
	}
}

func TestPF001LinuxReleaseAssemblyRejectsEveryUnsafeInput(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*testing.T, *assemblyFixture){
		"architecture": func(_ *testing.T, fixture *assemblyFixture) { fixture.options.Architecture = "386" },
		"epoch":        func(_ *testing.T, fixture *assemblyFixture) { fixture.options.SourceEpoch = 0 },
		"existing output": func(t *testing.T, fixture *assemblyFixture) {
			if err := os.Mkdir(fixture.output, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked trust": func(t *testing.T, fixture *assemblyFixture) {
			link := filepath.Join(t.TempDir(), "trust-link.json")
			if err := os.Symlink(fixture.trust, link); err != nil {
				t.Fatal(err)
			}
			fixture.options.TrustDocument = link
		},
		"symlinked bundle entry": func(t *testing.T, fixture *assemblyFixture) {
			if err := os.Symlink("model.bin", filepath.Join(fixture.bundle, "models/embedding/alias.bin")); err != nil {
				t.Fatal(err)
			}
		},
		"missing manifest": func(t *testing.T, fixture *assemblyFixture) {
			if err := os.Remove(filepath.Join(fixture.bundle, "bootstrap/distribution-manifest.json")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newAssemblyFixture(t)
			mutate(t, fixture)
			runner := &fakeCommandRunner{}
			if err := Assemble(context.Background(), fixture.options, runner, func(string) error { return nil }); err == nil {
				t.Fatal("Assemble() error = nil, want rejection")
			}
			if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) && name != "existing output" {
				t.Fatalf("partial output exists: %v", err)
			}
		})
	}
}

func TestPF001LinuxReleaseAssemblyFailsClosedForAuthorityRevisionAndBuild(t *testing.T) {
	t.Parallel()
	for name, configure := range map[string]func(*fakeCommandRunner) trustValidator{
		"trust": func(_ *fakeCommandRunner) trustValidator {
			return func(string) error { return errors.New("invalid") }
		},
		"dirty revision": func(runner *fakeCommandRunner) trustValidator {
			runner.gitOutput = []byte(" M source.go\n")
			return func(string) error { return nil }
		},
		"git failure": func(runner *fakeCommandRunner) trustValidator {
			runner.gitError = errors.New("failed")
			return func(string) error { return nil }
		},
		"build failure": func(runner *fakeCommandRunner) trustValidator {
			runner.buildErrorAt = 1
			return func(string) error { return nil }
		},
		"missing build output": func(runner *fakeCommandRunner) trustValidator {
			runner.skipBuildAt = 1
			return func(string) error { return nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newAssemblyFixture(t)
			runner := &fakeCommandRunner{}
			if err := Assemble(context.Background(), fixture.options, runner, configure(runner)); err == nil {
				t.Fatal("Assemble() error = nil, want failure")
			}
			if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial output exists: %v", err)
			}
		})
	}
}

func TestPF001LinuxReleaseAssemblyRejectsInvalidCapabilitiesAndPaths(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	validator := func(string) error { return nil }
	runner := &fakeCommandRunner{}
	if err := Assemble(context.Background(), fixture.options, nil, validator); err == nil {
		t.Fatal("Assemble(nil runner) error = nil")
	}
	if err := Assemble(context.Background(), fixture.options, runner, nil); err == nil {
		t.Fatal("Assemble(nil validator) error = nil")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Assemble(cancelled, fixture.options, runner, validator); !errors.Is(err, context.Canceled) {
		t.Fatalf("Assemble(cancelled) error = %v", err)
	}

	for name, mutate := range map[string]func(*AssemblyOptions){
		"missing bundle": func(options *AssemblyOptions) { options.BundleRoot = "" },
		"missing trust":  func(options *AssemblyOptions) { options.TrustDocument = "" },
		"missing output": func(options *AssemblyOptions) { options.Output = "" },
		"missing output parent": func(options *AssemblyOptions) {
			options.Output = filepath.Join(fixture.repository, "missing", "stage")
		},
		"repository file": func(options *AssemblyOptions) { options.RepositoryRoot = fixture.trust },
		"bundle file":     func(options *AssemblyOptions) { options.BundleRoot = fixture.trust },
		"empty trust": func(options *AssemblyOptions) {
			empty := filepath.Join(filepath.Dir(fixture.trust), "empty.json")
			if err := os.WriteFile(empty, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			options.TrustDocument = empty
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := fixture.options
			mutate(&options)
			if err := Assemble(context.Background(), options, runner, validator); err == nil {
				t.Fatal("Assemble() error = nil, want rejection")
			}
		})
	}
	if err := normalizeBuiltBinary(filepath.Join(t.TempDir(), "missing"), time.Unix(1, 0)); err == nil {
		t.Fatal("normalizeBuiltBinary(missing) error = nil")
	}
	if _, err := readBoundedRegularFile(fixture.trust, 1); err == nil {
		t.Fatal("readBoundedRegularFile(oversized) error = nil")
	}
}

func TestPF001LinuxReleaseProcessRunnerIsAllowlistedAndDeterministic(t *testing.T) {
	runner := processRunner{}
	workingDirectory := t.TempDir()
	if output, err := runner.Run(context.Background(), Command{
		Name: "git", Args: []string{"--version"}, Dir: workingDirectory,
	}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("processRunner.Run(git) output=%q error=%v", output, err)
	}
	if _, err := runner.Run(context.Background(), Command{Name: "sh", Dir: workingDirectory}); err == nil {
		t.Fatal("processRunner.Run(disallowed) error = nil")
	}
	t.Setenv("AGENTMEMORY_ENV_TEST", "original")
	environment := mergedEnvironment(map[string]string{"AGENTMEMORY_ENV_TEST": "replacement", "ZZ_AGENTMEMORY": "last"})
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "AGENTMEMORY_ENV_TEST=replacement") ||
		!strings.Contains(joined, "ZZ_AGENTMEMORY=last") || !sort.StringsAreSorted(environment) {
		t.Fatalf("mergedEnvironment() = %q", environment)
	}
}

func TestPF001LinuxReleaseCommandRejectsInvalidInvocation(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional) = %d, want 2", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-arch", "386"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Linux release assembly failed") {
		t.Fatalf("run(invalid) = %d stderr=%q", code, stderr.String())
	}
}

type assemblyFixture struct {
	repository string
	bundle     string
	trust      string
	output     string
	options    AssemblyOptions
}

func newAssemblyFixture(t *testing.T) *assemblyFixture {
	t.Helper()
	parent := t.TempDir()
	repository := filepath.Join(parent, "repository")
	bundle := filepath.Join(parent, "release-bundle")
	output := filepath.Join(parent, "stage")
	for _, directory := range []string{
		repository,
		filepath.Join(bundle, "bootstrap"),
		filepath.Join(bundle, "models", "embedding"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	trust := filepath.Join(parent, "trust.json")
	for path, content := range map[string]string{
		trust: `{"schemaVersion":1}`,
		filepath.Join(bundle, "bootstrap/distribution-manifest.json"): `{"signed":true}`,
		filepath.Join(bundle, "models/embedding/model.bin"):           "model",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &assemblyFixture{
		repository: repository, bundle: bundle, trust: trust, output: output,
		options: AssemblyOptions{
			RepositoryRoot: repository, BundleRoot: bundle, TrustDocument: trust,
			Output: output, Architecture: "arm64", SourceEpoch: 1_784_073_600,
		},
	}
}

type fakeCommandRunner struct {
	commands     []Command
	gitOutput    []byte
	gitError     error
	buildErrorAt int
	skipBuildAt  int
	builds       int
}

func (r *fakeCommandRunner) Run(_ context.Context, command Command) ([]byte, error) {
	r.commands = append(r.commands, command)
	if command.Name == "git" {
		return append([]byte(nil), r.gitOutput...), r.gitError
	}
	r.builds++
	if r.buildErrorAt == r.builds {
		return nil, errors.New("build failed")
	}
	if r.skipBuildAt == r.builds {
		return nil, nil
	}
	output := ""
	for index, argument := range command.Args {
		if argument == "-o" && index+1 < len(command.Args) {
			output = command.Args[index+1]
			break
		}
	}
	if output == "" {
		return nil, errors.New("missing output")
	}
	if err := os.WriteFile(output, []byte("linux binary"), 0o600); err != nil {
		return nil, err
	}
	return nil, nil
}
