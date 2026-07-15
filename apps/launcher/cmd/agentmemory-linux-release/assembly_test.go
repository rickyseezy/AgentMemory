package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	var bundleValidation bundleValidationCall
	err := Assemble(context.Background(), fixture.options, runner, func(encoded string) error {
		validated = encoded
		return nil
	}, func(_ context.Context, root string, trust string, operatingSystem string, architecture string, verifiedAt time.Time) (verifiedNativePackage, error) {
		for _, relative := range []string{
			"bootstrap/distribution-manifest.json", "native/linux/arm64/agentmemory",
		} {
			info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("verification input %s mode=%v error=%v, want private 0600", relative, info, err)
			}
		}
		bundleValidation = bundleValidationCall{
			root: root, trust: trust, operatingSystem: operatingSystem,
			architecture: architecture, verifiedAt: verifiedAt,
		}
		return verifiedNativePackageAtRoot(t, root), nil
	})
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(validated); err != nil || string(decoded) != `{"schemaVersion":1}` {
		t.Fatalf("validated trust = %q, decode error = %v", validated, err)
	}
	if bundleValidation.root == fixture.bundle || filepath.Base(bundleValidation.root) != "bundle" ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(bundleValidation.root)), ".agentmemory-linux-stage-") ||
		bundleValidation.trust != validated ||
		bundleValidation.operatingSystem != "linux" || bundleValidation.architecture != "arm64" ||
		bundleValidation.verifiedAt.Unix() != fixture.options.VerificationEpoch {
		t.Fatalf("bundle validation = %+v", bundleValidation)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != "git" {
		t.Fatalf("commands = %+v, want only the clean-revision check", runner.commands)
	}
	resolvedRepository, err := filepath.EvalSymlinks(fixture.repository)
	if err != nil {
		t.Fatal(err)
	}
	if runner.commands[0].Dir != resolvedRepository {
		t.Fatalf("git command = %+v", runner.commands[0])
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
	for path, want := range map[string]string{
		"agentmemory":                "signed launcher bytes",
		"agentmemory-runtime-helper": "signed helper bytes",
	} {
		content, err := os.ReadFile(filepath.Join(fixture.output, path)) // #nosec G304 -- path is a closed test-owned leaf set.
		if err != nil || string(content) != want {
			t.Fatalf("packaged %s = %q, error = %v", path, content, err)
		}
	}
}

func TestPF001LinuxReleaseAssemblyRejectsEveryUnsafeInput(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*testing.T, *assemblyFixture){
		"architecture": func(_ *testing.T, fixture *assemblyFixture) { fixture.options.Architecture = "386" },
		"epoch":        func(_ *testing.T, fixture *assemblyFixture) { fixture.options.SourceEpoch = 0 },
		"verification epoch": func(_ *testing.T, fixture *assemblyFixture) {
			fixture.options.VerificationEpoch = 0
		},
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
			if err := Assemble(context.Background(), fixture.options, runner, func(string) error { return nil }, acceptBundle); err == nil {
				t.Fatal("Assemble() error = nil, want rejection")
			}
			if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) && name != "existing output" {
				t.Fatalf("partial output exists: %v", err)
			}
		})
	}
}

func TestPF001LinuxReleaseAssemblyFailsClosedForAuthorityAndRevision(t *testing.T) {
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
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newAssemblyFixture(t)
			runner := &fakeCommandRunner{}
			if err := Assemble(context.Background(), fixture.options, runner, configure(runner), acceptBundle); err == nil {
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
	if err := Assemble(context.Background(), fixture.options, nil, validator, acceptBundle); err == nil {
		t.Fatal("Assemble(nil runner) error = nil")
	}
	if err := Assemble(context.Background(), fixture.options, runner, nil, acceptBundle); err == nil {
		t.Fatal("Assemble(nil validator) error = nil")
	}
	if err := Assemble(context.Background(), fixture.options, runner, validator, nil); err == nil {
		t.Fatal("Assemble(nil bundle validator) error = nil")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Assemble(cancelled, fixture.options, runner, validator, acceptBundle); !errors.Is(err, context.Canceled) {
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
			if err := Assemble(context.Background(), options, runner, validator, acceptBundle); err == nil {
				t.Fatal("Assemble() error = nil, want rejection")
			}
		})
	}
	if _, err := readBoundedRegularFile(fixture.trust, 1); err == nil {
		t.Fatal("readBoundedRegularFile(oversized) error = nil")
	}
}

func TestPF001LinuxReleaseAssemblyRejectsUnboundNativePackageProjection(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*verifiedNativePackage){
		"empty":        func(value *verifiedNativePackage) { *value = verifiedNativePackage{} },
		"wrong target": func(value *verifiedNativePackage) { value.operatingSystem = "windows" },
		"path traversal": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = "../agentmemory"
		},
		"malformed digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("g", 64)
		},
		"wrong digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 64)
		},
		"wrong size":    func(value *verifiedNativePackage) { value.helper.size++ },
		"same resource": func(value *verifiedNativePackage) { value.helper = value.launcher },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newAssemblyFixture(t)
			resolver := func(_ context.Context, root string, _ string, _ string, _ string, _ time.Time) (verifiedNativePackage, error) {
				value := verifiedNativePackageAtRoot(t, root)
				mutate(&value)
				return value, nil
			}
			if err := Assemble(
				context.Background(), fixture.options, &fakeCommandRunner{},
				func(string) error { return nil }, resolver,
			); err == nil {
				t.Fatal("Assemble() error = nil, want rejection")
			}
			if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial output exists: %v", err)
			}
		})
	}
}

func TestPF001LinuxReleaseAssemblyFailsClosedWhenProductionBundleVerificationFails(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	runner := &fakeCommandRunner{}
	err := Assemble(context.Background(), fixture.options, runner, func(string) error { return nil },
		func(context.Context, string, string, string, string, time.Time) (verifiedNativePackage, error) {
			return verifiedNativePackage{}, errors.New("verification failed")
		})
	if err == nil || len(runner.commands) != 1 || runner.commands[0].Name != "git" {
		t.Fatalf("Assemble() error=%v commands=%+v", err, runner.commands)
	}
	if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial output exists: %v", statErr)
	}
}

type bundleValidationCall struct {
	root            string
	trust           string
	operatingSystem string
	architecture    string
	verifiedAt      time.Time
}

func acceptBundle(_ context.Context, root string, _ string, _ string, _ string, _ time.Time) (verifiedNativePackage, error) {
	return verifiedNativePackageFromRoot(root)
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
	if _, err := runner.Run(context.Background(), Command{Name: "go", Dir: workingDirectory}); err == nil {
		t.Fatal("processRunner.Run(go) error = nil; assembly must never rebuild manifest-bound bytes")
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
	//lint:ignore SA1012 Deliberate absent-context composition-boundary test.
	_, projectionErr := resolveProductionNativePackage(nil, "", "", "linux", "amd64", time.Time{}) //nolint:staticcheck
	if projectionErr == nil {
		t.Fatal("resolveProductionNativePackage(invalid) error = nil")
	}
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
		filepath.Join(bundle, "native", "linux", "arm64"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	trust := filepath.Join(parent, "trust.json")
	for path, content := range map[string]string{
		trust: `{"schemaVersion":1}`,
		filepath.Join(bundle, "bootstrap/distribution-manifest.json"):          `{"signed":true}`,
		filepath.Join(bundle, "models/embedding/model.bin"):                    "model",
		filepath.Join(bundle, "native/linux/arm64/agentmemory"):                "signed launcher bytes",
		filepath.Join(bundle, "native/linux/arm64/agentmemory-runtime-helper"): "signed helper bytes",
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
			VerificationEpoch: 1_784_116_800,
		},
	}
}

func verifiedNativePackageAtRoot(t testing.TB, root string) verifiedNativePackage {
	t.Helper()
	value, err := verifiedNativePackageFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func verifiedNativePackageFromRoot(root string) (verifiedNativePackage, error) {
	resource := func(id string, relative string) (verifiedNativeResource, error) {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative))) // #nosec G304 -- test fixture path.
		if err != nil {
			return verifiedNativeResource{}, err
		}
		digest := sha256.Sum256(content)
		return verifiedNativeResource{
			resourceID: id, bundlePath: relative,
			sha256: hex.EncodeToString(digest[:]), size: uint64(len(content)),
		}, nil
	}
	launcher, err := resource("launcher-linux-arm64", "native/linux/arm64/agentmemory")
	if err != nil {
		return verifiedNativePackage{}, err
	}
	helper, err := resource("helper-linux-arm64", "native/linux/arm64/agentmemory-runtime-helper")
	if err != nil {
		return verifiedNativePackage{}, err
	}
	return verifiedNativePackage{
		operatingSystem: "linux", architecture: "arm64",
		launcher: launcher, helper: helper,
	}, nil
}

type fakeCommandRunner struct {
	commands  []Command
	gitOutput []byte
	gitError  error
}

func (r *fakeCommandRunner) Run(_ context.Context, command Command) ([]byte, error) {
	r.commands = append(r.commands, command)
	if command.Name == "git" {
		return append([]byte(nil), r.gitOutput...), r.gitError
	}
	return nil, errors.New("unexpected command")
}
