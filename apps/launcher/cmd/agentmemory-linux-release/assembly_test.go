package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPF001LinuxReleaseStaticLimitsAreExact(t *testing.T) {
	t.Parallel()
	if maximumTrustDocumentBytes != 128*1024 {
		t.Fatal("Linux release trust boundary changed")
	}
}

func TestPF001LinuxReleaseReportsEveryInjectedFilesystemFailure(t *testing.T) {
	tests := []struct {
		name, prefix string
	}{
		{"mkdir-temp", "create private staging directory: "},
		{"copy-bundle", "stage release bundle: "},
		{"copy-resource", "stage verified agentmemory: "},
		{"normalize", "normalize staging directories: "},
		{"rename", "publish staging directory: "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAssemblyFixture(t)
			fault := errors.New("injected " + test.name)
			operations := &faultingAssemblyOperations{fail: test.name, err: fault}
			err := assembleWithOperations(
				t.Context(), fixture.options, &fakeCommandRunner{}, acceptNativeTrust, acceptBundle, operations,
			)
			if err == nil || !errors.Is(err, fault) || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("assembleWithOperations() error=%v", err)
			}
			if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed stage was published: %v", statErr)
			}
			temporary, globErr := filepath.Glob(filepath.Join(filepath.Dir(fixture.output), ".agentmemory-linux-stage-*"))
			if globErr != nil || len(temporary) != 0 {
				t.Fatalf("private Linux stages survived failure: paths=%v error=%v", temporary, globErr)
			}
		})
	}
}

func TestPF001LinuxReleaseResolverCoversFilesystemContracts(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	missingRoot := fixture.options
	missingRoot.RepositoryRoot += ".missing"
	if _, err := resolveAssemblyOptions(missingRoot); err == nil || errors.Unwrap(err) == nil ||
		!strings.HasPrefix(err.Error(), "resolve repository root links: ") {
		t.Fatalf("missing root error=%v", err)
	}
	fileRoot := fixture.options
	fileRoot.RepositoryRoot = fixture.trust
	if _, err := resolveAssemblyOptions(fileRoot); err == nil || err.Error() != "repository root is not a directory" {
		t.Fatalf("file root error=%v", err)
	}
	blockedOutput := fixture.options
	parentFile := filepath.Join(filepath.Dir(fixture.output), "output-parent-file")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedOutput.Output = filepath.Join(parentFile, "stage")
	_, blockedErr := resolveAssemblyOptions(blockedOutput)
	if blockedErr == nil {
		t.Fatal("output below a regular file was accepted")
	}
	if blockedErr.Error() != "output parent must be an existing non-symlink directory" &&
		(errors.Unwrap(blockedErr) == nil || !strings.HasPrefix(blockedErr.Error(), "inspect output: ")) {
		t.Fatalf("blocked output error=%v", blockedErr)
	}

	relative := fixture.options
	var err error
	relative.BundleRoot, err = filepath.Rel(relative.RepositoryRoot, relative.BundleRoot)
	if err != nil {
		t.Fatal(err)
	}
	relative.TrustDocument, err = filepath.Rel(relative.RepositoryRoot, relative.TrustDocument)
	if err != nil {
		t.Fatal(err)
	}
	relative.Output, err = filepath.Rel(relative.RepositoryRoot, relative.Output)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveAssemblyOptions(relative)
	if err != nil || !filepath.IsAbs(resolved.BundleRoot) || !filepath.IsAbs(resolved.TrustDocument) ||
		!filepath.IsAbs(resolved.Output) {
		t.Fatalf("relative assembly options=%+v,%v", resolved, err)
	}
	defaultRoot := fixture.options
	defaultRoot.RepositoryRoot = ""
	resolved, err = resolveAssemblyOptions(defaultRoot)
	if err != nil || resolved.RepositoryRoot == "" || !filepath.IsAbs(resolved.RepositoryRoot) {
		t.Fatalf("default repository options=%+v,%v", resolved, err)
	}
}

func TestPF001LinuxReleaseResolverAndRevisionPoliciesAreExact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		configure func(*AssemblyOptions)
		want      string
	}{
		{name: "empty architecture", configure: func(options *AssemblyOptions) { options.Architecture = "" }, want: "architecture must be amd64 or arm64"},
		{name: "unknown architecture", configure: func(options *AssemblyOptions) { options.Architecture = "386" }, want: "architecture must be amd64 or arm64"},
		{name: "zero source epoch", configure: func(options *AssemblyOptions) { options.SourceEpoch = 0 }, want: "source date epoch must be positive"},
		{name: "negative source epoch", configure: func(options *AssemblyOptions) { options.SourceEpoch = -1 }, want: "source date epoch must be positive"},
		{name: "zero verification epoch", configure: func(options *AssemblyOptions) { options.VerificationEpoch = 0 }, want: "release verification epoch must be positive"},
		{name: "negative verification epoch", configure: func(options *AssemblyOptions) { options.VerificationEpoch = -1 }, want: "release verification epoch must be positive"},
		{name: "missing bundle", configure: func(options *AssemblyOptions) { options.BundleRoot = "" }, want: "bundle root is required"},
		{name: "missing trust", configure: func(options *AssemblyOptions) { options.TrustDocument = "" }, want: "trust document is required"},
		{name: "missing output", configure: func(options *AssemblyOptions) { options.Output = "" }, want: "output is required"},
		{name: "missing output parent", configure: func(options *AssemblyOptions) {
			options.Output = filepath.Join(filepath.Dir(options.Output), "missing", "stage")
		}, want: "output parent must be an existing non-symlink directory"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAssemblyFixture(t)
			test.configure(&fixture.options)
			if _, err := resolveAssemblyOptions(fixture.options); err == nil || err.Error() != test.want {
				t.Fatalf("resolveAssemblyOptions() error=%v want=%q", err, test.want)
			}
		})
	}

	fixture := newAssemblyFixture(t)
	for _, architecture := range []string{"amd64", "arm64"} {
		options := fixture.options
		options.Architecture = architecture
		options.SourceEpoch, options.VerificationEpoch = 1, 1
		resolved, err := resolveAssemblyOptions(options)
		if err != nil || resolved.Architecture != architecture || resolved.SourceEpoch != 1 || resolved.VerificationEpoch != 1 {
			t.Fatalf("architecture=%q resolved=%+v error=%v", architecture, resolved, err)
		}
	}
	existing := newAssemblyFixture(t)
	if err := os.WriteFile(existing.output, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAssemblyOptions(existing.options); err == nil || err.Error() != "output already exists" {
		t.Fatalf("existing output error=%v", err)
	}
	symlinkedParent := newAssemblyFixture(t)
	realParent := t.TempDir()
	link := filepath.Join(filepath.Dir(symlinkedParent.output), "output-link")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	symlinkedParent.options.Output = filepath.Join(link, "stage")
	if _, err := resolveAssemblyOptions(symlinkedParent.options); err == nil || err.Error() != "output parent must be an existing non-symlink directory" {
		t.Fatalf("symlink output parent error=%v", err)
	}

	for _, test := range []struct {
		name   string
		runner *fakeCommandRunner
		want   string
	}{
		{name: "clean", runner: &fakeCommandRunner{}},
		{name: "command failure", runner: &fakeCommandRunner{gitError: errors.New("git failed")}, want: "verify clean source revision failed"},
		{name: "dirty", runner: &fakeCommandRunner{gitOutput: []byte(" M source.go\n")}, want: "source revision is dirty"},
	} {
		test := test
		t.Run("revision "+test.name, func(t *testing.T) {
			t.Parallel()
			err := requireCleanRevision(t.Context(), test.runner, "/closed/repository")
			if test.want == "" && err != nil || test.want != "" && (err == nil || err.Error() != test.want) {
				t.Fatalf("requireCleanRevision() error=%v want=%q", err, test.want)
			}
			if len(test.runner.commands) != 1 || !reflect.DeepEqual(test.runner.commands[0], Command{
				Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: "/closed/repository",
			}) {
				t.Fatalf("revision commands=%+v", test.runner.commands)
			}
		})
	}
}

func TestPF001LinuxReleaseAssemblyPublishesNormalizedClosedStage(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	runner := &fakeCommandRunner{}
	validated := ""
	var bundleValidation bundleValidationCall
	err := Assemble(context.Background(), fixture.options, runner, func(encoded string) error {
		validated = encoded
		return nil
	}, func(ctx context.Context, root string, trust string, operatingSystem string, architecture string, verifiedAt time.Time) (verifiedNativePackage, error) {
		if ctx == nil {
			return verifiedNativePackage{}, errors.New("nil verification context")
		}
		for _, relative := range []string{
			"bootstrap/distribution-manifest.json", "native/linux/arm64/agentmemory",
		} {
			info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
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
	if len(runner.commands) != 1 || runner.commands[0].Name != "git" ||
		!reflect.DeepEqual(runner.commands[0].Args, []string{"status", "--porcelain=v1", "--untracked-files=all"}) ||
		len(runner.commands[0].Env) != 0 {
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
		if runtime.GOOS != "windows" && info.Mode().Perm() != wantMode || info.ModTime().Unix() != epoch.Unix() {
			t.Errorf("%s mode=%04o mtime=%d, want %04o/%d", relative, info.Mode().Perm(), info.ModTime().Unix(), wantMode, epoch.Unix())
		}
	}
	content, err := os.ReadFile(filepath.Join(fixture.output, "bundle/models/embedding/model.bin"))
	if err != nil || string(content) != "model" {
		t.Fatalf("copied model = %q, error = %v", content, err)
	}
	for path, want := range map[string]string{
		"bundle/bootstrap/distribution-manifest.json":          `{"signed":true}`,
		"bundle/models/embedding/model.bin":                    "model",
		"bundle/native/linux/arm64/agentmemory":                "signed launcher bytes",
		"bundle/native/linux/arm64/agentmemory-runtime-helper": "signed helper bytes",
		"agentmemory":                "signed launcher bytes",
		"agentmemory-runtime-helper": "signed helper bytes",
	} {
		content, err := os.ReadFile(filepath.Join(fixture.output, path)) // #nosec G304 -- path is a closed test-owned leaf set.
		if err != nil || string(content) != want {
			t.Fatalf("packaged %s = %q, error = %v", path, content, err)
		}
	}
	assertExactLinuxStageTree(t, fixture.output)
}

func TestPF001LinuxReleaseAssemblyRejectsEveryUnsafeInput(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*testing.T, *assemblyFixture){
		"architecture": func(_ *testing.T, fixture *assemblyFixture) { fixture.options.Architecture = "386" },
		"epoch":        func(_ *testing.T, fixture *assemblyFixture) { fixture.options.SourceEpoch = 0 },
		"negative epoch": func(_ *testing.T, fixture *assemblyFixture) {
			fixture.options.SourceEpoch = -1
		},
		"verification epoch": func(_ *testing.T, fixture *assemblyFixture) {
			fixture.options.VerificationEpoch = 0
		},
		"negative verification epoch": func(_ *testing.T, fixture *assemblyFixture) {
			fixture.options.VerificationEpoch = -1
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
	if err := assembleWithOperations(
		context.Background(), fixture.options, runner, validator, acceptBundle, nil,
	); err == nil || err.Error() != "assembly capabilities are incomplete" {
		t.Fatalf("Assemble(nil operations) error=%v", err)
	}
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := Assemble(nil, fixture.options, runner, validator, acceptBundle); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("Assemble(nil context) error = nil")
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
	if content, err := readBoundedRegularFile(fixture.trust, int64(len(`{"schemaVersion":1}`))); err != nil || string(content) != `{"schemaVersion":1}` {
		t.Fatalf("readBoundedRegularFile(boundary)=%q error=%v", content, err)
	}
}

func TestPF001LinuxReleaseAssemblyRejectsUnboundNativePackageProjection(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*verifiedNativePackage){
		"empty":              func(value *verifiedNativePackage) { *value = verifiedNativePackage{} },
		"wrong target":       func(value *verifiedNativePackage) { value.operatingSystem = "windows" },
		"wrong architecture": func(value *verifiedNativePackage) { value.architecture = "amd64" },
		"empty launcher id":  func(value *verifiedNativePackage) { value.launcher.resourceID = "" },
		"empty launcher path": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = ""
		},
		"zero launcher size": func(value *verifiedNativePackage) { value.launcher.size = 0 },
		"short launcher digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 63)
		},
		"long launcher digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 65)
		},
		"path traversal": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = "../agentmemory"
		},
		"absolute path": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = filepath.Join(string(filepath.Separator), "agentmemory")
		},
		"dot path": func(value *verifiedNativePackage) { value.launcher.bundlePath = "." },
		"backslash path": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = `native\agentmemory`
		},
		"nul path": func(value *verifiedNativePackage) { value.launcher.bundlePath = "native/\x00agentmemory" },
		"noncanonical path": func(value *verifiedNativePackage) {
			value.launcher.bundlePath = "native/linux/../arm64/agentmemory"
		},
		"malformed digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("g", 64)
		},
		"wrong digest": func(value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 64)
		},
		"wrong size":         func(value *verifiedNativePackage) { value.helper.size++ },
		"same resource id":   func(value *verifiedNativePackage) { value.helper.resourceID = value.launcher.resourceID },
		"same resource path": func(value *verifiedNativePackage) { value.helper.bundlePath = value.launcher.bundlePath },
		"same resource digest": func(value *verifiedNativePackage) {
			value.helper.sha256 = value.launcher.sha256
		},
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

func acceptBundle(ctx context.Context, root string, _ string, _ string, _ string, _ time.Time) (verifiedNativePackage, error) {
	if ctx == nil {
		return verifiedNativePackage{}, errors.New("nil bundle context")
	}
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
	//lint:ignore SA1012 The process boundary must reject an adversarial nil context.
	if _, err := runner.Run(nil, Command{Name: "git", Dir: workingDirectory}); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("processRunner.Run(nil context) error = nil")
	}
	if _, err := runner.Run(context.Background(), Command{Dir: workingDirectory}); err == nil {
		t.Fatal("processRunner.Run(empty name) error = nil")
	}
	if _, err := runner.Run(context.Background(), Command{Name: "git"}); err == nil {
		t.Fatal("processRunner.Run(empty directory) error = nil")
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
	fixture := newAssemblyFixture(t)
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), linuxReleaseArguments(fixture.options), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Linux release assembly failed") {
		t.Fatalf("run(complete flags)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001LinuxReleaseCLICompositionIsExact(t *testing.T) {
	fixture := newAssemblyFixture(t)
	arguments := linuxReleaseArguments(fixture.options)
	ctx := context.WithValue(t.Context(), linuxReleaseContextKey{}, "closed-context")
	var capturedContext context.Context
	var capturedOptions AssemblyOptions
	var stdout, stderr bytes.Buffer
	code := runWithAssembly(ctx, arguments, &stdout, &stderr, func(gotContext context.Context, options AssemblyOptions) error {
		capturedContext, capturedOptions = gotContext, options
		return nil
	})
	if code != 0 || capturedContext != ctx || !reflect.DeepEqual(capturedOptions, fixture.options) ||
		stdout.String() != fixture.output+"\n" || stderr.Len() != 0 {
		t.Fatalf("runWithAssembly()=%d context=%v options=%+v stdout=%q stderr=%q", code, capturedContext, capturedOptions, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	fault := errors.New("injected assembly command")
	code = runWithAssembly(ctx, arguments, &stdout, &stderr, func(context.Context, AssemblyOptions) error { return fault })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "Linux release assembly failed: injected assembly command\n" {
		t.Fatalf("failed runWithAssembly()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	writer := &linuxReleaseCountingErrorWriter{}
	if code := runWithAssembly(ctx, arguments, writer, &stderr, func(context.Context, AssemblyOptions) error { return nil }); code != 1 || writer.calls != 1 {
		t.Fatalf("stdout failure code=%d calls=%d", code, writer.calls)
	}
	writer = &linuxReleaseCountingErrorWriter{}
	if code := runWithAssembly(ctx, arguments, &stdout, writer, func(context.Context, AssemblyOptions) error { return fault }); code != 1 || writer.calls != 1 {
		t.Fatalf("stderr failure code=%d calls=%d", code, writer.calls)
	}
	writer = &linuxReleaseCountingErrorWriter{}
	if code := runWithAssembly(ctx, []string{"unexpected"}, &stdout, writer, func(context.Context, AssemblyOptions) error { return nil }); code != 1 || writer.calls != 1 {
		t.Fatalf("positional stderr failure code=%d calls=%d", code, writer.calls)
	}
	stderr.Reset()
	if code := runWithAssembly(ctx, arguments, &stdout, &stderr, nil); code != 1 ||
		stderr.String() != "Linux release assembly failed: assembly command is unavailable\n" {
		t.Fatalf("nil assembly code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := runWithAssembly(ctx, []string{"-unknown"}, &stdout, &stderr, func(context.Context, AssemblyOptions) error { return nil }); code != 2 ||
		!strings.Contains(stderr.String(), "flag provided but not defined: -unknown") {
		t.Fatalf("parse failure code=%d stderr=%q", code, stderr.String())
	}
	launcherResource := newVerifiedNativeResource("launcher-id", "native/launcher", strings.Repeat("a", 64), 11)
	helperResource := newVerifiedNativeResource("helper-id", "native/helper", strings.Repeat("b", 64), 12)
	projected := newVerifiedNativePackage("linux", "arm64", launcherResource, helperResource)
	if !reflect.DeepEqual(projected, verifiedNativePackage{
		operatingSystem: "linux", architecture: "arm64",
		launcher: verifiedNativeResource{
			resourceID: "launcher-id", bundlePath: "native/launcher", sha256: strings.Repeat("a", 64), size: 11,
		},
		helper: verifiedNativeResource{
			resourceID: "helper-id", bundlePath: "native/helper", sha256: strings.Repeat("b", 64), size: 12,
		},
	}) {
		t.Fatalf("production projection=%+v", projected)
	}
}

func TestPF001LinuxReleaseValueAndBoundaryContractsAreExact(t *testing.T) {
	t.Parallel()
	fixture := newAssemblyFixture(t)
	valid := verifiedNativePackageAtRoot(t, fixture.bundle)
	if !valid.launcher.valid() || !valid.helper.valid() || !valid.valid("linux", "arm64") {
		t.Fatal("valid native package rejected")
	}
	for name, mutate := range map[string]func(*verifiedNativeResource){
		"id":     func(value *verifiedNativeResource) { value.resourceID = "" },
		"path":   func(value *verifiedNativeResource) { value.bundlePath = "" },
		"size":   func(value *verifiedNativeResource) { value.size = 0 },
		"length": func(value *verifiedNativeResource) { value.sha256 = strings.Repeat("0", 63) },
		"hex":    func(value *verifiedNativeResource) { value.sha256 = strings.Repeat("g", 64) },
	} {
		value := valid.launcher
		mutate(&value)
		if value.valid() {
			t.Fatalf("%s invalid resource accepted: %+v", name, value)
		}
	}
	for name, mutate := range map[string]func(*verifiedNativePackage){
		"os":           func(value *verifiedNativePackage) { value.operatingSystem = "windows" },
		"architecture": func(value *verifiedNativePackage) { value.architecture = "amd64" },
		"launcher":     func(value *verifiedNativePackage) { value.launcher.resourceID = "" },
		"helper":       func(value *verifiedNativePackage) { value.helper.resourceID = "" },
		"same id":      func(value *verifiedNativePackage) { value.helper.resourceID = value.launcher.resourceID },
		"same path":    func(value *verifiedNativePackage) { value.helper.bundlePath = value.launcher.bundlePath },
		"same digest":  func(value *verifiedNativePackage) { value.helper.sha256 = value.launcher.sha256 },
	} {
		value := valid
		mutate(&value)
		if value.valid("linux", "arm64") {
			t.Fatalf("%s invalid package accepted: %+v", name, value)
		}
	}
	for name, path := range map[string]string{
		"empty": "", "backslash": `native\agentmemory`, "nul": "native/\x00agentmemory",
		"absolute": filepath.Join(string(filepath.Separator), "agentmemory"), "dot": ".",
		"traversal": "../agentmemory", "noncanonical": "native/linux/../arm64/agentmemory",
	} {
		resource := valid.launcher
		resource.bundlePath = path
		err := copyVerifiedNativeResource(fixture.bundle, filepath.Join(t.TempDir(), "agentmemory"), resource, time.Unix(1, 0))
		if err == nil || err.Error() != "native resource projection is invalid" {
			t.Fatalf("%s path error=%v", name, err)
		}
	}
	boundaryRoot := t.TempDir()
	boundary := filepath.Join(boundaryRoot, "one")
	if err := os.WriteFile(boundary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readBoundedRegularFile(boundary, 1); err != nil || string(raw) != "x" {
		t.Fatalf("one-byte boundary=%q error=%v", raw, err)
	}
	if _, err := readBoundedRegularFile(boundary, 0); err == nil {
		t.Fatal("one-byte file accepted by zero bound")
	}
	options := fixture.options
	options.SourceEpoch, options.VerificationEpoch = 1, 1
	options.Architecture = "amd64"
	resolved, err := resolveAssemblyOptions(options)
	if err != nil || resolved.SourceEpoch != 1 || resolved.VerificationEpoch != 1 || resolved.Architecture != "amd64" {
		t.Fatalf("minimum options=%+v error=%v", resolved, err)
	}
	missingTrust := fixture.options
	missingTrust.TrustDocument = filepath.Join(t.TempDir(), "missing.json")
	if err := Assemble(t.Context(), missingTrust, &fakeCommandRunner{}, acceptNativeTrust, acceptBundle); err == nil ||
		err.Error() != "read release trust: input must be a bounded non-empty regular file" {
		t.Fatalf("missing trust error=%v", err)
	}
}

type assemblyFixture struct {
	repository string
	bundle     string
	trust      string
	output     string
	options    AssemblyOptions
}

type linuxReleaseContextKey struct{}

type linuxReleaseCountingErrorWriter struct{ calls int }

func (writer *linuxReleaseCountingErrorWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("injected writer failure")
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

type faultingAssemblyOperations struct {
	system systemAssemblyOperations
	fail   string
	err    error
}

func (o *faultingAssemblyOperations) MkdirTemp(parent string, pattern string) (string, error) {
	if o.fail == "mkdir-temp" {
		return "", o.err
	}
	return o.system.MkdirTemp(parent, pattern)
}

func (o *faultingAssemblyOperations) CopyBundle(source string, target string, epoch time.Time) error {
	if o.fail == "copy-bundle" {
		return o.err
	}
	return o.system.CopyBundle(source, target, epoch)
}

func (o *faultingAssemblyOperations) CopyVerifiedNativeResource(
	root string,
	target string,
	resource verifiedNativeResource,
	epoch time.Time,
) error {
	if o.fail == "copy-resource" {
		return o.err
	}
	return o.system.CopyVerifiedNativeResource(root, target, resource, epoch)
}

func (o *faultingAssemblyOperations) NormalizeDirectoryTree(root string, epoch time.Time) error {
	if o.fail == "normalize" {
		return o.err
	}
	return o.system.NormalizeDirectoryTree(root, epoch)
}

func (o *faultingAssemblyOperations) Rename(oldPath string, newPath string) error {
	if o.fail == "rename" {
		return o.err
	}
	return o.system.Rename(oldPath, newPath)
}

func (o *faultingAssemblyOperations) RemoveAll(path string) error {
	return o.system.RemoveAll(path)
}

func (r *fakeCommandRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil command context")
	}
	r.commands = append(r.commands, command)
	if command.Name == "git" {
		return append([]byte(nil), r.gitOutput...), r.gitError
	}
	return nil, errors.New("unexpected command")
}

func linuxReleaseArguments(options AssemblyOptions) []string {
	return []string{
		"-root", options.RepositoryRoot,
		"-bundle", options.BundleRoot,
		"-trust", options.TrustDocument,
		"-output", options.Output,
		"-arch", options.Architecture,
		"-source-date-epoch", fmt.Sprintf("%d", options.SourceEpoch),
		"-verification-epoch", fmt.Sprintf("%d", options.VerificationEpoch),
	}
}

func acceptNativeTrust(string) error { return nil }

func assertExactLinuxStageTree(t testing.TB, root string) {
	t.Helper()
	var got []string
	if err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got = append(got, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		".", "agentmemory", "agentmemory-runtime-helper", "bundle", "bundle/bootstrap",
		"bundle/bootstrap/distribution-manifest.json", "bundle/models", "bundle/models/embedding",
		"bundle/models/embedding/model.bin", "bundle/native", "bundle/native/linux",
		"bundle/native/linux/arm64", "bundle/native/linux/arm64/agentmemory",
		"bundle/native/linux/arm64/agentmemory-runtime-helper",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stage tree=%v want=%v", got, want)
	}
}
