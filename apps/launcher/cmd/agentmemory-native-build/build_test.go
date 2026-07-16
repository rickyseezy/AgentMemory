package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

const testSourceCommit = "0123456789abcdef0123456789abcdef01234567"

func TestPF001NativeBuildStaticAuthorityIsExact(t *testing.T) {
	t.Parallel()
	if requiredGoVersion != "go1.26.5" || maximumTrustDocumentBytes != 128*1024 ||
		maximumNativeBinaryBytes != 512*1024*1024 || nativeBuildMetadataName != "unsigned-build.json" ||
		releaseTrustVariable != "github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher.embeddedNativeReleaseTrustBase64" {
		t.Fatal("native build release authority changed")
	}
}

func TestPF001NativeBuildReportsEveryInjectedFilesystemFailure(t *testing.T) {
	tests := []struct {
		name, prefix string
	}{
		{"mkdir-temp", "create private native build root: "},
		{"mkdir-pass", "create reproducibility pass: "},
		{"remove-first", "remove first comparison root: "},
		{"remove-second", "remove second comparison root: "},
		{"metadata", "write native build metadata: "},
		{"normalize", "normalize native build root: "},
		{"rename", "publish native build: "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNativeBuildFixture(t)
			fault := errors.New("injected " + test.name)
			operations := &faultingBuildOperations{fail: test.name, err: fault}
			runner := &nativeBuildRunner{goVersion: requiredGoVersion, sourceCommit: testSourceCommit}
			err := buildWithOperations(t.Context(), fixture.options, runner, acceptNativeTrust, operations)
			if err == nil || !errors.Is(err, fault) || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("buildWithOperations() error=%v", err)
			}
			if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed build was published: %v", statErr)
			}
			temporary, globErr := filepath.Glob(filepath.Join(filepath.Dir(fixture.output), ".agentmemory-native-build-*"))
			if globErr != nil || len(temporary) != 0 {
				t.Fatalf("private build roots survived failure: paths=%v error=%v", temporary, globErr)
			}
		})
	}
}

func TestPF001NativeBuildResolverCoversRuntimeAndFilesystemContracts(t *testing.T) {
	t.Parallel()
	fixture := newNativeBuildFixture(t)
	missingRoot := fixture.options
	missingRoot.RepositoryRoot += ".missing"
	if _, err := resolveBuildOptions(missingRoot); err == nil || errors.Unwrap(err) == nil ||
		!strings.HasPrefix(err.Error(), "resolve repository root links: ") {
		t.Fatalf("missing root error=%v", err)
	}
	fileRoot := fixture.options
	fileRoot.RepositoryRoot = fixture.trust
	if _, err := resolveBuildOptions(fileRoot); err == nil || err.Error() != "repository root is not a directory" {
		t.Fatalf("file root error=%v", err)
	}
	blockedOutput := fixture.options
	parentFile := filepath.Join(filepath.Dir(fixture.output), "output-parent-file")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedOutput.Output = filepath.Join(parentFile, "native")
	if _, err := resolveBuildOptions(blockedOutput); err == nil || errors.Unwrap(err) == nil ||
		!strings.HasPrefix(err.Error(), "inspect output: ") {
		t.Fatalf("blocked output error=%v", err)
	}

	darwin := fixture.options
	darwin.OperatingSystem = "darwin"
	if _, err := resolveBuildOptionsForRuntime(darwin, "linux", "amd64"); err == nil ||
		err.Error() != "darwin CGO release builds require an exact native runner" {
		t.Fatalf("foreign Darwin runner error=%v", err)
	}
	resolvedDarwin, err := resolveBuildOptionsForRuntime(darwin, "darwin", "arm64")
	if err != nil || resolvedDarwin.cgoEnabled != "1" {
		t.Fatalf("native Darwin options=%+v,%v", resolvedDarwin, err)
	}

	relative := fixture.options
	relative.TrustDocument, err = filepath.Rel(fixture.root, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	relative.Output, err = filepath.Rel(fixture.root, fixture.output)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveBuildOptions(relative)
	if err != nil || !filepath.IsAbs(resolved.TrustDocument) || !filepath.IsAbs(resolved.Output) ||
		resolved.cgoEnabled != "0" {
		t.Fatalf("relative build options=%+v,%v", resolved, err)
	}
	defaultRoot := fixture.options
	defaultRoot.RepositoryRoot = ""
	resolved, err = resolveBuildOptions(defaultRoot)
	if err != nil || resolved.RepositoryRoot == "" || !filepath.IsAbs(resolved.RepositoryRoot) {
		t.Fatalf("default repository options=%+v,%v", resolved, err)
	}
}

func TestPF001NativeBuildResolverEnforcesEveryClosedPolicyAlternative(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		configure func(*BuildOptions)
		want      string
	}{
		{name: "empty operating system", configure: func(options *BuildOptions) { options.OperatingSystem = "" }, want: "operating system must be linux, windows, or darwin"},
		{name: "unknown operating system", configure: func(options *BuildOptions) { options.OperatingSystem = "freebsd" }, want: "operating system must be linux, windows, or darwin"},
		{name: "empty architecture", configure: func(options *BuildOptions) { options.Architecture = "" }, want: "architecture must be amd64 or arm64"},
		{name: "unknown architecture", configure: func(options *BuildOptions) { options.Architecture = "386" }, want: "architecture must be amd64 or arm64"},
		{name: "zero epoch", configure: func(options *BuildOptions) { options.SourceEpoch = 0 }, want: "source date epoch must be positive"},
		{name: "negative epoch", configure: func(options *BuildOptions) { options.SourceEpoch = -1 }, want: "source date epoch must be positive"},
		{name: "missing trust", configure: func(options *BuildOptions) { options.TrustDocument = "" }, want: "trust document is required"},
		{name: "missing output", configure: func(options *BuildOptions) { options.Output = "" }, want: "output is required"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newNativeBuildFixture(t)
			test.configure(&fixture.options)
			if _, err := resolveBuildOptionsForRuntime(fixture.options, "linux", "arm64"); err == nil || err.Error() != test.want {
				t.Fatalf("resolveBuildOptionsForRuntime() error=%v want=%q", err, test.want)
			}
		})
	}

	fixture := newNativeBuildFixture(t)
	for _, target := range []struct {
		operatingSystem string
		architecture    string
		runnerOS        string
		runnerArch      string
		cgo             string
	}{
		{operatingSystem: "linux", architecture: "amd64", runnerOS: "windows", runnerArch: "arm64", cgo: "0"},
		{operatingSystem: "linux", architecture: "arm64", runnerOS: "linux", runnerArch: "amd64", cgo: "0"},
		{operatingSystem: "windows", architecture: "amd64", runnerOS: "linux", runnerArch: "arm64", cgo: "0"},
		{operatingSystem: "windows", architecture: "arm64", runnerOS: "darwin", runnerArch: "amd64", cgo: "0"},
		{operatingSystem: "darwin", architecture: "amd64", runnerOS: "darwin", runnerArch: "amd64", cgo: "1"},
		{operatingSystem: "darwin", architecture: "arm64", runnerOS: "darwin", runnerArch: "arm64", cgo: "1"},
	} {
		options := fixture.options
		options.OperatingSystem = target.operatingSystem
		options.Architecture = target.architecture
		options.SourceEpoch = 1
		resolved, err := resolveBuildOptionsForRuntime(options, target.runnerOS, target.runnerArch)
		if err != nil || resolved.OperatingSystem != target.operatingSystem ||
			resolved.Architecture != target.architecture || resolved.SourceEpoch != 1 ||
			resolved.cgoEnabled != target.cgo {
			t.Fatalf("target=%+v resolved=%+v error=%v", target, resolved, err)
		}
	}
	for _, runner := range []struct{ operatingSystem, architecture string }{
		{operatingSystem: "linux", architecture: "arm64"},
		{operatingSystem: "darwin", architecture: "amd64"},
	} {
		options := fixture.options
		options.OperatingSystem = "darwin"
		options.Architecture = "arm64"
		if _, err := resolveBuildOptionsForRuntime(options, runner.operatingSystem, runner.architecture); err == nil ||
			err.Error() != "darwin CGO release builds require an exact native runner" {
			t.Fatalf("foreign Darwin runner=%+v error=%v", runner, err)
		}
	}

	existing := fixture.options
	if err := os.WriteFile(existing.Output, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBuildOptions(existing); err == nil || err.Error() != "output already exists" {
		t.Fatalf("existing output error=%v", err)
	}
}

func TestPF001NativeBuildSourceAndToolchainAuthorityIsExact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		runner *nativeBuildRunner
		want   string
	}{
		{name: "status command", runner: &nativeBuildRunner{gitError: errors.New("status failed")}, want: "verify clean source revision failed"},
		{name: "dirty revision", runner: &nativeBuildRunner{dirty: true}, want: "source revision is dirty"},
		{name: "revision command", runner: &nativeBuildRunner{revisionError: errors.New("revision failed"), sourceCommit: testSourceCommit}, want: "resolve exact source revision failed"},
		{name: "invalid revision", runner: &nativeBuildRunner{sourceCommit: strings.Repeat("g", 40)}, want: "resolve exact source revision failed"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := cleanSourceCommit(t.Context(), test.runner, "/closed/repository"); err == nil || err.Error() != test.want {
				t.Fatalf("cleanSourceCommit() error=%v want=%q", err, test.want)
			}
		})
	}
	validRunner := &nativeBuildRunner{sourceCommit: testSourceCommit}
	commit, err := cleanSourceCommit(t.Context(), validRunner, "/closed/repository")
	if err != nil || commit != testSourceCommit || len(validRunner.commands) != 2 ||
		!reflect.DeepEqual(validRunner.commands[0], Command{
			Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: "/closed/repository",
		}) || !reflect.DeepEqual(validRunner.commands[1], Command{
		Name: "git", Args: []string{"rev-parse", "HEAD"}, Dir: "/closed/repository",
	}) {
		t.Fatalf("commit=%q commands=%+v error=%v", commit, validRunner.commands, err)
	}

	for _, test := range []struct {
		name string
		raw  string
		err  error
		want string
	}{
		{name: "exact", raw: "go version " + requiredGoVersion + " test/arch\n"},
		{name: "command error", err: errors.New("go failed"), want: "release build requires exact Go toolchain " + requiredGoVersion},
		{name: "missing field", raw: "go version " + requiredGoVersion, want: "release build requires exact Go toolchain " + requiredGoVersion},
		{name: "wrong executable", raw: "gcc version " + requiredGoVersion + " test/arch", want: "release build requires exact Go toolchain " + requiredGoVersion},
		{name: "wrong marker", raw: "go release " + requiredGoVersion + " test/arch", want: "release build requires exact Go toolchain " + requiredGoVersion},
		{name: "wrong version", raw: "go version go1.99.0 test/arch", want: "release build requires exact Go toolchain " + requiredGoVersion},
	} {
		test := test
		t.Run("toolchain "+test.name, func(t *testing.T) {
			t.Parallel()
			runner := commandRunnerFunc(func(_ context.Context, command Command) ([]byte, error) {
				if !reflect.DeepEqual(command, Command{Name: "go", Args: []string{"version"}, Dir: "/closed/repository"}) {
					t.Fatalf("toolchain command=%+v", command)
				}
				return []byte(test.raw), test.err
			})
			err := requireToolchain(t.Context(), runner, "/closed/repository")
			if test.want == "" && err != nil || test.want != "" && (err == nil || err.Error() != test.want) {
				t.Fatalf("requireToolchain() error=%v want=%q", err, test.want)
			}
		})
	}
}

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
	if decoded, err := base64.StdEncoding.DecodeString(validated); err != nil || string(decoded) != `{"schemaVersion":1}` || len(runner.commands) != 9 {
		t.Fatalf("validated=%q commands=%+v", validated, runner.commands)
	}
	if !reflect.DeepEqual(runner.commands[0].Args, []string{"status", "--porcelain=v1", "--untracked-files=all"}) ||
		!reflect.DeepEqual(runner.commands[1].Args, []string{"rev-parse", "HEAD"}) ||
		!reflect.DeepEqual(runner.commands[2].Args, []string{"version"}) {
		t.Fatalf("authority commands=%+v", runner.commands[:3])
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
		"agentmemory-bootstrap":      "bootstrap deterministic bytes",
		"agentmemory-runtime-helper": "helper deterministic bytes",
	} {
		path := filepath.Join(fixture.output, name)
		content, err := os.ReadFile(path) // #nosec G304 -- closed test-owned filename set.
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || string(content) != want ||
			(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
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
		metadata.SourceEpoch != fixture.options.SourceEpoch || len(metadata.Artifacts) != 3 {
		t.Fatalf("metadata=%+v error=%v", metadata, err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("metadata is not newline terminated: %q", raw)
	}
	wantArtifacts := []nativeBuildArtifact{
		nativeArtifact("agentmemory", "./apps/launcher/cmd/agentmemory", "launcher deterministic bytes"),
		nativeArtifact("agentmemory-bootstrap", "./apps/launcher/cmd/agentmemory-bootstrap", "bootstrap deterministic bytes"),
		nativeArtifact("agentmemory-runtime-helper", "./apps/launcher/cmd/agentmemory-runtime-helper", "helper deterministic bytes"),
	}
	if !reflect.DeepEqual(metadata.Artifacts, wantArtifacts) {
		t.Fatalf("metadata artifacts=%+v want=%+v", metadata.Artifacts, wantArtifacts)
	}
	entries, err := os.ReadDir(fixture.output)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if want := []string{"agentmemory", "agentmemory-bootstrap", "agentmemory-runtime-helper", nativeBuildMetadataName}; !reflect.DeepEqual(names, want) {
		t.Fatalf("native build tree=%v want=%v", names, want)
	}
	metadataInfo, err := os.Lstat(filepath.Join(fixture.output, nativeBuildMetadataName))
	if err != nil || runtime.GOOS != "windows" && metadataInfo.Mode().Perm() != 0o644 || metadataInfo.ModTime().Unix() != epoch.Unix() {
		t.Fatalf("metadata info=%v error=%v", metadataInfo, err)
	}
	outputInfo, err := os.Lstat(fixture.output)
	if err != nil || runtime.GOOS != "windows" && outputInfo.Mode().Perm() != 0o755 || outputInfo.ModTime().Unix() != epoch.Unix() {
		t.Fatalf("output info=%v error=%v", outputInfo, err)
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
		"negative epoch": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.SourceEpoch = -1
			return acceptNativeTrust
		},
		"architecture": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.Architecture = "386"
			return acceptNativeTrust
		},
		"missing trust": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.TrustDocument = ""
			return acceptNativeTrust
		},
		"missing output path": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.Output = ""
			return acceptNativeTrust
		},
		"missing output parent": func(fixture *nativeBuildFixture, _ *nativeBuildRunner) trustValidator {
			fixture.options.Output = filepath.Join(fixture.root, "missing", "native")
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
	if err := buildWithOperations(
		context.Background(), fixture.options, runner, acceptNativeTrust, nil,
	); err == nil || err.Error() != "native build capabilities are incomplete" {
		t.Fatalf("Build(nil operations) error=%v", err)
	}
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := Build(nil, fixture.options, runner, acceptNativeTrust); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("Build(nil context) error=nil")
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
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nativeBuildArguments(fixture.options), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Native build failed") {
		t.Fatalf("run(complete flags)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, invalid := range []string{strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 40)} {
		if validSourceCommit(invalid) {
			t.Fatalf("invalid source commit accepted: %q", invalid)
		}
	}
	if !validSourceCommit(strings.Repeat("a", 40)) {
		t.Fatal("valid 40-character source commit rejected")
	}
	if raw, err := readBoundedRegularFile(fixture.trust, int64(len(`{"schemaVersion":1}`))); err != nil || string(raw) != `{"schemaVersion":1}` {
		t.Fatalf("bounded trust=%q error=%v", raw, err)
	}
	if _, err := readBoundedRegularFile(fixture.trust, 1); err == nil {
		t.Fatal("oversized trust accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(empty, 1); err == nil {
		t.Fatal("empty trust accepted")
	}
	directory := t.TempDir()
	if _, err := readBoundedRegularFile(directory, 1); err == nil || err.Error() != "input must be a bounded non-empty regular file" {
		t.Fatalf("directory trust error=%v", err)
	}
	symlink := filepath.Join(t.TempDir(), "trust-link")
	if err := os.Symlink(fixture.trust, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(symlink, int64(len(`{"schemaVersion":1}`))); err == nil ||
		err.Error() != "input must be a bounded non-empty regular file" {
		t.Fatalf("symlink trust error=%v", err)
	}
	if _, _, err := regularFileDigest(empty); err == nil {
		t.Fatal("empty native binary accepted")
	}
	if _, _, err := regularFileDigest(directory); err == nil || err.Error() != "native build did not produce a bounded regular file" {
		t.Fatalf("directory native binary error=%v", err)
	}
	if _, _, err := regularFileDigest(symlink); err == nil || err.Error() != "native build did not produce a bounded regular file" {
		t.Fatalf("symlink native binary error=%v", err)
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
	//lint:ignore SA1012 The process boundary must reject an adversarial nil context.
	if _, err := runner.Run(nil, Command{Name: "git", Dir: working}); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil process context accepted")
	}
	if _, err := runner.Run(context.Background(), Command{Name: "git"}); err == nil {
		t.Fatal("empty process directory accepted")
	}
	if _, err := runner.Run(context.Background(), Command{Name: "", Dir: working}); err == nil {
		t.Fatal("empty executable accepted")
	}
	if output, err := runner.Run(context.Background(), Command{
		Name: "go", Args: []string{"version"}, Dir: working,
	}); err != nil || !bytes.Contains(output, []byte("go version")) {
		t.Fatalf("go output=%q error=%v", output, err)
	}
	if _, err := runner.Run(context.Background(), Command{
		Name: "git", Args: []string{"definitely-not-a-git-command"}, Dir: working,
	}); err == nil {
		t.Fatal("failed process reported success")
	}
	t.Setenv("AGENTMEMORY_NATIVE_BUILD_FORBIDDEN", "secret")
	for index, name := range []string{"HOME", "PATH", "SystemRoot", "TEMP", "TMP", "TMPDIR", "USERPROFILE"} {
		t.Setenv(name, fmt.Sprintf("/closed/environment/%d", index))
	}
	t.Setenv("TEMP", "")
	environment := closedBuildEnvironment(map[string]string{"GOOS": "linux", "HOME": "/closed/home"})
	if !sort.StringsAreSorted(environment) || !containsString(environment, "GOOS=linux") ||
		!containsString(environment, "HOME=/closed/home") || !containsString(environment, "PATH=/closed/environment/1") ||
		!containsString(environment, "SystemRoot=/closed/environment/2") || !containsString(environment, "TMP=/closed/environment/4") ||
		!containsString(environment, "TMPDIR=/closed/environment/5") || !containsString(environment, "USERPROFILE=/closed/environment/6") ||
		containsPrefix(environment, "TEMP=") || containsPrefix(environment, "AGENTMEMORY_NATIVE_BUILD_FORBIDDEN=") {
		t.Fatalf("closed environment=%v", environment)
	}
}

func TestPF001NativeBuildCLIReportsExactBoundaryFailures(t *testing.T) {
	fixture := newNativeBuildFixture(t)
	var stdout, stderr bytes.Buffer
	arguments := []string{
		"-root", fixture.options.RepositoryRoot,
		"-trust", fixture.options.TrustDocument,
		"-output", fixture.options.Output,
		"-os", fixture.options.OperatingSystem,
		"-arch", fixture.options.Architecture,
	}
	if code := run(t.Context(), arguments, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "source date epoch must be positive") {
		t.Fatalf("run(omitted epoch)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), []string{"-unknown"}, &stdout, &stderr); code != 2 ||
		!strings.Contains(stderr.String(), "flag provided but not defined: -unknown") {
		t.Fatalf("run(unknown flag)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), nativeBuildArguments(fixture.options), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "release trust is not accepted by the production decoder") {
		t.Fatalf("run(process failure)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	//lint:ignore SA1012 The CLI boundary must propagate an adversarial nil context into the capability guard.
	if code := run(nil, nativeBuildArguments(fixture.options), &stdout, &stderr); code != 1 || //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		!strings.Contains(stderr.String(), "native build capabilities are incomplete") {
		t.Fatalf("run(nil context)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001NativeBuildCLICompositionIsExact(t *testing.T) {
	fixture := newNativeBuildFixture(t)
	arguments := nativeBuildArguments(fixture.options)
	ctx := context.WithValue(t.Context(), nativeBuildContextKey{}, "closed-context")
	var capturedContext context.Context
	var capturedOptions BuildOptions
	var stdout, stderr bytes.Buffer
	code := runWithBuild(ctx, arguments, &stdout, &stderr, func(gotContext context.Context, options BuildOptions) error {
		capturedContext, capturedOptions = gotContext, options
		return nil
	})
	if code != 0 || capturedContext != ctx || !reflect.DeepEqual(capturedOptions, fixture.options) ||
		stdout.String() != fixture.output+"\n" || stderr.Len() != 0 {
		t.Fatalf("runWithBuild()=%d context=%v options=%+v stdout=%q stderr=%q", code, capturedContext, capturedOptions, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	fault := errors.New("injected build command")
	code = runWithBuild(ctx, arguments, &stdout, &stderr, func(context.Context, BuildOptions) error { return fault })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "Native build failed: injected build command\n" {
		t.Fatalf("failed runWithBuild()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	writer := &countingErrorWriter{}
	if code := runWithBuild(ctx, arguments, writer, &stderr, func(context.Context, BuildOptions) error { return nil }); code != 1 || writer.calls != 1 {
		t.Fatalf("stdout failure code=%d calls=%d", code, writer.calls)
	}
	writer = &countingErrorWriter{}
	if code := runWithBuild(ctx, arguments, &stdout, writer, func(context.Context, BuildOptions) error { return fault }); code != 1 || writer.calls != 1 {
		t.Fatalf("stderr failure code=%d calls=%d", code, writer.calls)
	}
	stderr.Reset()
	if code := runWithBuild(ctx, arguments, &stdout, &stderr, nil); code != 1 ||
		stderr.String() != "Native build failed: build command is unavailable\n" {
		t.Fatalf("nil build code=%d stderr=%q", code, stderr.String())
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
	revisionError    error
	buildErrorAt     int
	skipBuildAt      int
	builds           int
	nondeterministic bool
}

type nativeBuildContextKey struct{}

type countingErrorWriter struct{ calls int }

func (writer *countingErrorWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("injected writer failure")
}

type commandRunnerFunc func(context.Context, Command) ([]byte, error)

func (function commandRunnerFunc) Run(ctx context.Context, command Command) ([]byte, error) {
	return function(ctx, command)
}

type faultingBuildOperations struct {
	system         systemBuildOperations
	fail           string
	err            error
	removeAllCalls int
}

func (o *faultingBuildOperations) MkdirTemp(parent string, pattern string) (string, error) {
	if o.fail == "mkdir-temp" {
		return "", o.err
	}
	return o.system.MkdirTemp(parent, pattern)
}

func (o *faultingBuildOperations) Mkdir(path string, mode os.FileMode) error {
	if o.fail == "mkdir-pass" {
		return o.err
	}
	return o.system.Mkdir(path, mode)
}

func (o *faultingBuildOperations) RemoveAll(path string) error {
	o.removeAllCalls++
	if o.fail == "remove-first" && o.removeAllCalls == 1 ||
		o.fail == "remove-second" && o.removeAllCalls == 2 {
		return o.err
	}
	return o.system.RemoveAll(path)
}

func (o *faultingBuildOperations) WriteBuildMetadata(
	path string,
	metadata nativeBuildMetadata,
	epoch time.Time,
) error {
	if o.fail == "metadata" {
		return o.err
	}
	return o.system.WriteBuildMetadata(path, metadata, epoch)
}

func (o *faultingBuildOperations) NormalizeDirectory(root string, epoch time.Time) error {
	if o.fail == "normalize" {
		return o.err
	}
	return o.system.NormalizeDirectory(root, epoch)
}

func (o *faultingBuildOperations) Rename(oldPath string, newPath string) error {
	if o.fail == "rename" {
		return o.err
	}
	return o.system.Rename(oldPath, newPath)
}

func (r *nativeBuildRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil command context")
	}
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
		if r.revisionError != nil {
			return nil, r.revisionError
		}
		return []byte(r.sourceCommit + "\n"), nil
	}
	if command.Name != "go" || len(command.Args) == 0 {
		return nil, errors.New("unexpected command")
	}
	if command.Args[0] == "version" {
		if !reflect.DeepEqual(command.Args, []string{"version"}) || command.Dir == "" || len(command.Env) != 0 {
			return nil, errors.New("invalid version command")
		}
		return []byte("go version " + r.goVersion + " test/arch\n"), nil
	}
	if command.Dir == "" || !reflect.DeepEqual(command.Env, map[string]string{
		"CGO_ENABLED": "0", "GOARCH": "arm64", "GOOS": "linux", "GOENV": "off",
		"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
	}) || len(command.Args) != 8 || !reflect.DeepEqual(command.Args[:6], []string{
		"build", "-buildvcs=true", "-trimpath", "-ldflags", command.Args[4], "-o",
	}) || !strings.HasPrefix(command.Args[4], "-buildid= -X "+releaseTrustVariable+"=") {
		return nil, errors.New("invalid build command")
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
	if strings.HasSuffix(packagePath, "agentmemory-bootstrap") {
		content = "bootstrap deterministic bytes"
	} else if strings.HasSuffix(packagePath, "agentmemory-runtime-helper") {
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

func nativeArtifact(name, packagePath, content string) nativeBuildArtifact {
	digest := sha256.Sum256([]byte(content))
	return nativeBuildArtifact{Name: name, Package: packagePath, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content))}
}

func nativeBuildArguments(options BuildOptions) []string {
	return []string{
		"-root", options.RepositoryRoot,
		"-trust", options.TrustDocument,
		"-output", options.Output,
		"-os", options.OperatingSystem,
		"-arch", options.Architecture,
		"-source-date-epoch", fmt.Sprintf("%d", options.SourceEpoch),
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func commandArgumentAfter(arguments []string, name string) string {
	for index, argument := range arguments {
		if argument == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}
