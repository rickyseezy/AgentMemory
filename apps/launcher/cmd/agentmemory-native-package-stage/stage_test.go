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

func TestPF001NativeStageStaticLimitsAreExact(t *testing.T) {
	t.Parallel()
	if maximumTrustDocumentBytes != 128*1024 {
		t.Fatal("native stage trust boundary changed")
	}
}

func TestPF001NativeStageValueContractsAreIndependentAndExact(t *testing.T) {
	t.Parallel()
	launcher := verifiedNativeResource{
		resourceID: "launcher", bundlePath: "native/launcher", sha256: strings.Repeat("a", 64), size: 1,
	}
	helper := verifiedNativeResource{
		resourceID: "helper", bundlePath: "native/helper", sha256: strings.Repeat("b", 64), size: 1,
	}
	if !launcher.valid() || !helper.valid() {
		t.Fatal("minimum valid native resources were rejected")
	}
	for name, mutate := range map[string]func(*verifiedNativeResource){
		"resource id":   func(value *verifiedNativeResource) { value.resourceID = "" },
		"bundle path":   func(value *verifiedNativeResource) { value.bundlePath = "" },
		"size":          func(value *verifiedNativeResource) { value.size = 0 },
		"digest length": func(value *verifiedNativeResource) { value.sha256 = strings.Repeat("a", 62) },
		"digest hex":    func(value *verifiedNativeResource) { value.sha256 = strings.Repeat("g", 64) },
	} {
		value := launcher
		mutate(&value)
		if value.valid() {
			t.Fatalf("resource with invalid %s accepted: %+v", name, value)
		}
	}

	valid := verifiedNativePackage{
		operatingSystem: "darwin", architecture: "arm64", launcher: launcher, helper: helper,
	}
	if !valid.valid("darwin", "arm64") {
		t.Fatal("valid native package rejected")
	}
	for name, mutate := range map[string]func(*verifiedNativePackage){
		"operating system": func(value *verifiedNativePackage) { value.operatingSystem = "windows" },
		"architecture":     func(value *verifiedNativePackage) { value.architecture = "amd64" },
		"launcher":         func(value *verifiedNativePackage) { value.launcher.resourceID = "" },
		"helper":           func(value *verifiedNativePackage) { value.helper.resourceID = "" },
		"resource id":      func(value *verifiedNativePackage) { value.helper.resourceID = value.launcher.resourceID },
		"bundle path":      func(value *verifiedNativePackage) { value.helper.bundlePath = value.launcher.bundlePath },
		"digest":           func(value *verifiedNativePackage) { value.helper.sha256 = value.launcher.sha256 },
	} {
		value := valid
		mutate(&value)
		if value.valid("darwin", "arm64") {
			t.Fatalf("package with invalid %s accepted: %+v", name, value)
		}
	}
}

func TestPF001NativeStageSystemOperationAdaptersPropagateErrors(t *testing.T) {
	t.Parallel()
	operations := systemStageOperations{}
	existing := t.TempDir()
	if err := operations.Mkdir(existing, 0o700); err == nil {
		t.Fatal("system Mkdir adapter suppressed an existing-directory error")
	}
	if err := operations.NormalizePackageDirectories(filepath.Join(existing, "missing"), time.Unix(1, 0)); err == nil {
		t.Fatal("system normalization adapter suppressed a missing-root error")
	}
}

func TestPF001NativeStageResourceCopyRejectsEachPathInvariantDirectly(t *testing.T) {
	t.Parallel()
	valid := verifiedNativeResource{
		resourceID: "launcher", bundlePath: "native/launcher", sha256: strings.Repeat("a", 64), size: 1,
	}
	for name, mutate := range map[string]func(*verifiedNativeResource){
		"invalid resource": func(value *verifiedNativeResource) { value.resourceID = "" },
		"backslash":        func(value *verifiedNativeResource) { value.bundlePath = `native\launcher` },
		"nul":              func(value *verifiedNativeResource) { value.bundlePath = "native/\x00launcher" },
		"absolute": func(value *verifiedNativeResource) {
			value.bundlePath = filepath.Join(string(filepath.Separator), "launcher")
		},
		"noncanonical": func(value *verifiedNativeResource) { value.bundlePath = "native/../launcher" },
		"dot":          func(value *verifiedNativeResource) { value.bundlePath = "." },
		"traversal":    func(value *verifiedNativeResource) { value.bundlePath = "../launcher" },
	} {
		resource := valid
		mutate(&resource)
		err := copyVerifiedNativeResource(t.TempDir(), filepath.Join(t.TempDir(), "launcher"), resource, time.Unix(1, 0))
		if err == nil || err.Error() != "native resource projection is invalid" {
			t.Fatalf("%s projection error=%v", name, err)
		}
	}
}

func TestPF001NativeStageResourceCopyAcceptsCaseInsensitiveVerifiedDigest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	content := []byte("x")
	if err := os.WriteFile(filepath.Join(root, "launcher"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	resource := verifiedNativeResource{
		resourceID: "launcher", bundlePath: "launcher", sha256: strings.ToUpper(hex.EncodeToString(digest[:])), size: 1,
	}
	target := filepath.Join(t.TempDir(), "launcher")
	epoch := time.Unix(1, 0)
	if err := copyVerifiedNativeResource(root, target, resource, epoch); err != nil {
		t.Fatalf("case-insensitive verified copy error=%v", err)
	}
	content, err := os.ReadFile(target) // #nosec G304 -- target is beneath this test's private temporary directory.
	info, statErr := os.Lstat(target)
	if err != nil || statErr != nil || string(content) != "x" || !info.ModTime().Equal(epoch) {
		t.Fatalf("copied resource=%q info=%+v errors=(%v,%v)", content, info, err, statErr)
	}
}

func TestPF001NativeStageReportsEveryInjectedFilesystemFailure(t *testing.T) {
	operations := []struct {
		name, prefix string
	}{
		{"mkdir-temp", "create private package root: "},
		{"copy-verification-bundle", "retain private release bundle: "},
		{"mkdir-payload", "create package payload: "},
		{"mkdir-bundle-parent", "create installed bundle parent: "},
		{"copy-installed-bundle", "stage installed release bundle: "},
		{"mkdir-native-directory", "create native package directory: "},
		{"copy-native-resource", "stage verified native resource: "},
		{"remove-verification", "remove private verification authority: "},
		{"normalize", "normalize native package directories: "},
		{"rename", "publish native package stage: "},
	}
	for _, test := range operations {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageStageFixture(t, "darwin", "arm64")
			fault := errors.New("injected " + test.name)
			ops := &faultingStageOperations{fail: test.name, err: fault}
			err := stageWithOperations(
				t.Context(), fixture.options, &packageStageRunner{}, func(string) error { return nil },
				func(
					_ context.Context,
					root string,
					_ string,
					operatingSystem string,
					architecture string,
					_ time.Time,
				) (verifiedNativePackage, error) {
					return verifiedPackageFromFixture(t, root, operatingSystem, architecture), nil
				},
				ops,
			)
			if err == nil || !errors.Is(err, fault) || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("stageWithOperations() error=%v", err)
			}
			if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed stage was published: %v", statErr)
			}
			temporary, globErr := filepath.Glob(filepath.Join(filepath.Dir(fixture.output), ".agentmemory-native-package-*"))
			if globErr != nil || len(temporary) != 0 {
				t.Fatalf("private native stages survived failure: paths=%v error=%v", temporary, globErr)
			}
		})
	}
}

func TestPF001NativeStageResolverCoversFilesystemContracts(t *testing.T) {
	t.Parallel()
	fixture := newPackageStageFixture(t, "darwin", "arm64")
	missingRoot := fixture.options
	missingRoot.RepositoryRoot += ".missing"
	if _, err := resolveStageOptions(missingRoot); err == nil || errors.Unwrap(err) == nil ||
		!strings.HasPrefix(err.Error(), "resolve repository root links: ") {
		t.Fatalf("missing root error=%v", err)
	}
	fileRoot := fixture.options
	fileRoot.RepositoryRoot = fixture.options.TrustDocument
	if _, err := resolveStageOptions(fileRoot); err == nil || err.Error() != "repository root is not a directory" {
		t.Fatalf("file root error=%v", err)
	}
	blockedOutput := fixture.options
	parentFile := filepath.Join(filepath.Dir(fixture.output), "output-parent-file")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedOutput.Output = filepath.Join(parentFile, "stage")
	_, blockedErr := resolveStageOptions(blockedOutput)
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
	resolved, err := resolveStageOptions(relative)
	if err != nil || !filepath.IsAbs(resolved.BundleRoot) || !filepath.IsAbs(resolved.TrustDocument) ||
		!filepath.IsAbs(resolved.Output) {
		t.Fatalf("relative stage options=%+v,%v", resolved, err)
	}
	defaultRoot := fixture.options
	defaultRoot.RepositoryRoot = ""
	resolved, err = resolveStageOptions(defaultRoot)
	if err != nil || resolved.RepositoryRoot == "" || !filepath.IsAbs(resolved.RepositoryRoot) {
		t.Fatalf("default repository options=%+v,%v", resolved, err)
	}
}

func TestPF001NativeStageResolverRevisionAndLayoutPoliciesAreExact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		configure func(*StageOptions)
		want      string
	}{
		{name: "empty operating system", configure: func(options *StageOptions) { options.OperatingSystem = "" }, want: "operating system must be darwin or windows"},
		{name: "unknown operating system", configure: func(options *StageOptions) { options.OperatingSystem = "linux" }, want: "operating system must be darwin or windows"},
		{name: "empty architecture", configure: func(options *StageOptions) { options.Architecture = "" }, want: "architecture must be amd64 or arm64"},
		{name: "unknown architecture", configure: func(options *StageOptions) { options.Architecture = "386" }, want: "architecture must be amd64 or arm64"},
		{name: "zero source epoch", configure: func(options *StageOptions) { options.SourceEpoch = 0 }, want: "source and verification epochs must be positive"},
		{name: "negative source epoch", configure: func(options *StageOptions) { options.SourceEpoch = -1 }, want: "source and verification epochs must be positive"},
		{name: "zero verification epoch", configure: func(options *StageOptions) { options.VerificationEpoch = 0 }, want: "source and verification epochs must be positive"},
		{name: "negative verification epoch", configure: func(options *StageOptions) { options.VerificationEpoch = -1 }, want: "source and verification epochs must be positive"},
		{name: "missing bundle", configure: func(options *StageOptions) { options.BundleRoot = "" }, want: "bundle root is required"},
		{name: "missing trust", configure: func(options *StageOptions) { options.TrustDocument = "" }, want: "trust document is required"},
		{name: "missing output", configure: func(options *StageOptions) { options.Output = "" }, want: "output is required"},
		{name: "missing output parent", configure: func(options *StageOptions) {
			options.Output = filepath.Join(filepath.Dir(options.Output), "missing", "stage")
		}, want: "output parent must be an existing non-symlink directory"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newPackageStageFixture(t, "darwin", "arm64")
			test.configure(&fixture.options)
			if _, err := resolveStageOptions(fixture.options); err == nil || err.Error() != test.want {
				t.Fatalf("resolveStageOptions() error=%v want=%q", err, test.want)
			}
		})
	}

	fixture := newPackageStageFixture(t, "darwin", "arm64")
	for _, target := range []struct{ operatingSystem, architecture string }{
		{operatingSystem: "darwin", architecture: "amd64"},
		{operatingSystem: "darwin", architecture: "arm64"},
		{operatingSystem: "windows", architecture: "amd64"},
		{operatingSystem: "windows", architecture: "arm64"},
	} {
		options := fixture.options
		options.OperatingSystem, options.Architecture = target.operatingSystem, target.architecture
		options.SourceEpoch, options.VerificationEpoch = 1, 1
		resolved, err := resolveStageOptions(options)
		if err != nil || resolved.OperatingSystem != target.operatingSystem || resolved.Architecture != target.architecture ||
			resolved.SourceEpoch != 1 || resolved.VerificationEpoch != 1 {
			t.Fatalf("target=%+v resolved=%+v error=%v", target, resolved, err)
		}
	}
	for _, test := range []struct {
		operatingSystem string
		want            packageLayout
	}{
		{operatingSystem: "darwin", want: packageLayout{
			launcher: "usr/local/bin/agentmemory",
			helper:   "Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
			bundle:   "Library/Application Support/AgentMemory/resources/bundle",
		}},
		{operatingSystem: "windows", want: packageLayout{
			launcher: "agentmemory.exe", helper: "bin/agentmemory-runtime-helper.exe", bundle: "resources/bundle",
		}},
	} {
		layout, err := desktopPackageLayout(test.operatingSystem)
		if err != nil || !reflect.DeepEqual(layout, test.want) {
			t.Fatalf("desktopPackageLayout(%q)=%+v,%v want=%+v", test.operatingSystem, layout, err, test.want)
		}
	}
	existing := newPackageStageFixture(t, "darwin", "arm64")
	if err := os.WriteFile(existing.output, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveStageOptions(existing.options); err == nil || err.Error() != "output already exists" {
		t.Fatalf("existing output error=%v", err)
	}
	symlinkedParent := newPackageStageFixture(t, "darwin", "arm64")
	link := filepath.Join(filepath.Dir(symlinkedParent.output), "output-link")
	if err := os.Symlink(t.TempDir(), link); err == nil {
		symlinkedParent.options.Output = filepath.Join(link, "stage")
		if _, err := resolveStageOptions(symlinkedParent.options); err == nil || err.Error() != "output parent must be an existing non-symlink directory" {
			t.Fatalf("symlink output parent error=%v", err)
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		runner *packageStageRunner
		want   string
	}{
		{name: "clean", runner: &packageStageRunner{}},
		{name: "command failure", runner: &packageStageRunner{failure: errors.New("git failed")}, want: "verify clean source revision failed"},
		{name: "dirty", runner: &packageStageRunner{dirty: true}, want: "source revision is dirty"},
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

func TestPF001NativePackageStagePublishesExactVerifiedDesktopLayouts(t *testing.T) {
	t.Parallel()
	for _, target := range []struct {
		operatingSystem string
		architecture    string
		launcher        string
		helper          string
		bundle          string
	}{
		{
			operatingSystem: "darwin", architecture: "arm64",
			launcher: "payload/usr/local/bin/agentmemory",
			helper:   "payload/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
			bundle:   "payload/Library/Application Support/AgentMemory/resources/bundle",
		},
		{
			operatingSystem: "windows", architecture: "amd64",
			launcher: "payload/agentmemory.exe",
			helper:   "payload/bin/agentmemory-runtime-helper.exe",
			bundle:   "payload/resources/bundle",
		},
	} {
		t.Run(target.operatingSystem, func(t *testing.T) {
			t.Parallel()
			fixture := newPackageStageFixture(t, target.operatingSystem, target.architecture)
			runner := &packageStageRunner{}
			var observed packageResolutionCall
			validatedTrust := ""
			err := Stage(context.Background(), fixture.options, runner, func(value string) error {
				validatedTrust = value
				return nil
			},
				func(ctx context.Context, root string, trust string, operatingSystem string, architecture string, verifiedAt time.Time) (verifiedNativePackage, error) {
					if ctx == nil || trust != validatedTrust {
						return verifiedNativePackage{}, errors.New("invalid resolution authority")
					}
					observed = packageResolutionCall{root: root, operatingSystem: operatingSystem, architecture: architecture, verifiedAt: verifiedAt}
					for _, relative := range []string{
						"bootstrap/distribution-manifest.json", fixture.launcherBundlePath,
					} {
						info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
						if statErr != nil || !info.Mode().IsRegular() ||
							(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
							t.Fatalf("verification input %s info=%+v error=%v", relative, info, statErr)
						}
					}
					return verifiedPackageFromFixture(t, root, operatingSystem, architecture), nil
				})
			if err != nil {
				t.Fatalf("Stage() error=%v", err)
			}
			if decoded, decodeErr := base64.StdEncoding.DecodeString(validatedTrust); decodeErr != nil || string(decoded) != `{"schema_version":1}` {
				t.Fatalf("validated trust=%q decode error=%v", validatedTrust, decodeErr)
			}
			if len(runner.commands) != 1 || runner.commands[0].Name != "git" ||
				!reflect.DeepEqual(runner.commands[0].Args, []string{"status", "--porcelain=v1", "--untracked-files=all"}) ||
				observed.operatingSystem != target.operatingSystem || observed.architecture != target.architecture ||
				observed.verifiedAt.Unix() != fixture.options.VerificationEpoch || observed.verifiedAt.Nanosecond() != 0 ||
				observed.root == fixture.bundle {
				t.Fatalf("commands=%+v resolution=%+v", runner.commands, observed)
			}
			for relative, want := range map[string]string{
				target.launcher: "signed launcher bytes",
				target.helper:   "signed helper bytes",
				filepath.ToSlash(filepath.Join(target.bundle, "models/model.bin")): "model bytes",
			} {
				content, readErr := os.ReadFile(filepath.Join(fixture.output, filepath.FromSlash(relative))) // #nosec G304 -- closed test-owned paths.
				if readErr != nil || string(content) != want {
					t.Fatalf("%s content=%q error=%v", relative, content, readErr)
				}
			}
			if _, statErr := os.Lstat(filepath.Join(fixture.output, ".verification-bundle")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("private verification authority leaked: %v", statErr)
			}
			assertExactPackageStageTree(t, fixture, target.launcher, target.helper, target.bundle)
		})
	}
}

func TestPF001NativePackageStageRejectsUnsafeInputsAndProjection(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*packageStageFixture, *packageStageRunner, *verifiedNativePackage){
		"target": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.OperatingSystem = "linux"
		},
		"architecture": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.Architecture = "386"
		},
		"epoch": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.SourceEpoch = 0
		},
		"negative epoch": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.SourceEpoch = -1
		},
		"verification epoch": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.VerificationEpoch = 0
		},
		"negative verification epoch": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.VerificationEpoch = -1
		},
		"dirty": func(_ *packageStageFixture, runner *packageStageRunner, _ *verifiedNativePackage) {
			runner.dirty = true
		},
		"git": func(_ *packageStageFixture, runner *packageStageRunner, _ *verifiedNativePackage) {
			runner.failure = errors.New("git failed")
		},
		"existing output": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			if err := os.Mkdir(fixture.output, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"missing output parent": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.Output = filepath.Join(filepath.Dir(fixture.output), "missing", "stage")
		},
		"repository file": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.RepositoryRoot = fixture.options.TrustDocument
		},
		"empty trust": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			if err := os.WriteFile(fixture.options.TrustDocument, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"linked trust": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			link := filepath.Join(filepath.Dir(fixture.options.TrustDocument), "trust-link.json")
			if err := os.Symlink(fixture.options.TrustDocument, link); err != nil {
				fixture.options.TrustDocument = filepath.Join(filepath.Dir(link), "missing-trust.json")
				return
			}
			fixture.options.TrustDocument = link
		},
		"missing manifest": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			if err := os.Remove(filepath.Join(fixture.bundle, "bootstrap/distribution-manifest.json")); err != nil {
				t.Fatal(err)
			}
		},
		"linked bundle entry": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			if err := os.Symlink("model.bin", filepath.Join(fixture.bundle, "models/model-link.bin")); err != nil {
				if removeErr := os.Remove(filepath.Join(fixture.bundle, "bootstrap/distribution-manifest.json")); removeErr != nil {
					t.Fatal(removeErr)
				}
			}
		},
		"projection target": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.operatingSystem = "windows"
		},
		"projection architecture": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.architecture = "amd64"
		},
		"empty resource id": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.resourceID = ""
		},
		"empty resource path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = ""
		},
		"zero resource size": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.size = 0
		},
		"short resource digest": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 63)
		},
		"long resource digest": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.sha256 = strings.Repeat("0", 65)
		},
		"projection path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = "../launcher"
		},
		"absolute path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = filepath.Join(string(filepath.Separator), "launcher")
		},
		"dot path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = "."
		},
		"backslash path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = `native\launcher`
		},
		"nul path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = "native/\x00launcher"
		},
		"noncanonical path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = "native/darwin/../arm64/agentmemory"
		},
		"projection digest": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.sha256 = strings.Repeat("0", 64)
		},
		"malformed digest": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.sha256 = strings.Repeat("g", 64)
		},
		"projection size": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.size++
		},
		"same resource id": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.resourceID = value.launcher.resourceID
		},
		"same resource path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.bundlePath = value.launcher.bundlePath
		},
		"same resource digest": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.helper.sha256 = value.launcher.sha256
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newPackageStageFixture(t, "darwin", "arm64")
			runner := &packageStageRunner{}
			projection := verifiedPackageFromFixture(t, fixture.bundle, "darwin", "arm64")
			mutate(fixture, runner, &projection)
			resolver := func(context.Context, string, string, string, string, time.Time) (verifiedNativePackage, error) {
				return projection, nil
			}
			if err := Stage(context.Background(), fixture.options, runner, func(string) error { return nil }, resolver); err == nil {
				t.Fatal("Stage() error=nil")
			}
			if _, err := os.Lstat(fixture.output); !errors.Is(err, os.ErrNotExist) && name != "existing output" {
				t.Fatalf("partial output exists: %v", err)
			}
		})
	}
}

func TestPF001NativePackageStageRejectsCapabilitiesTrustAndResolverFailure(t *testing.T) {
	t.Parallel()
	fixture := newPackageStageFixture(t, "windows", "amd64")
	runner := &packageStageRunner{}
	resolver := func(context.Context, string, string, string, string, time.Time) (verifiedNativePackage, error) {
		return verifiedNativePackage{}, errors.New("failed")
	}
	if err := Stage(context.Background(), fixture.options, nil, func(string) error { return nil }, resolver); err == nil {
		t.Fatal("nil runner accepted")
	}
	if err := Stage(context.Background(), fixture.options, runner, nil, resolver); err == nil {
		t.Fatal("nil trust accepted")
	}
	if err := Stage(context.Background(), fixture.options, runner, func(string) error { return nil }, nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
	if err := stageWithOperations(
		context.Background(), fixture.options, runner, func(string) error { return nil }, resolver, nil,
	); err == nil || err.Error() != "native package staging capabilities are incomplete" {
		t.Fatalf("nil operations error=%v", err)
	}
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := Stage(nil, fixture.options, runner, func(string) error { return nil }, resolver); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil context accepted")
	}
	if err := Stage(context.Background(), fixture.options, runner, func(string) error { return errors.New("bad") }, resolver); err == nil {
		t.Fatal("rejected trust accepted")
	}
	if err := Stage(context.Background(), fixture.options, runner, func(string) error { return nil }, resolver); err == nil {
		t.Fatal("resolver failure accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Stage(cancelled, fixture.options, runner, func(string) error { return nil }, resolver); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Stage error=%v", err)
	}
}

func TestPF001NativePackageStageCommandAndRunnerAreClosed(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-os", "linux"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Native package staging failed") {
		t.Fatalf("run(invalid)=%d stderr=%q", code, stderr.String())
	}
	fixture := newPackageStageFixture(t, "darwin", "arm64")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), packageStageArguments(fixture.options), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Native package staging failed") {
		t.Fatalf("run(complete flags)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	process := processRunner{}
	if output, err := process.Run(context.Background(), Command{
		Name: "git", Args: []string{"--version"}, Dir: t.TempDir(),
	}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("git output=%q error=%v", output, err)
	}
	if _, err := process.Run(context.Background(), Command{Name: "sh", Dir: t.TempDir()}); err == nil {
		t.Fatal("disallowed package-stage process accepted")
	}
	//lint:ignore SA1012 The process boundary must reject an adversarial nil context.
	if _, err := process.Run(nil, Command{Name: "git", Dir: t.TempDir()}); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil package-stage process context accepted")
	}
	if _, err := process.Run(context.Background(), Command{Name: "git"}); err == nil {
		t.Fatal("empty package-stage process directory accepted")
	}
	if _, err := process.Run(context.Background(), Command{
		Name: "git", Args: []string{"status", "--porcelain=v1"}, Dir: t.TempDir(),
	}); err == nil {
		t.Fatal("package-stage process ignored its explicit non-repository directory")
	}
	//lint:ignore SA1012 Deliberate absent-context composition-boundary test.
	_, projectionErr := resolveProductionNativePackage(nil, "", "", "darwin", "arm64", time.Time{}) //nolint:staticcheck
	if projectionErr == nil {
		t.Fatal("invalid production package projection accepted")
	}
}

func TestPF001NativePackageStageCLICompositionIsExact(t *testing.T) {
	fixture := newPackageStageFixture(t, "darwin", "arm64")
	arguments := packageStageArguments(fixture.options)
	ctx := context.WithValue(t.Context(), packageStageContextKey{}, "closed-context")
	var capturedContext context.Context
	var capturedOptions StageOptions
	var stdout, stderr bytes.Buffer
	code := runWithStage(ctx, arguments, &stdout, &stderr, func(gotContext context.Context, options StageOptions) error {
		capturedContext, capturedOptions = gotContext, options
		return nil
	})
	if code != 0 || capturedContext != ctx || !reflect.DeepEqual(capturedOptions, fixture.options) ||
		stdout.String() != fixture.output+"\n" || stderr.Len() != 0 {
		t.Fatalf("runWithStage()=%d context=%v options=%+v stdout=%q stderr=%q", code, capturedContext, capturedOptions, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	fault := errors.New("injected stage command")
	code = runWithStage(ctx, arguments, &stdout, &stderr, func(context.Context, StageOptions) error { return fault })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "Native package staging failed: injected stage command\n" {
		t.Fatalf("failed runWithStage()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	writer := &packageStageCountingErrorWriter{}
	if code := runWithStage(ctx, arguments, writer, &stderr, func(context.Context, StageOptions) error { return nil }); code != 1 || writer.calls != 1 {
		t.Fatalf("stdout failure code=%d calls=%d", code, writer.calls)
	}
	writer = &packageStageCountingErrorWriter{}
	if code := runWithStage(ctx, arguments, &stdout, writer, func(context.Context, StageOptions) error { return fault }); code != 1 || writer.calls != 1 {
		t.Fatalf("stderr failure code=%d calls=%d", code, writer.calls)
	}
	stderr.Reset()
	if code := runWithStage(ctx, arguments, &stdout, &stderr, nil); code != 1 ||
		stderr.String() != "Native package staging failed: stage command is unavailable\n" {
		t.Fatalf("nil stage code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := runWithStage(ctx, []string{"-unknown"}, &stdout, &stderr, func(context.Context, StageOptions) error { return nil }); code != 2 ||
		!strings.Contains(stderr.String(), "flag provided but not defined: -unknown") {
		t.Fatalf("parse failure code=%d stderr=%q", code, stderr.String())
	}
	launcherResource := newVerifiedNativeResource("launcher-id", "native/launcher", strings.Repeat("a", 64), 11)
	helperResource := newVerifiedNativeResource("helper-id", "native/helper", strings.Repeat("b", 64), 12)
	projected := newVerifiedNativePackage("darwin", "arm64", launcherResource, helperResource)
	if !reflect.DeepEqual(projected, verifiedNativePackage{
		operatingSystem: "darwin", architecture: "arm64",
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

func TestPF001NativePackageStageHelpersFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newPackageStageFixture(t, "windows", "amd64")
	if _, err := desktopPackageLayout("linux"); err == nil {
		t.Fatal("unsupported desktop layout accepted")
	}
	for name, mutate := range map[string]func(*StageOptions){
		"bundle": func(options *StageOptions) { options.BundleRoot = "" },
		"trust":  func(options *StageOptions) { options.TrustDocument = "" },
		"output": func(options *StageOptions) { options.Output = "" },
	} {
		t.Run(name, func(t *testing.T) {
			options := fixture.options
			mutate(&options)
			if _, err := resolveStageOptions(options); err == nil {
				t.Fatal("incomplete stage options accepted")
			}
		})
	}
	if _, err := readBoundedRegularFile(fixture.options.TrustDocument, 1); err == nil {
		t.Fatal("oversized bounded input accepted")
	}
	if raw, err := readBoundedRegularFile(fixture.options.TrustDocument, int64(len(`{"schema_version":1}`))); err != nil || string(raw) != `{"schema_version":1}` {
		t.Fatalf("bounded trust=%q error=%v", raw, err)
	}
	if err := copyBundleTree(
		fixture.options.TrustDocument, filepath.Join(t.TempDir(), "copy"),
		0o700, 0o600, time.Unix(1, 0),
	); err == nil {
		t.Fatal("regular file accepted as a bundle root")
	}
	missing := verifiedNativeResource{
		resourceID: "missing", bundlePath: "native/windows/amd64/missing.exe",
		sha256: strings.Repeat("0", 64), size: 1,
	}
	if err := copyVerifiedNativeResource(
		fixture.bundle, filepath.Join(t.TempDir(), "missing.exe"), missing, time.Unix(1, 0),
	); err == nil {
		t.Fatal("missing verified native resource accepted")
	}
	unsafeStage := t.TempDir()
	target := filepath.Join(unsafeStage, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(unsafeStage, "link")); err == nil {
		if err := normalizePackageDirectories(unsafeStage, time.Unix(1, 0)); err == nil {
			t.Fatal("linked package stage normalized")
		}
	}
}

type packageResolutionCall struct {
	root            string
	operatingSystem string
	architecture    string
	verifiedAt      time.Time
}

type packageStageFixture struct {
	bundle             string
	output             string
	launcherBundlePath string
	helperBundlePath   string
	options            StageOptions
}

type packageStageContextKey struct{}

type packageStageCountingErrorWriter struct{ calls int }

func (writer *packageStageCountingErrorWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("injected writer failure")
}

func newPackageStageFixture(t testing.TB, operatingSystem string, architecture string) *packageStageFixture {
	t.Helper()
	parent := t.TempDir()
	repository := filepath.Join(parent, "repository")
	bundle := filepath.Join(parent, "bundle")
	launcherName := "agentmemory"
	helperName := "agentmemory-runtime-helper"
	if operatingSystem == "windows" {
		launcherName += ".exe"
		helperName += ".exe"
	}
	launcherPath := filepath.ToSlash(filepath.Join("native", operatingSystem, architecture, launcherName))
	helperPath := filepath.ToSlash(filepath.Join("native", operatingSystem, architecture, helperName))
	for _, directory := range []string{
		repository, filepath.Join(bundle, "bootstrap"), filepath.Join(bundle, "models"),
		filepath.Dir(filepath.Join(bundle, filepath.FromSlash(launcherPath))),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(parent, "trust.json"):                           `{"schema_version":1}`,
		filepath.Join(bundle, "bootstrap/distribution-manifest.json"): `{"signed":true}`,
		filepath.Join(bundle, "models/model.bin"):                     "model bytes",
		filepath.Join(bundle, filepath.FromSlash(launcherPath)):       "signed launcher bytes",
		filepath.Join(bundle, filepath.FromSlash(helperPath)):         "signed helper bytes",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &packageStageFixture{
		bundle: bundle, output: filepath.Join(parent, "stage"),
		launcherBundlePath: launcherPath, helperBundlePath: helperPath,
		options: StageOptions{
			RepositoryRoot: repository, BundleRoot: bundle, TrustDocument: filepath.Join(parent, "trust.json"),
			Output: filepath.Join(parent, "stage"), OperatingSystem: operatingSystem, Architecture: architecture,
			SourceEpoch: 1_784_073_600, VerificationEpoch: 1_784_116_800,
		},
	}
}

func verifiedPackageFromFixture(
	t testing.TB,
	root string,
	operatingSystem string,
	architecture string,
) verifiedNativePackage {
	t.Helper()
	name := "agentmemory"
	helper := "agentmemory-runtime-helper"
	if operatingSystem == "windows" {
		name += ".exe"
		helper += ".exe"
	}
	resource := func(id string, relative string) verifiedNativeResource {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative))) // #nosec G304 -- closed fixture path.
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		return verifiedNativeResource{
			resourceID: id, bundlePath: relative, sha256: hex.EncodeToString(digest[:]), size: uint64(len(content)),
		}
	}
	launcherPath := filepath.ToSlash(filepath.Join("native", operatingSystem, architecture, name))
	helperPath := filepath.ToSlash(filepath.Join("native", operatingSystem, architecture, helper))
	return verifiedNativePackage{
		operatingSystem: operatingSystem, architecture: architecture,
		launcher: resource("launcher-"+operatingSystem+"-"+architecture, launcherPath),
		helper:   resource("helper-"+operatingSystem+"-"+architecture, helperPath),
	}
}

type packageStageRunner struct {
	commands []Command
	dirty    bool
	failure  error
}

type faultingStageOperations struct {
	system                            systemStageOperations
	fail                              string
	err                               error
	copyTreeCalls, mkdirAllCalls      int
	copyResourceCalls, removeAllCalls int
}

func (o *faultingStageOperations) MkdirTemp(parent string, pattern string) (string, error) {
	if o.fail == "mkdir-temp" {
		return "", o.err
	}
	return o.system.MkdirTemp(parent, pattern)
}

func (o *faultingStageOperations) CopyBundleTree(
	source string,
	target string,
	directoryMode os.FileMode,
	fileMode os.FileMode,
	epoch time.Time,
) error {
	o.copyTreeCalls++
	if o.fail == "copy-verification-bundle" && o.copyTreeCalls == 1 ||
		o.fail == "copy-installed-bundle" && o.copyTreeCalls == 2 {
		return o.err
	}
	return o.system.CopyBundleTree(source, target, directoryMode, fileMode, epoch)
}

func (o *faultingStageOperations) Mkdir(path string, mode os.FileMode) error {
	if o.fail == "mkdir-payload" {
		return o.err
	}
	return o.system.Mkdir(path, mode)
}

func (o *faultingStageOperations) MkdirAll(path string, mode os.FileMode) error {
	o.mkdirAllCalls++
	if o.fail == "mkdir-bundle-parent" && o.mkdirAllCalls == 1 ||
		o.fail == "mkdir-native-directory" && o.mkdirAllCalls == 2 {
		return o.err
	}
	return o.system.MkdirAll(path, mode)
}

func (o *faultingStageOperations) CopyVerifiedNativeResource(
	root string,
	target string,
	resource verifiedNativeResource,
	epoch time.Time,
) error {
	o.copyResourceCalls++
	if o.fail == "copy-native-resource" && o.copyResourceCalls == 1 {
		return o.err
	}
	return o.system.CopyVerifiedNativeResource(root, target, resource, epoch)
}

func (o *faultingStageOperations) RemoveAll(path string) error {
	o.removeAllCalls++
	if o.fail == "remove-verification" && o.removeAllCalls == 1 {
		return o.err
	}
	return o.system.RemoveAll(path)
}

func (o *faultingStageOperations) NormalizePackageDirectories(root string, epoch time.Time) error {
	if o.fail == "normalize" {
		return o.err
	}
	return o.system.NormalizePackageDirectories(root, epoch)
}

func (o *faultingStageOperations) Rename(oldPath string, newPath string) error {
	if o.fail == "rename" {
		return o.err
	}
	return o.system.Rename(oldPath, newPath)
}

func (r *packageStageRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil command context")
	}
	r.commands = append(r.commands, command)
	if command.Name != "git" {
		return nil, errors.New("unexpected command")
	}
	if r.failure != nil {
		return nil, r.failure
	}
	if r.dirty {
		return []byte(" M source.go\n"), nil
	}
	return nil, nil
}

func packageStageArguments(options StageOptions) []string {
	return []string{
		"-root", options.RepositoryRoot,
		"-bundle", options.BundleRoot,
		"-trust", options.TrustDocument,
		"-output", options.Output,
		"-os", options.OperatingSystem,
		"-arch", options.Architecture,
		"-source-date-epoch", fmt.Sprintf("%d", options.SourceEpoch),
		"-verification-epoch", fmt.Sprintf("%d", options.VerificationEpoch),
	}
}

func assertExactPackageStageTree(t testing.TB, fixture *packageStageFixture, launcher, helper, bundle string) {
	t.Helper()
	wantFiles := map[string]string{
		launcher: "signed launcher bytes", helper: "signed helper bytes",
		filepath.ToSlash(filepath.Join(bundle, "bootstrap/distribution-manifest.json")):         `{"signed":true}`,
		filepath.ToSlash(filepath.Join(bundle, "models/model.bin")):                             "model bytes",
		filepath.ToSlash(filepath.Join(bundle, filepath.FromSlash(fixture.launcherBundlePath))): "signed launcher bytes",
		filepath.ToSlash(filepath.Join(bundle, filepath.FromSlash(fixture.helperBundlePath))):   "signed helper bytes",
	}
	var files []string
	if err := filepath.WalkDir(fixture.output, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(fixture.output, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantNames := make([]string, 0, len(wantFiles))
	for name := range wantFiles {
		wantNames = append(wantNames, name)
	}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(files, wantNames) {
		t.Fatalf("package file tree=%v want=%v", files, wantNames)
	}
	for relative, want := range wantFiles {
		raw, err := os.ReadFile(filepath.Join(fixture.output, filepath.FromSlash(relative))) // #nosec G304 -- closed test-owned path set.
		if err != nil || string(raw) != want {
			t.Fatalf("%s content=%q error=%v", relative, raw, err)
		}
	}
}
