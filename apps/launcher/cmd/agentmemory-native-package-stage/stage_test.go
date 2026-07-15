package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
			err := Stage(context.Background(), fixture.options, runner, func(string) error { return nil },
				func(_ context.Context, root string, _ string, operatingSystem string, architecture string, verifiedAt time.Time) (verifiedNativePackage, error) {
					observed = packageResolutionCall{root: root, operatingSystem: operatingSystem, architecture: architecture, verifiedAt: verifiedAt}
					for _, relative := range []string{
						"bootstrap/distribution-manifest.json", fixture.launcherBundlePath,
					} {
						info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
						if statErr != nil || info.Mode().Perm() != 0o600 {
							t.Fatalf("verification input %s info=%+v error=%v", relative, info, statErr)
						}
					}
					return verifiedPackageFromFixture(t, root, operatingSystem, architecture), nil
				})
			if err != nil {
				t.Fatalf("Stage() error=%v", err)
			}
			if len(runner.commands) != 1 || runner.commands[0].Name != "git" ||
				observed.operatingSystem != target.operatingSystem || observed.architecture != target.architecture ||
				observed.verifiedAt.Unix() != fixture.options.VerificationEpoch || observed.root == fixture.bundle {
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
		"verification epoch": func(fixture *packageStageFixture, _ *packageStageRunner, _ *verifiedNativePackage) {
			fixture.options.VerificationEpoch = 0
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
		"projection path": func(_ *packageStageFixture, _ *packageStageRunner, value *verifiedNativePackage) {
			value.launcher.bundlePath = "../launcher"
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
	process := processRunner{}
	if output, err := process.Run(context.Background(), Command{
		Name: "git", Args: []string{"--version"}, Dir: t.TempDir(),
	}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("git output=%q error=%v", output, err)
	}
	if _, err := process.Run(context.Background(), Command{Name: "sh", Dir: t.TempDir()}); err == nil {
		t.Fatal("disallowed package-stage process accepted")
	}
	//lint:ignore SA1012 Deliberate absent-context composition-boundary test.
	_, projectionErr := resolveProductionNativePackage(nil, "", "", "darwin", "arm64", time.Time{}) //nolint:staticcheck
	if projectionErr == nil {
		t.Fatal("invalid production package projection accepted")
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

func (r *packageStageRunner) Run(_ context.Context, command Command) ([]byte, error) {
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
