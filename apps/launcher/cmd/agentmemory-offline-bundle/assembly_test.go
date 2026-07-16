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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001OfflineBundleStaticAuthorityIsExact(t *testing.T) {
	t.Parallel()
	if maximumOfflineTrustBytes != 128*1024 || maximumOfflineEnvelopeBytes != 32*1024*1024 ||
		distributionEnvelopePath != "bootstrap/distribution-manifest.json" {
		t.Fatal("offline bundle security boundaries changed")
	}
	want := [][2]string{
		{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"},
		{"darwin", "arm64"}, {"windows", "amd64"},
	}
	if len(certifiedReleaseTargets) != len(want) {
		t.Fatalf("certified target count=%d want=%d", len(certifiedReleaseTargets), len(want))
	}
	for index, target := range certifiedReleaseTargets {
		if target.operatingSystem != want[index][0] || target.architecture != want[index][1] {
			t.Fatalf("certified target[%d]=%+v want=%v", index, target, want[index])
		}
	}
}

func TestPF001OfflineBundleReportsEveryInjectedFilesystemFailure(t *testing.T) {
	tests := []struct {
		name, prefix string
	}{
		{"mkdir-temp", "create private bundle root: "},
		{"mkdir-resource", "create bundle resource parent: "},
		{"copy-resource", "copy resource core: "},
		{"reject-uninventoried", ""},
		{"mkdir-envelope", "create distribution envelope parent: "},
		{"write-envelope", "write distribution envelope: "},
		{"normalize", "normalize retained bundle: "},
		{"rename", "publish retained offline bundle: "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOfflineBundleFixture(t)
			fault := errors.New("injected " + test.name)
			operations := &faultingBundleOperations{fail: test.name, err: fault}
			err := assembleWithOperations(
				t.Context(), fixture.options, &bundleRunner{commit: fixture.commit},
				func([]byte) (bundleInventory, error) { return fixture.inventory, nil },
				func(context.Context, string, string, string, string, time.Time) error { return nil },
				operations,
			)
			if err == nil || !errors.Is(err, fault) || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("assembleWithOperations() error=%v", err)
			}
			if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed bundle was published: %v", statErr)
			}
			temporary, globErr := filepath.Glob(filepath.Join(filepath.Dir(fixture.output), ".agentmemory-offline-bundle-*"))
			if globErr != nil || len(temporary) != 0 {
				t.Fatalf("private offline bundles survived failure: paths=%v error=%v", temporary, globErr)
			}
		})
	}
}

func TestPF001OfflineBundleResolverCoversFilesystemContracts(t *testing.T) {
	t.Parallel()
	fixture := newOfflineBundleFixture(t)
	missingRoot := fixture.options
	missingRoot.RepositoryRoot += ".missing"
	if _, err := resolveAssembleOptions(missingRoot); err == nil || errors.Unwrap(err) == nil ||
		!strings.HasPrefix(err.Error(), "resolve repository links: ") {
		t.Fatalf("missing root error=%v", err)
	}
	fileRoot := fixture.options
	fileRoot.RepositoryRoot = fixture.options.TrustDocument
	if _, err := resolveAssembleOptions(fileRoot); err == nil ||
		err.Error() != "repository root must be a non-symlink directory" {
		t.Fatalf("file root error=%v", err)
	}
	blockedOutput := fixture.options
	parentFile := filepath.Join(filepath.Dir(fixture.output), "output-parent-file")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedOutput.Output = filepath.Join(parentFile, "bundle")
	_, blockedErr := resolveAssembleOptions(blockedOutput)
	if blockedErr == nil {
		t.Fatal("output below a regular file was accepted")
	}
	if blockedErr.Error() != "output parent must be an existing non-symlink directory" &&
		(errors.Unwrap(blockedErr) == nil || !strings.HasPrefix(blockedErr.Error(), "inspect output: ")) {
		t.Fatalf("blocked output error=%v", blockedErr)
	}
	stagingFile := fixture.options
	stagingFile.StagingRoot = fixture.options.TrustDocument
	if _, err := resolveAssembleOptions(stagingFile); err == nil ||
		err.Error() != "staging root must be a non-symlink directory" {
		t.Fatalf("staging file error=%v", err)
	}

	for name, clearField := range map[string]func(*AssembleOptions){
		"staging root":    func(value *AssembleOptions) { value.StagingRoot = "" },
		"signed envelope": func(value *AssembleOptions) { value.SignedEnvelope = "" },
		"trust document":  func(value *AssembleOptions) { value.TrustDocument = "" },
		"output":          func(value *AssembleOptions) { value.Output = "" },
	} {
		options := fixture.options
		clearField(&options)
		if _, err := resolveAssembleOptions(options); err == nil || err.Error() != name+" is required" {
			t.Fatalf("%s error=%v", name, err)
		}
	}

	relative := fixture.options
	var err error
	relative.StagingRoot, err = filepath.Rel(relative.RepositoryRoot, relative.StagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	relative.SignedEnvelope, err = filepath.Rel(relative.RepositoryRoot, relative.SignedEnvelope)
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
	resolved, err := resolveAssembleOptions(relative)
	if err != nil || !filepath.IsAbs(resolved.StagingRoot) || !filepath.IsAbs(resolved.SignedEnvelope) ||
		!filepath.IsAbs(resolved.TrustDocument) || !filepath.IsAbs(resolved.Output) {
		t.Fatalf("relative bundle options=%+v,%v", resolved, err)
	}
	defaultRoot := fixture.options
	defaultRoot.RepositoryRoot = ""
	resolved, err = resolveAssembleOptions(defaultRoot)
	if err != nil || resolved.RepositoryRoot == "" || !filepath.IsAbs(resolved.RepositoryRoot) {
		t.Fatalf("default repository options=%+v,%v", resolved, err)
	}
}

func TestPF001OfflineBundleResolverAndRevisionPoliciesAreExact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		configure func(*AssembleOptions)
		want      string
	}{
		{name: "zero source epoch", configure: func(options *AssembleOptions) { options.SourceEpoch = 0 }, want: "source and verification epochs must be positive"},
		{name: "negative source epoch", configure: func(options *AssembleOptions) { options.SourceEpoch = -1 }, want: "source and verification epochs must be positive"},
		{name: "zero verification epoch", configure: func(options *AssembleOptions) { options.VerificationEpoch = 0 }, want: "source and verification epochs must be positive"},
		{name: "negative verification epoch", configure: func(options *AssembleOptions) { options.VerificationEpoch = -1 }, want: "source and verification epochs must be positive"},
		{name: "missing staging", configure: func(options *AssembleOptions) { options.StagingRoot = "" }, want: "staging root is required"},
		{name: "missing envelope", configure: func(options *AssembleOptions) { options.SignedEnvelope = "" }, want: "signed envelope is required"},
		{name: "missing trust", configure: func(options *AssembleOptions) { options.TrustDocument = "" }, want: "trust document is required"},
		{name: "missing output", configure: func(options *AssembleOptions) { options.Output = "" }, want: "output is required"},
		{name: "missing staging path", configure: func(options *AssembleOptions) { options.StagingRoot += ".missing" }, want: "staging root must be a non-symlink directory"},
		{name: "missing output parent", configure: func(options *AssembleOptions) {
			options.Output = filepath.Join(filepath.Dir(options.Output), "missing", "bundle")
		}, want: "output parent must be an existing non-symlink directory"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newOfflineBundleFixture(t)
			test.configure(&fixture.options)
			if _, err := resolveAssembleOptions(fixture.options); err == nil || err.Error() != test.want {
				t.Fatalf("resolveAssembleOptions() error=%v want=%q", err, test.want)
			}
		})
	}

	fixture := newOfflineBundleFixture(t)
	options := fixture.options
	options.SourceEpoch, options.VerificationEpoch = 1, 1
	resolved, err := resolveAssembleOptions(options)
	if err != nil || resolved.SourceEpoch != 1 || resolved.VerificationEpoch != 1 {
		t.Fatalf("minimum options=%+v error=%v", resolved, err)
	}
	existing := newOfflineBundleFixture(t)
	if err := os.WriteFile(existing.output, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAssembleOptions(existing.options); err == nil || err.Error() != "output already exists" {
		t.Fatalf("existing output error=%v", err)
	}
	symlinkedStaging := newOfflineBundleFixture(t)
	stagingLink := filepath.Join(filepath.Dir(symlinkedStaging.output), "staging-link")
	if err := os.Symlink(symlinkedStaging.staging, stagingLink); err != nil {
		t.Fatal(err)
	}
	symlinkedStaging.options.StagingRoot = stagingLink
	if _, err := resolveAssembleOptions(symlinkedStaging.options); err == nil || err.Error() != "staging root must be a non-symlink directory" {
		t.Fatalf("symlink staging error=%v", err)
	}
	symlinkedParent := newOfflineBundleFixture(t)
	parentLink := filepath.Join(filepath.Dir(symlinkedParent.output), "output-link")
	if err := os.Symlink(t.TempDir(), parentLink); err != nil {
		t.Fatal(err)
	}
	symlinkedParent.options.Output = filepath.Join(parentLink, "bundle")
	if _, err := resolveAssembleOptions(symlinkedParent.options); err == nil || err.Error() != "output parent must be an existing non-symlink directory" {
		t.Fatalf("symlink output parent error=%v", err)
	}

	validRunner := &bundleRunner{commit: fixture.commit}
	commit, err := cleanBundleSourceCommit(t.Context(), validRunner, "/closed/repository")
	if err != nil || commit != fixture.commit || len(validRunner.commands) != 2 ||
		!reflect.DeepEqual(validRunner.commands[0], Command{
			Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: "/closed/repository",
		}) || !reflect.DeepEqual(validRunner.commands[1], Command{
		Name: "git", Args: []string{"rev-parse", "HEAD"}, Dir: "/closed/repository",
	}) {
		t.Fatalf("commit=%q commands=%+v error=%v", commit, validRunner.commands, err)
	}
	for _, runner := range []*bundleRunner{
		{commit: fixture.commit, failure: errors.New("git failed")},
		{commit: fixture.commit, dirty: true},
		{commit: strings.Repeat("g", 40)},
		{commit: strings.Repeat("0", 40)},
	} {
		if _, err := cleanBundleSourceCommit(t.Context(), runner, "/closed/repository"); err == nil ||
			err.Error() != "source revision is unavailable or dirty" {
			t.Fatalf("invalid source runner=%+v error=%v", runner, err)
		}
	}
	revisionFailure := bundleCommandRunnerFunc(func(_ context.Context, command Command) ([]byte, error) {
		if len(command.Args) > 0 && command.Args[0] == "status" {
			return nil, nil
		}
		return nil, errors.New("revision failed")
	})
	if _, err := cleanBundleSourceCommit(t.Context(), revisionFailure, "/closed/repository"); err == nil ||
		err.Error() != "source revision is unavailable or dirty" {
		t.Fatalf("revision command failure error=%v", err)
	}
}

func TestPF001OfflineBundlePublishesOnlyExactInventoryAfterEveryTargetVerification(t *testing.T) {
	t.Parallel()
	fixture := newOfflineBundleFixture(t)
	runner := &bundleRunner{commit: fixture.commit}
	var calls []verificationCall
	err := Assemble(context.Background(), fixture.options, runner,
		func(raw []byte) (bundleInventory, error) {
			if !bytes.Equal(raw, fixture.envelope) {
				t.Fatal("decoder did not receive exact envelope bytes")
			}
			return fixture.inventory, nil
		},
		func(ctx context.Context, root string, trust string, operatingSystem string, architecture string, at time.Time) error {
			if ctx == nil {
				return errors.New("nil verification context")
			}
			calls = append(calls, verificationCall{root, trust, operatingSystem, architecture, at})
			for _, resource := range fixture.inventory.resources {
				content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(resource.path))) // #nosec G304 -- test-owned root and closed fixture path.
				if readErr != nil || digestHex(content) != resource.sha256 {
					t.Fatalf("verification resource %s error=%v", resource.path, readErr)
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("Assemble() error=%v", err)
	}
	if len(runner.commands) != 2 || runner.commands[0].Name != "git" || runner.commands[1].Name != "git" ||
		!reflect.DeepEqual(runner.commands[0].Args, []string{"status", "--porcelain=v1", "--untracked-files=all"}) ||
		!reflect.DeepEqual(runner.commands[1].Args, []string{"rev-parse", "HEAD"}) {
		t.Fatalf("commands=%+v", runner.commands)
	}
	wantTargets := []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"}
	if len(calls) != len(wantTargets) {
		t.Fatalf("verification calls=%+v", calls)
	}
	for index, want := range wantTargets {
		if calls[index].operatingSystem+"/"+calls[index].architecture != want ||
			calls[index].at.Unix() != fixture.options.VerificationEpoch ||
			calls[index].at.Nanosecond() != 0 ||
			calls[index].root == fixture.staging || calls[index].trust == "" {
			t.Fatalf("verification[%d]=%+v", index, calls[index])
		}
	}
	if decoded, decodeErr := base64.StdEncoding.DecodeString(calls[0].trust); decodeErr != nil || string(decoded) != `{"trust":"public"}` {
		t.Fatalf("verification trust=%q decode error=%v", calls[0].trust, decodeErr)
	}
	manifest, err := os.ReadFile(filepath.Join(fixture.output, "bootstrap", "distribution-manifest.json"))
	if err != nil || !bytes.Equal(manifest, fixture.envelope) {
		t.Fatalf("published envelope=%q error=%v", manifest, err)
	}
	for _, resource := range fixture.inventory.resources {
		path := filepath.Join(fixture.output, filepath.FromSlash(resource.path))
		content, readErr := os.ReadFile(path) // #nosec G304 -- test-owned output and closed fixture path.
		info, statErr := os.Lstat(path)
		if readErr != nil || statErr != nil || digestHex(content) != resource.sha256 ||
			(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) ||
			!info.ModTime().Equal(time.Unix(fixture.options.SourceEpoch, 0)) {
			t.Fatalf("published %s content=%q info=%+v errors=(%v,%v)", resource.path, content, info, readErr, statErr)
		}
	}
	assertExactOfflineBundleTree(t, fixture)
}

func TestPF001OfflineBundleRejectsUnsafeInputsBeforePublication(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*offlineBundleFixture, *bundleRunner, *bundleInventory){
		"dirty checkout": func(_ *offlineBundleFixture, runner *bundleRunner, _ *bundleInventory) { runner.dirty = true },
		"git failure": func(_ *offlineBundleFixture, runner *bundleRunner, _ *bundleInventory) {
			runner.failure = errors.New("git")
		},
		"source commit": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.sourceCommit = strings.Repeat("b", 40)
		},
		"source epoch": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.SourceEpoch = 0
		},
		"negative source epoch": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.SourceEpoch = -1
		},
		"verification epoch": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.VerificationEpoch = 0
		},
		"negative verification epoch": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.VerificationEpoch = -1
		},
		"missing staging": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.StagingRoot = filepath.Join(fixture.staging, "missing")
		},
		"existing output": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			_ = os.Mkdir(fixture.output, 0o700)
		},
		"output parent": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.Output = filepath.Join(fixture.output, "missing", "bundle")
		},
		"missing resource": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			_ = os.Remove(filepath.Join(fixture.staging, "release", "core.bin"))
		},
		"changed digest": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[0].sha256 = strings.Repeat("0", 64)
		},
		"changed size": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[0].size++
		},
		"unsafe path": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[0].path = "../escape"
		},
		"reserved path": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[0].path = "bootstrap/distribution-manifest.json"
		},
		"duplicate path": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[1].path = inventory.resources[0].path
		},
		"duplicate id": func(_ *offlineBundleFixture, _ *bundleRunner, inventory *bundleInventory) {
			inventory.resources[1].id = inventory.resources[0].id
		},
		"extra file": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			_ = os.WriteFile(filepath.Join(fixture.staging, "extra"), []byte("extra"), 0o600)
		},
		"linked entry": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			link := filepath.Join(fixture.staging, "linked")
			if err := os.Symlink("release/core.bin", link); err != nil {
				_ = os.WriteFile(link, []byte("extra"), 0o600)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newOfflineBundleFixture(t)
			runner := &bundleRunner{commit: fixture.commit}
			inventory := fixture.inventory.clone()
			mutate(fixture, runner, &inventory)
			err := Assemble(context.Background(), fixture.options, runner,
				func([]byte) (bundleInventory, error) { return inventory, nil },
				func(context.Context, string, string, string, string, time.Time) error { return nil })
			if err == nil {
				t.Fatal("Assemble() error=nil")
			}
			if _, statErr := os.Lstat(fixture.output); !errors.Is(statErr, os.ErrNotExist) && name != "existing output" {
				t.Fatalf("partial output exists: %v", statErr)
			}
		})
	}
}

func TestPF001OfflineBundleRejectsDecoderTrustVerificationAndCapabilityFailures(t *testing.T) {
	t.Parallel()
	fixture := newOfflineBundleFixture(t)
	runner := &bundleRunner{commit: fixture.commit}
	decoder := func([]byte) (bundleInventory, error) { return fixture.inventory, nil }
	validator := func(context.Context, string, string, string, string, time.Time) error { return nil }
	if err := Assemble(context.Background(), fixture.options, nil, decoder, validator); err == nil {
		t.Fatal("nil runner accepted")
	}
	if err := Assemble(context.Background(), fixture.options, runner, nil, validator); err == nil {
		t.Fatal("nil decoder accepted")
	}
	if err := Assemble(context.Background(), fixture.options, runner, decoder, nil); err == nil {
		t.Fatal("nil validator accepted")
	}
	if err := assembleWithOperations(
		context.Background(), fixture.options, runner, decoder, validator, nil,
	); err == nil || err.Error() != "offline bundle assembly capabilities are incomplete" {
		t.Fatalf("nil operations error=%v", err)
	}
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := Assemble(nil, fixture.options, runner, decoder, validator); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil context accepted")
	}
	if err := Assemble(context.Background(), fixture.options, runner,
		func([]byte) (bundleInventory, error) { return bundleInventory{}, errors.New("decode") }, validator); err == nil {
		t.Fatal("decoder failure accepted")
	}
	if err := Assemble(context.Background(), fixture.options, runner,
		func([]byte) (bundleInventory, error) { return fixture.inventory, errors.New("decode") }, validator); err == nil {
		t.Fatal("decoder error with an otherwise valid inventory accepted")
	}
	if err := Assemble(context.Background(), fixture.options, runner, decoder,
		func(context.Context, string, string, string, string, time.Time) error { return errors.New("verify") }); err == nil {
		t.Fatal("verification failure accepted")
	}
	if err := os.WriteFile(fixture.options.TrustDocument, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Assemble(context.Background(), fixture.options, runner, decoder, validator); err == nil {
		t.Fatal("empty trust accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Assemble(cancelled, fixture.options, runner, decoder, validator); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func TestPF001OfflineBundleProductionDecoderAndCommandFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := decodeProductionInventory(nil); err == nil {
		t.Fatal("empty production envelope accepted")
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "Offline bundle assembly failed") {
		t.Fatalf("run(invalid)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	fixture := newOfflineBundleFixture(t)
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), offlineBundleArguments(fixture.options), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Offline bundle assembly failed") {
		t.Fatalf("run(complete flags)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	process := processRunner{}
	if output, err := process.Run(context.Background(), Command{Name: "git", Args: []string{"--version"}, Dir: t.TempDir()}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("git output=%q error=%v", output, err)
	}
	if _, err := process.Run(context.Background(), Command{Name: "sh", Dir: t.TempDir()}); err == nil {
		t.Fatal("shell process accepted")
	}
	//lint:ignore SA1012 The process boundary must reject an adversarial nil context.
	if _, err := process.Run(nil, Command{Name: "git", Dir: t.TempDir()}); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil process context accepted")
	}
	if _, err := process.Run(context.Background(), Command{Name: "git"}); err == nil {
		t.Fatal("empty process directory accepted")
	}
	if _, err := process.Run(context.Background(), Command{
		Name: "git", Args: []string{"status", "--porcelain=v1"}, Dir: t.TempDir(),
	}); err == nil {
		t.Fatal("offline process ignored its explicit non-repository directory")
	}
}

func TestPF001OfflineBundleCLICompositionIsExact(t *testing.T) {
	fixture := newOfflineBundleFixture(t)
	arguments := offlineBundleArguments(fixture.options)
	ctx := context.WithValue(t.Context(), offlineBundleContextKey{}, "closed-context")
	var capturedContext context.Context
	var capturedOptions AssembleOptions
	var stdout, stderr bytes.Buffer
	code := runWithAssembly(ctx, arguments, &stdout, &stderr, func(gotContext context.Context, options AssembleOptions) error {
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
	code = runWithAssembly(ctx, arguments, &stdout, &stderr, func(context.Context, AssembleOptions) error { return fault })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "Offline bundle assembly failed: injected assembly command\n" {
		t.Fatalf("failed runWithAssembly()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	writer := &offlineBundleCountingErrorWriter{}
	if code := runWithAssembly(ctx, arguments, writer, &stderr, func(context.Context, AssembleOptions) error { return nil }); code != 1 || writer.calls != 1 {
		t.Fatalf("stdout failure code=%d calls=%d", code, writer.calls)
	}
	writer = &offlineBundleCountingErrorWriter{}
	if code := runWithAssembly(ctx, arguments, &stdout, writer, func(context.Context, AssembleOptions) error { return fault }); code != 1 || writer.calls != 1 {
		t.Fatalf("stderr failure code=%d calls=%d", code, writer.calls)
	}
	stderr.Reset()
	if code := runWithAssembly(ctx, arguments, &stdout, &stderr, nil); code != 1 ||
		stderr.String() != "Offline bundle assembly failed: assembly command is unavailable\n" {
		t.Fatalf("nil assembly code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := runWithAssembly(ctx, []string{"-unknown"}, &stdout, &stderr, func(context.Context, AssembleOptions) error { return nil }); code != 2 ||
		!strings.Contains(stderr.String(), "flag provided but not defined: -unknown") {
		t.Fatalf("parse failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001OfflineBundleValueAndBoundaryContractsAreExact(t *testing.T) {
	t.Parallel()
	fixture := newOfflineBundleFixture(t)
	valid := fixture.inventory.resources[0]
	if !valid.valid() {
		t.Fatal("valid bundle resource rejected")
	}
	minimum := valid
	minimum.id = strings.Repeat("a", 128)
	minimum.size = 1
	if !minimum.valid() {
		t.Fatal("maximum identifier and minimum size boundary rejected")
	}
	for name, mutate := range map[string]func(*bundleResource){
		"empty id":   func(value *bundleResource) { value.id = "" },
		"long id":    func(value *bundleResource) { value.id = strings.Repeat("a", 129) },
		"empty path": func(value *bundleResource) { value.path = "" },
		"zero size":  func(value *bundleResource) { value.size = 0 },
		"even short digest": func(value *bundleResource) {
			value.sha256 = strings.Repeat("0", 62)
		},
		"short digest":   func(value *bundleResource) { value.sha256 = strings.Repeat("0", 63) },
		"invalid digest": func(value *bundleResource) { value.sha256 = strings.Repeat("g", 64) },
		"uppercase digest": func(value *bundleResource) {
			value.sha256 = strings.ToUpper(value.sha256)
		},
		"backslash":    func(value *bundleResource) { value.path = `release\core.bin` },
		"nul":          func(value *bundleResource) { value.path = "release/\x00core.bin" },
		"absolute":     func(value *bundleResource) { value.path = filepath.Join(string(filepath.Separator), "core.bin") },
		"noncanonical": func(value *bundleResource) { value.path = "release/../core.bin" },
		"dot":          func(value *bundleResource) { value.path = "." },
		"traversal":    func(value *bundleResource) { value.path = "../core.bin" },
		"reserved":     func(value *bundleResource) { value.path = distributionEnvelopePath },
	} {
		value := valid
		mutate(&value)
		if value.valid() {
			t.Fatalf("%s invalid resource accepted: %+v", name, value)
		}
	}
	if _, err := validateBundleInventory(bundleInventory{}); err == nil || err.Error() != "signed bundle inventory is incomplete" {
		t.Fatalf("empty inventory error=%v", err)
	}
	if _, err := validateBundleInventory(bundleInventory{
		sourceCommit: fixture.commit,
	}); err == nil || err.Error() != "signed bundle inventory is incomplete" {
		t.Fatalf("empty resources error=%v", err)
	}
	if _, err := validateBundleInventory(bundleInventory{
		sourceCommit: strings.Repeat("0", 40), resources: fixture.inventory.clone().resources,
	}); err == nil || err.Error() != "signed bundle inventory is incomplete" {
		t.Fatalf("invalid commit error=%v", err)
	}
	invalidResource := valid
	invalidResource.size = 0
	if _, err := validateBundleInventory(bundleInventory{
		sourceCommit: fixture.commit, resources: []bundleResource{invalidResource},
	}); err == nil || err.Error() != "signed bundle resource projection is invalid" {
		t.Fatalf("invalid projected resource error=%v", err)
	}
	clone := fixture.inventory.clone()
	clone.resources[0].id = "mutated-clone"
	if fixture.inventory.resources[0].id == clone.resources[0].id {
		t.Fatal("inventory clone aliases the original resource slice")
	}
	duplicateID := fixture.inventory.clone()
	duplicateID.resources[1].id = duplicateID.resources[0].id
	if _, err := validateBundleInventory(duplicateID); err == nil || err.Error() != "signed bundle resource identifier is duplicated" {
		t.Fatalf("duplicate id error=%v", err)
	}
	duplicatePath := fixture.inventory.clone()
	duplicatePath.resources[1].path = duplicatePath.resources[0].path
	if _, err := validateBundleInventory(duplicatePath); err == nil || err.Error() != "signed bundle resource path is aliased" {
		t.Fatalf("duplicate path error=%v", err)
	}
	for _, validCommit := range []string{
		strings.Repeat("a", 40), strings.Repeat("a", 64), "09af" + strings.Repeat("a", 36),
	} {
		if !canonicalSourceCommit(validCommit) {
			t.Fatalf("valid commit rejected: %q", validCommit)
		}
	}
	for _, invalidCommit := range []string{strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 40), strings.Repeat("0", 64)} {
		if canonicalSourceCommit(invalidCommit) {
			t.Fatalf("invalid commit accepted: %q", invalidCommit)
		}
	}
	options := fixture.options
	options.SourceEpoch, options.VerificationEpoch = 1, 1
	resolved, err := resolveAssembleOptions(options)
	if err != nil || resolved.SourceEpoch != 1 || resolved.VerificationEpoch != 1 {
		t.Fatalf("minimum options=%+v error=%v", resolved, err)
	}
	one := filepath.Join(t.TempDir(), "one")
	if err := os.WriteFile(one, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readBoundedRegularFile(one, 1); err != nil || string(raw) != "x" {
		t.Fatalf("one-byte boundary=%q error=%v", raw, err)
	}
	if _, err := readBoundedRegularFile(one, 0); err == nil {
		t.Fatal("one-byte file accepted by zero bound")
	}
}

func TestPF001OfflineBundleSystemNormalizationAdapterPropagatesErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	if err := (systemBundleOperations{}).NormalizeBundleDirectories(missing, time.Unix(1, 0)); err == nil {
		t.Fatal("system normalization adapter suppressed a missing-root error")
	}
}

func TestPF001OfflineBundleProductionProjectionRequiresRetainedResources(t *testing.T) {
	t.Parallel()
	content := []byte(`{"bomFormat":"CycloneDX"}`)
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "core-cyclonedx", Kind: releaseinventory.ResourceKindCycloneDXSBOM,
		Purpose: releaseinventory.ResourcePurposeCycloneDXSBOM, MediaType: releaseinventory.MediaTypeCycloneDX,
		Platform: releaseinventory.Platform{}, Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef: "bundle://evidence/core.cdx.json", SourceAllowlist: []string{"bundle://evidence/core.cdx.json"},
		SubjectResourceID: "core", SubjectDigest: releaseinventory.DigestBytes([]byte("core")),
	})
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	inventory, err := projectProductionInventory(commit, []releaseinventory.Resource{resource})
	if err != nil || inventory.sourceCommit != commit || len(inventory.resources) != 1 ||
		inventory.resources[0].path != "evidence/core.cdx.json" || inventory.resources[0].sha256 != resource.Digest().Hex() {
		t.Fatalf("inventory=%+v error=%v", inventory, err)
	}
	networkInput := releaseinventory.ResourceInput{
		ID: "network-cyclonedx", Kind: releaseinventory.ResourceKindCycloneDXSBOM,
		Purpose: releaseinventory.ResourcePurposeCycloneDXSBOM, MediaType: releaseinventory.MediaTypeCycloneDX,
		Platform: releaseinventory.Platform{}, Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef:         "https://releases.agentmemory.dev/evidence/core.cdx.json",
		SourceAllowlist:   []string{"https://releases.agentmemory.dev/evidence/core.cdx.json"},
		SubjectResourceID: "core", SubjectDigest: releaseinventory.DigestBytes([]byte("core")),
	}
	network, err := releaseinventory.NewResource(networkInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projectProductionInventory(commit, []releaseinventory.Resource{network}); err == nil {
		t.Fatal("network-only release resource accepted for offline assembly")
	}
	for _, invalid := range []string{"", strings.Repeat("0", 40), strings.Repeat("A", 40), "abc"} {
		if canonicalSourceCommit(invalid) {
			t.Fatalf("invalid source commit accepted: %q", invalid)
		}
	}
}

type verificationCall struct {
	root, trust, operatingSystem, architecture string
	at                                         time.Time
}

type offlineBundleFixture struct {
	staging, output, commit string
	envelope                []byte
	inventory               bundleInventory
	options                 AssembleOptions
}

type offlineBundleContextKey struct{}

type offlineBundleCountingErrorWriter struct{ calls int }

func (writer *offlineBundleCountingErrorWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("injected writer failure")
}

func newOfflineBundleFixture(t testing.TB) *offlineBundleFixture {
	t.Helper()
	parent := t.TempDir()
	repository := filepath.Join(parent, "repository")
	staging := filepath.Join(parent, "staging")
	for _, directory := range []string{repository, filepath.Join(staging, "release"), filepath.Join(staging, "evidence")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	resources := []bundleResource{
		newBundleFixtureResource(t, staging, "core", "release/core.bin", []byte("core bytes")),
		newBundleFixtureResource(t, staging, "core-sbom", "evidence/core.cdx.json", []byte(`{"bomFormat":"CycloneDX"}`)),
	}
	envelope := []byte(`{"signed":"release"}`)
	trust := filepath.Join(parent, "trust.json")
	manifest := filepath.Join(parent, "distribution-manifest.json")
	if err := os.WriteFile(trust, []byte(`{"trust":"public"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	return &offlineBundleFixture{
		staging: staging, output: filepath.Join(parent, "bundle"), commit: commit,
		envelope: envelope, inventory: bundleInventory{sourceCommit: commit, resources: resources},
		options: AssembleOptions{
			RepositoryRoot: repository, StagingRoot: staging, SignedEnvelope: manifest,
			TrustDocument: trust, Output: filepath.Join(parent, "bundle"),
			SourceEpoch: 1_784_073_600, VerificationEpoch: 1_784_116_800,
		},
	}
}

func newBundleFixtureResource(t testing.TB, root, id, path string, content []byte) bundleResource {
	t.Helper()
	absolute := filepath.Join(root, filepath.FromSlash(path))
	if err := os.WriteFile(absolute, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundleResource{id: id, path: path, sha256: digestHex(content), size: uint64(len(content))}
}

func digestHex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

type bundleRunner struct {
	commands []Command
	commit   string
	dirty    bool
	failure  error
}

type bundleCommandRunnerFunc func(context.Context, Command) ([]byte, error)

func (function bundleCommandRunnerFunc) Run(ctx context.Context, command Command) ([]byte, error) {
	return function(ctx, command)
}

type faultingBundleOperations struct {
	system systemBundleOperations
	fail   string
	err    error
}

func (o *faultingBundleOperations) MkdirTemp(parent string, pattern string) (string, error) {
	if o.fail == "mkdir-temp" {
		return "", o.err
	}
	return o.system.MkdirTemp(parent, pattern)
}

func (o *faultingBundleOperations) MkdirAll(path string, mode os.FileMode) error {
	if o.fail == "mkdir-resource" ||
		o.fail == "mkdir-envelope" && strings.HasSuffix(filepath.ToSlash(path), "/bootstrap") {
		return o.err
	}
	return o.system.MkdirAll(path, mode)
}

func (o *faultingBundleOperations) CopyExactBundleResource(
	root string,
	target string,
	resource bundleResource,
	epoch time.Time,
) error {
	if o.fail == "copy-resource" {
		return o.err
	}
	return o.system.CopyExactBundleResource(root, target, resource, epoch)
}

func (o *faultingBundleOperations) RejectUninventoriedBundleEntries(
	root string,
	expected map[string]bundleResource,
) error {
	if o.fail == "reject-uninventoried" {
		return o.err
	}
	return o.system.RejectUninventoriedBundleEntries(root, expected)
}

func (o *faultingBundleOperations) WriteExactFile(path string, content []byte, epoch time.Time) error {
	if o.fail == "write-envelope" {
		return o.err
	}
	return o.system.WriteExactFile(path, content, epoch)
}

func (o *faultingBundleOperations) NormalizeBundleDirectories(root string, epoch time.Time) error {
	if o.fail == "normalize" {
		return o.err
	}
	return o.system.NormalizeBundleDirectories(root, epoch)
}

func (o *faultingBundleOperations) Rename(oldPath string, newPath string) error {
	if o.fail == "rename" {
		return o.err
	}
	return o.system.Rename(oldPath, newPath)
}

func (o *faultingBundleOperations) RemoveAll(path string) error {
	return o.system.RemoveAll(path)
}

func (r *bundleRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil command context")
	}
	r.commands = append(r.commands, command)
	if r.failure != nil {
		return nil, r.failure
	}
	if len(command.Args) > 0 && command.Args[0] == "status" {
		if r.dirty {
			return []byte(" M file\n"), nil
		}
		return nil, nil
	}
	return []byte(r.commit + "\n"), nil
}

func offlineBundleArguments(options AssembleOptions) []string {
	return []string{
		"-root", options.RepositoryRoot,
		"-staging", options.StagingRoot,
		"-envelope", options.SignedEnvelope,
		"-trust", options.TrustDocument,
		"-output", options.Output,
		"-source-date-epoch", fmt.Sprintf("%d", options.SourceEpoch),
		"-verification-epoch", fmt.Sprintf("%d", options.VerificationEpoch),
	}
}

func assertExactOfflineBundleTree(t testing.TB, fixture *offlineBundleFixture) {
	t.Helper()
	want := []string{
		distributionEnvelopePath,
		fixture.inventory.resources[0].path,
		fixture.inventory.resources[1].path,
	}
	sort.Strings(want)
	var got []string
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
		got = append(got, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("offline bundle tree=%v want=%v", got, want)
	}
}
