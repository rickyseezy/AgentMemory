package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

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
		func(_ context.Context, root string, trust string, operatingSystem string, architecture string, at time.Time) error {
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
	if len(runner.commands) != 2 || runner.commands[0].Name != "git" || runner.commands[1].Name != "git" {
		t.Fatalf("commands=%+v", runner.commands)
	}
	wantTargets := []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"}
	if len(calls) != len(wantTargets) {
		t.Fatalf("verification calls=%+v", calls)
	}
	for index, want := range wantTargets {
		if calls[index].operatingSystem+"/"+calls[index].architecture != want ||
			calls[index].at.Unix() != fixture.options.VerificationEpoch ||
			calls[index].root == fixture.staging || calls[index].trust == "" {
			t.Fatalf("verification[%d]=%+v", index, calls[index])
		}
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
			info.ModTime().Unix() != fixture.options.SourceEpoch {
			t.Fatalf("published %s content=%q info=%+v errors=(%v,%v)", resource.path, content, info, readErr, statErr)
		}
	}
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
		"verification epoch": func(fixture *offlineBundleFixture, _ *bundleRunner, _ *bundleInventory) {
			fixture.options.VerificationEpoch = 0
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
	if err := Assemble(context.Background(), fixture.options, runner,
		func([]byte) (bundleInventory, error) { return bundleInventory{}, errors.New("decode") }, validator); err == nil {
		t.Fatal("decoder failure accepted")
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
	process := processRunner{}
	if output, err := process.Run(context.Background(), Command{Name: "git", Args: []string{"--version"}, Dir: t.TempDir()}); err != nil || !bytes.Contains(output, []byte("git version")) {
		t.Fatalf("git output=%q error=%v", output, err)
	}
	if _, err := process.Run(context.Background(), Command{Name: "sh", Dir: t.TempDir()}); err == nil {
		t.Fatal("shell process accepted")
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

func (r *bundleRunner) Run(_ context.Context, command Command) ([]byte, error) {
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
