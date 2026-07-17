package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPF001MutationTargetsAssignEverySupportedBuildVariantExactlyOnce(t *testing.T) {
	t.Parallel()
	root := mutationFixture(t)
	targets, err := classifyTargets(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"common.go": "linux-amd64-cgo", "linux_arm64.go": "linux-arm64-cgo",
		"linux_nocgo.go": "linux-amd64-nocgo", "linux_arm64_nocgo.go": "linux-arm64-nocgo",
		"darwin.go": "darwin-arm64-cgo", "darwin_amd64.go": "darwin-amd64-cgo",
		"darwin_nocgo.go": "darwin-arm64-nocgo", "darwin_intel_nocgo.go": "darwin-amd64-nocgo",
		"windows.go": "windows-amd64-nocgo",
	}
	got := make(map[string]string, len(want))
	for owner, paths := range targets.ByOwner {
		for _, path := range paths {
			got[filepath.Base(path)] = owner
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("classified targets=%v want=%v", got, want)
	}
	if len(targets.Unowned) != 1 || filepath.Base(targets.Unowned[0]) != "unsupported.go" {
		t.Fatalf("unowned targets=%v", targets.Unowned)
	}
}

func TestPF001MutationTargetMatrixContainsOnlyNonEmptyCompleteShards(t *testing.T) {
	t.Parallel()
	targets, err := classifyTargets(mutationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	matrix := buildMatrix(targets.ByOwner, 1)
	seen := make(map[string]bool)
	for _, cell := range matrix.Include {
		files, err := selectShard(targets.ByOwner[cell.Owner], cell.ShardIndex, cell.ShardCount)
		if err != nil {
			t.Fatalf("cell %+v: %v", cell, err)
		}
		if len(files) != 1 || seen[files[0]] {
			t.Fatalf("cell %+v files=%v seen=%v", cell, files, seen)
		}
		seen[files[0]] = true
		owner, ok := ownerByName(cell.Owner)
		if !ok || cell.Runner != owner.Runner || cell.CgoEnabled != map[bool]string{true: "1", false: "0"}[owner.CgoEnabled] {
			t.Fatalf("cell authority=%+v owner=%+v", cell, owner)
		}
	}
	wantCount := 0
	for _, paths := range targets.ByOwner {
		wantCount += len(paths)
	}
	if len(seen) != wantCount {
		t.Fatalf("matrix covered=%d want=%d", len(seen), wantCount)
	}
}

func TestPF001MutationTargetSelectionRejectsInvalidAuthorityAndFilesystem(t *testing.T) {
	t.Parallel()
	if _, err := selectShard([]string{"one.go"}, -1, 1); err == nil {
		t.Fatal("negative shard was accepted")
	}
	if _, err := selectShard([]string{"one.go"}, 1, 1); err == nil {
		t.Fatal("out-of-range shard was accepted")
	}
	if _, err := selectShard([]string{"one.go"}, 1, 2); err == nil {
		t.Fatal("empty shard was accepted")
	}
	file := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyTargets(file); err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
		t.Fatalf("file root error=%v", err)
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(filepath.Dir(file), link); err == nil {
		if _, err := classifyTargets(link); err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
			t.Fatalf("link root error=%v", err)
		}
	}
}

func TestPF001MutationTargetOrderingAndLookupAreDeterministic(t *testing.T) {
	t.Parallel()
	files := []string{"a.go", "b.go", "c.go", "d.go", "e.go"}
	first, err := selectShard(files, 0, 2)
	if err != nil || !reflect.DeepEqual(first, []string{"a.go", "c.go", "e.go"}) {
		t.Fatalf("first shard=%v,%v", first, err)
	}
	second, err := selectShard(files, 1, 2)
	if err != nil || !reflect.DeepEqual(second, []string{"b.go", "d.go"}) {
		t.Fatalf("second shard=%v,%v", second, err)
	}
	for _, owner := range supportedBuildOwners {
		got, ok := ownerByName(owner.Name)
		if !ok || got != owner {
			t.Fatalf("owner lookup=%+v,%v want=%+v", got, ok, owner)
		}
	}
	if _, ok := ownerByName("foreign"); ok {
		t.Fatal("foreign owner was accepted")
	}
}

func mutationFixture(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(".", ".mutation-targets-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	files := map[string]string{
		"common.go":             "package fixture\n",
		"linux_arm64.go":        "//go:build linux && arm64\n\npackage fixture\n",
		"linux_nocgo.go":        "//go:build linux && amd64 && !cgo\n\npackage fixture\n",
		"linux_arm64_nocgo.go":  "//go:build linux && arm64 && !cgo\n\npackage fixture\n",
		"darwin.go":             "//go:build darwin\n\npackage fixture\n",
		"darwin_amd64.go":       "//go:build darwin && amd64\n\npackage fixture\n",
		"darwin_nocgo.go":       "//go:build darwin && arm64 && !cgo\n\npackage fixture\n",
		"darwin_intel_nocgo.go": "//go:build darwin && amd64 && !cgo\n\npackage fixture\n",
		"windows.go":            "//go:build windows\n\npackage fixture\n",
		"unsupported.go":        "//go:build freebsd\n\npackage fixture\n",
		"ignored_test.go":       "package fixture\n",
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(root, name), []byte(files[name]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
