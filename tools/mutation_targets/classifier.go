package main

import (
	"fmt"
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type buildOwner struct {
	Name       string
	GOOS       string
	GOARCH     string
	CgoEnabled bool
	Runner     string
}

var supportedBuildOwners = []buildOwner{
	{Name: "linux-amd64-cgo", GOOS: "linux", GOARCH: "amd64", CgoEnabled: true, Runner: "ubuntu-24.04"},
	{Name: "linux-arm64-cgo", GOOS: "linux", GOARCH: "arm64", CgoEnabled: true, Runner: "ubuntu-24.04-arm"},
	{Name: "linux-amd64-nocgo", GOOS: "linux", GOARCH: "amd64", CgoEnabled: false, Runner: "ubuntu-24.04"},
	{Name: "linux-arm64-nocgo", GOOS: "linux", GOARCH: "arm64", CgoEnabled: false, Runner: "ubuntu-24.04-arm"},
	{Name: "darwin-arm64-cgo", GOOS: "darwin", GOARCH: "arm64", CgoEnabled: true, Runner: "macos-15"},
	{Name: "darwin-amd64-cgo", GOOS: "darwin", GOARCH: "amd64", CgoEnabled: true, Runner: "macos-15-intel"},
	{Name: "darwin-arm64-nocgo", GOOS: "darwin", GOARCH: "arm64", CgoEnabled: false, Runner: "macos-15"},
	{Name: "darwin-amd64-nocgo", GOOS: "darwin", GOARCH: "amd64", CgoEnabled: false, Runner: "macos-15-intel"},
	{Name: "windows-amd64-nocgo", GOOS: "windows", GOARCH: "amd64", CgoEnabled: false, Runner: "windows-2025"},
}

type classifiedTargets struct {
	ByOwner map[string][]string
	Unowned []string
}

func classifyTargets(root string) (classifiedTargets, error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return classifiedTargets{}, fmt.Errorf("inspect mutation root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return classifiedTargets{}, fmt.Errorf("mutation root must be a non-symlink directory")
	}

	result := classifiedTargets{ByOwner: make(map[string][]string, len(supportedBuildOwners))}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("mutation source tree contains a symlink: %s", path)
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		normalized, normalizeErr := repositoryRelativePath(path)
		if normalizeErr != nil {
			return normalizeErr
		}
		owner, matchErr := firstMatchingOwner(filepath.Dir(path), entry.Name())
		if matchErr != nil {
			return fmt.Errorf("classify %s: %w", normalized, matchErr)
		}
		if owner == "" {
			result.Unowned = append(result.Unowned, normalized)
			return nil
		}
		result.ByOwner[owner] = append(result.ByOwner[owner], normalized)
		return nil
	})
	if err != nil {
		return classifiedTargets{}, fmt.Errorf("walk mutation root: %w", err)
	}
	for owner := range result.ByOwner {
		sort.Strings(result.ByOwner[owner])
	}
	sort.Strings(result.Unowned)
	return result, nil
}

func firstMatchingOwner(directory, name string) (string, error) {
	for _, owner := range supportedBuildOwners {
		context := build.Default
		context.GOOS = owner.GOOS
		context.GOARCH = owner.GOARCH
		context.CgoEnabled = owner.CgoEnabled
		matches, err := context.MatchFile(directory, name)
		if err != nil {
			return "", err
		}
		if matches {
			return owner.Name, nil
		}
	}
	return "", nil
}

func repositoryRelativePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve source path: %w", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve repository directory: %w", err)
	}
	relative, err := filepath.Rel(workingDirectory, absolute)
	if err != nil {
		return "", fmt.Errorf("make source path relative: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("mutation source escapes the repository: %s", path)
	}
	return filepath.ToSlash(relative), nil
}

func ownerByName(name string) (buildOwner, bool) {
	for _, owner := range supportedBuildOwners {
		if owner.Name == name {
			return owner, true
		}
	}
	return buildOwner{}, false
}

func selectShard(files []string, index, count int) ([]string, error) {
	if count <= 0 || index < 0 || index >= count {
		return nil, fmt.Errorf("invalid mutation shard %d of %d", index, count)
	}
	selected := make([]string, 0, (len(files)+count-1)/count)
	for position, path := range files {
		if position%count == index {
			selected = append(selected, path)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("mutation shard %d of %d is empty", index, count)
	}
	return selected, nil
}
