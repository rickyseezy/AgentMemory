package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type sourceInventory struct {
	Packages map[string]struct{}
	Files    map[string]struct{}
}

func discoverSourceInventory(repositoryRoot string) (sourceInventory, error) {
	launcherRoot := filepath.Join(repositoryRoot, filepath.FromSlash(strings.TrimSuffix(launcherPathPrefix, "/")))
	info, err := os.Stat(launcherRoot)
	if err != nil {
		return sourceInventory{}, fmt.Errorf("inspect launcher source: %w", err)
	}
	if !info.IsDir() {
		return sourceInventory{}, fmt.Errorf("launcher source %q is not a directory", launcherRoot)
	}

	inventory := sourceInventory{
		Packages: make(map[string]struct{}),
		Files:    make(map[string]struct{}),
	}
	err = filepath.WalkDir(launcherRoot, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk launcher source: %w", walkErr)
		}
		if entry.IsDir() {
			if file != launcherRoot && (entry.Name() == "vendor" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("launcher source %q must not be a symbolic link", file)
		}
		matched, err := build.Default.MatchFile(filepath.Dir(file), entry.Name())
		if err != nil {
			return fmt.Errorf("match launcher source %q to the active build: %w", file, err)
		}
		if !matched {
			return nil
		}
		relative, err := filepath.Rel(repositoryRoot, file)
		if err != nil {
			return fmt.Errorf("resolve source path: %w", err)
		}
		relative = filepath.ToSlash(relative)
		executable, err := fileHasStatements(file)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", relative, err)
		}
		if !executable {
			return nil
		}
		inventory.Files[relative] = struct{}{}
		inventory.Packages[filepath.ToSlash(filepath.Dir(relative))] = struct{}{}
		return nil
	})
	if err != nil {
		return sourceInventory{}, err
	}
	return inventory, nil
}

func fileHasStatements(file string) (bool, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, file, nil, 0)
	if err != nil {
		return false, err
	}
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		if found {
			return false
		}
		statement, ok := node.(ast.Stmt)
		if ok && isCoverableStatement(statement) {
			found = true
			return false
		}
		return true
	})
	return found, nil
}

func isCoverableStatement(statement ast.Stmt) bool {
	switch statement.(type) {
	case *ast.BlockStmt, *ast.EmptyStmt:
		return false
	default:
		return true
	}
}

func missingProfileFiles(profile coverageProfile, expected map[string]struct{}) []string {
	coveredFiles := make(map[string]struct{}, len(profile.Blocks))
	for _, block := range profile.Blocks {
		if block.Statements > 0 {
			coveredFiles[block.File] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for file := range expected {
		if _, found := coveredFiles[file]; !found {
			missing = append(missing, file)
		}
	}
	sort.Strings(missing)
	return missing
}
