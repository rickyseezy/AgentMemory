// Package main verifies the exact security-reviewed release promotion workflow.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	releaseWorkflowPath    = ".github/workflows/pf001-release.yml"
	releaseWorkflowSHA256  = "3ddeb7dc66448315355336cde9ba606b9c9ef53be1842d967e1274a2f22b8345"
	downloadArtifactCommit = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
)

// Options identifies the repository whose release workflow is checked.
type Options struct{ RepositoryRoot string }

// Check rejects any mode, link, special-file, or byte-level drift in the
// reviewed immutable promotion workflow.
func Check(options Options) []error {
	root := options.RepositoryRoot
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return []error{fmt.Errorf("resolve repository root: %w", err)}
	}
	path := filepath.Join(absolute, filepath.FromSlash(releaseWorkflowPath))
	info, err := os.Lstat(path)
	if err != nil {
		return []error{fmt.Errorf("%s: inspect: %w", releaseWorkflowPath, err)}
	}
	if !info.Mode().IsRegular() {
		return []error{fmt.Errorf("%s: must be a regular file, got %s", releaseWorkflowPath, info.Mode())}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		return []error{fmt.Errorf("%s: mode is %04o, want 0644", releaseWorkflowPath, info.Mode().Perm())}
	}
	// #nosec G304 -- path is the one closed reviewed workflow above.
	content, err := os.ReadFile(path)
	if err != nil {
		return []error{fmt.Errorf("%s: read: %w", releaseWorkflowPath, err)}
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != releaseWorkflowSHA256 {
		return []error{fmt.Errorf("%s: content differs from the reviewed contract", releaseWorkflowPath)}
	}
	return nil
}
