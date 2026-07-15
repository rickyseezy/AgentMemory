// Package main verifies the exact security-reviewed release promotion workflow.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

const (
	releaseWorkflowPath       = ".github/workflows/pf001-release.yml"
	qualificationWorkflowPath = ".github/workflows/pf001-release-qualification.yml"
	downloadArtifactCommit    = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
)

var reviewedWorkflows = map[string]string{
	releaseWorkflowPath:       "b06d66b71191597e96a88895adab096cba7300c9dfec0de21bbbf399ee717d47",
	qualificationWorkflowPath: "72580bbd634f8962bf41ae093b185dc8819cc733f171bb5feffc7d9bb79ef520",
}

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
	violations := make([]error, 0)
	for workflow, expectedDigest := range reviewedWorkflows {
		path := filepath.Join(absolute, filepath.FromSlash(workflow))
		info, statErr := os.Lstat(path)
		if statErr != nil {
			violations = append(violations, fmt.Errorf("%s: inspect: %w", workflow, statErr))
			continue
		}
		if !info.Mode().IsRegular() {
			violations = append(violations, fmt.Errorf("%s: must be a regular file, got %s", workflow, info.Mode()))
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			violations = append(violations, fmt.Errorf("%s: mode is %04o, want 0644", workflow, info.Mode().Perm()))
			continue
		}
		// #nosec G304 -- path is selected from the closed reviewed workflow map.
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			violations = append(violations, fmt.Errorf("%s: read: %w", workflow, readErr))
			continue
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != expectedDigest {
			violations = append(violations, fmt.Errorf("%s: content differs from the reviewed contract", workflow))
		}
	}
	sort.Slice(violations, func(left, right int) bool { return violations[left].Error() < violations[right].Error() })
	return violations
}
