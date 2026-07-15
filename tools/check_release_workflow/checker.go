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
	buildWorkflowPath         = ".github/workflows/pf001-release-build.yml"
	hostPackageWorkflowPath   = ".github/workflows/pf001-host-package-build.yml"
	releaseWorkflowPath       = ".github/workflows/pf001-release.yml"
	qualificationWorkflowPath = ".github/workflows/pf001-release-qualification.yml"
	downloadArtifactCommit    = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
)

var reviewedWorkflows = map[string]string{
	buildWorkflowPath:         "0521cd8ed35750665b45e18a0e24990a5fbf38c53bfa4c3e618f604d6dd2b1c6",
	hostPackageWorkflowPath:   "c28e217174b577fea6ea52048ec17be3089b6787a9e280558c3e52ff52f9a998",
	releaseWorkflowPath:       "bc4f2e36f8d64caea952a8a1dc7534ceaa74ce435761b82fde47426d120e801a",
	qualificationWorkflowPath: "8b8ed85664314777bdb8d8b968e67e2be7443540adda5a47e9be634aa06b64e2",
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
