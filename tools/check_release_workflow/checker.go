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
	certificationWorkflowPath = ".github/workflows/pf001-native-certification.yml"
	hostPackageWorkflowPath   = ".github/workflows/pf001-host-package-build.yml"
	releaseWorkflowPath       = ".github/workflows/pf001-release.yml"
	qualificationWorkflowPath = ".github/workflows/pf001-release-qualification.yml"
	downloadArtifactCommit    = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
)

var reviewedWorkflows = map[string]string{
	buildWorkflowPath:         "0521cd8ed35750665b45e18a0e24990a5fbf38c53bfa4c3e618f604d6dd2b1c6",
	certificationWorkflowPath: "df05072b988d015412e855a8f3dba6614d26e5e18bab078dba34921b88bc6795",
	hostPackageWorkflowPath:   "c28e217174b577fea6ea52048ec17be3089b6787a9e280558c3e52ff52f9a998",
	releaseWorkflowPath:       "ab8cd6a2d3a30337a1a966412f6130d71639e6064da013907b57eab588c155da",
	qualificationWorkflowPath: "36d7454e3f917b2783240b40052f9b4267ff7e2049e5bad73ed1d3e9bcb383f2",
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
