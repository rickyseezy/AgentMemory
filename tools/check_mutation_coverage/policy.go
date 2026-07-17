package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

const maximumMutationPolicyBytes = 64 << 10

var requiredNativeMutators = []string{
	"arithmetic/assign_invert",
	"arithmetic/assignment",
	"arithmetic/base",
	"arithmetic/bitwise",
	"arithmetic/negate",
	"branch/case",
	"branch/else",
	"branch/if",
	"composite/field-clear",
	"concurrency/goroutine-remove",
	"conditional/negated",
	"conditional/not",
	"expression/context-nil",
	"expression/error-guard",
	"expression/errorf-wrap",
	"expression/recover-clear",
	"loop/break",
	"loop/condition",
	"loop/range_break",
	"select/case-remove",
	"select/default-remove",
	"statement/defer-remove",
	"statement/remove",
	"statement/return",
}

type nativeMutationPolicy struct {
	SkipWithoutTest   *bool    `yaml:"skip_without_test"`
	SkipWithBuildTags *bool    `yaml:"skip_with_build_tags"`
	EnableMutators    []string `yaml:"enable_mutators"`
}

func validateNativeMutationPolicy(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect native mutation policy: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maximumMutationPolicyBytes {
		return errors.New("native mutation policy must be a bounded regular file")
	}
	// #nosec G304 -- the path is CI-owned and constrained to a bounded regular
	// file before it is decoded with a closed schema and exact allowlist.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open native mutation policy: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := yaml.NewDecoder(io.LimitReader(file, maximumMutationPolicyBytes+1))
	decoder.KnownFields(true)
	var policy nativeMutationPolicy
	if err := decoder.Decode(&policy); err != nil {
		return fmt.Errorf("decode native mutation policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("native mutation policy contains trailing YAML documents")
	}
	if policy.SkipWithoutTest == nil || *policy.SkipWithoutTest ||
		policy.SkipWithBuildTags == nil || *policy.SkipWithBuildTags {
		return errors.New("native mutation policy must mutate tagged sources even without matching test filenames")
	}

	expected := make(map[string]struct{}, len(requiredNativeMutators))
	for _, name := range requiredNativeMutators {
		expected[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(policy.EnableMutators))
	for _, name := range policy.EnableMutators {
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("native mutation policy duplicates mutator %q", name)
		}
		if _, required := expected[name]; !required {
			return fmt.Errorf("native mutation policy contains unreviewed mutator %q", name)
		}
		seen[name] = struct{}{}
	}
	for _, name := range requiredNativeMutators {
		if _, present := seen[name]; !present {
			return fmt.Errorf("native mutation policy is missing required mutator %q", name)
		}
	}
	return nil
}
