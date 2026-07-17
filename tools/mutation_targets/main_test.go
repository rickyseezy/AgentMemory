package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestPF001MutationTargetCommandEmitsMatrixAndExactShard(t *testing.T) {
	t.Parallel()
	root := mutationFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", root, "-emit-github-matrix", "-max-files-per-shard", "1"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("matrix run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var matrix githubMatrix
	if err := json.Unmarshal(stdout.Bytes(), &matrix); err != nil || len(matrix.Include) != 9 {
		t.Fatalf("matrix=%+v error=%v", matrix, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"-root", root, "-owner", "windows-amd64-nocgo", "-shard-index", "0", "-shard-count", "1",
	}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || filepath.Base(strings.TrimSpace(stdout.String())) != "windows.go" {
		t.Fatalf("selection run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001MutationTargetCommandRejectsAmbiguousOrInvalidRequests(t *testing.T) {
	t.Parallel()
	root := mutationFixture(t)
	for name, args := range map[string][]string{
		"positional":       {"-root", root, "foreign"},
		"maximum":          {"-root", root, "-emit-github-matrix", "-max-files-per-shard", "0"},
		"ambiguous matrix": {"-root", root, "-emit-github-matrix", "-owner", "linux-amd64-cgo"},
		"foreign owner":    {"-root", root, "-owner", "foreign", "-shard-index", "0", "-shard-count", "1"},
		"empty shard":      {"-root", root, "-owner", "windows-amd64-nocgo", "-shard-index", "1", "-shard-count", "2"},
		"missing root":     {"-root", root + ".missing", "-emit-github-matrix"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code == 0 || stderr.Len() == 0 {
				t.Fatalf("run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
