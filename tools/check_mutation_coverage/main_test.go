package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPF001MutationCoverageAggregatesArbitraryShardsByNativeOwner(t *testing.T) {
	t.Parallel()
	directory, matrix := mutationCoverageFixture(t, githubMatrix{Include: []matrixCell{
		{
			Name: "linux-amd64-cgo-00", Owner: "linux-amd64-cgo", Runner: "ubuntu-24.04",
			CgoEnabled: "1", ShardIndex: 0, ShardCount: 2,
		},
		{Name: "linux-amd64-cgo-01", Owner: "linux-amd64-cgo", ShardIndex: 1, ShardCount: 2},
		{Name: "darwin-arm64-nocgo-00", Owner: "darwin-arm64-nocgo", ShardIndex: 0, ShardCount: 1},
	}})
	writeMutationSummary(t, directory, "linux-amd64-cgo-00", mutationSummary{
		TotalMutantsCount: 2, KilledCount: 1, EscapedCount: 1, Msi: 0.5, CoveredCodeMsi: 0.5,
	})
	writeMutationSummary(t, directory, "linux-amd64-cgo-01", mutationSummary{
		TotalMutantsCount: 9, KilledCount: 9, Msi: 1, CoveredCodeMsi: 1,
	})
	writeMutationSummary(t, directory, "darwin-arm64-nocgo-00", mutationSummary{})

	var stdout, stderr bytes.Buffer
	output := filepath.Join(t.TempDir(), "aggregate.json")
	code := run([]string{
		"-directory", directory, "-matrix", matrix, "-prefix", "adapter-",
		"-min-msi", "80", "-min-covered-msi", "80", "-output", output,
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "linux-amd64-cgo: MSI 90.91%") ||
		!strings.Contains(stdout.String(), "darwin-arm64-nocgo: no affected mutants") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	// #nosec G304 -- output is a test-owned path below t.TempDir().
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var evidence aggregateEvidence
	if err := json.Unmarshal(encoded, &evidence); err != nil || len(evidence.Owners) != 2 || !evidence.Passed {
		t.Fatalf("evidence=%+v error=%v", evidence, err)
	}
}

func TestPF001MutationCoverageEnforcesBothWeightedOwnerThresholds(t *testing.T) {
	t.Parallel()
	tests := map[string]mutationSummary{
		"overall": {
			TotalMutantsCount: 10, KilledCount: 7, EscapedCount: 2,
			NotCoveredCount: 1, Msi: 0.7, CoveredCodeMsi: 7.0 / 9.0,
		},
		"covered": {
			TotalMutantsCount: 10, KilledCount: 8, EscapedCount: 2,
			Msi: 0.8, CoveredCodeMsi: 0.8,
		},
	}
	for name, summary := range tests {
		name, summary := name, summary
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory, matrix := mutationCoverageFixture(t, githubMatrix{Include: []matrixCell{{
				Name: "linux-amd64-cgo-00", Owner: "linux-amd64-cgo", ShardIndex: 0, ShardCount: 1,
			}}})
			writeMutationSummary(t, directory, "linux-amd64-cgo-00", summary)
			var stdout, stderr bytes.Buffer
			output := filepath.Join(t.TempDir(), "failed-aggregate.json")
			minimumCovered := "70"
			if name == "covered" {
				minimumCovered = "81"
			}
			if code := run([]string{
				"-directory", directory, "-matrix", matrix, "-prefix", "adapter-",
				"-min-msi", "80", "-min-covered-msi", minimumCovered, "-output", output,
			}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "linux-amd64-cgo") {
				t.Fatalf("run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			encoded, err := os.ReadFile(output) // #nosec G304 -- output is under t.TempDir().
			if err != nil {
				t.Fatal(err)
			}
			var evidence aggregateEvidence
			if err := json.Unmarshal(encoded, &evidence); err != nil || evidence.Passed || len(evidence.Failures) != 1 {
				t.Fatalf("evidence=%+v error=%v", evidence, err)
			}
		})
	}
}

func TestPF001MutationCoverageRejectsIncompleteOrInvalidEvidence(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*testing.T, string){
		"missing": func(*testing.T, string) {},
		"unexpected": func(t *testing.T, directory string) {
			t.Helper()
			writeMutationSummary(t, directory, "linux-amd64-cgo-00", mutationSummary{})
			if err := os.WriteFile(filepath.Join(directory, "foreign.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"malformed": func(t *testing.T, directory string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(directory, "mutago-summary-adapter-linux-amd64-cgo-00.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"inconsistent counts": func(t *testing.T, directory string) {
			t.Helper()
			writeMutationSummary(t, directory, "linux-amd64-cgo-00", mutationSummary{
				TotalMutantsCount: 3, KilledCount: 2, Msi: 2.0 / 3.0, CoveredCodeMsi: 1,
			})
		},
		"inconsistent score": func(t *testing.T, directory string) {
			t.Helper()
			writeMutationSummary(t, directory, "linux-amd64-cgo-00", mutationSummary{
				TotalMutantsCount: 2, KilledCount: 2, Msi: 0.5, CoveredCodeMsi: 1,
			})
		},
	}
	for name, prepare := range tests {
		name, prepare := name, prepare
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory, matrix := mutationCoverageFixture(t, githubMatrix{Include: []matrixCell{{
				Name: "linux-amd64-cgo-00", Owner: "linux-amd64-cgo", ShardIndex: 0, ShardCount: 1,
			}}})
			prepare(t, directory)
			var stdout, stderr bytes.Buffer
			if code := run([]string{
				"-directory", directory, "-matrix", matrix, "-prefix", "adapter-",
				"-min-msi", "80", "-min-covered-msi", "80",
			}, &stdout, &stderr); code == 0 || stderr.Len() == 0 {
				t.Fatalf("run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestPF001MutationCoverageRejectsInvalidArgumentsAndMatrix(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	matrix := filepath.Join(directory, "matrix.json")
	if err := os.WriteFile(matrix, []byte(`{"include":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"missing required": nil,
		"positional":       {"foreign"},
		"minimum":          {"-directory", directory, "-matrix", matrix, "-min-msi", "101"},
		"prefix":           {"-directory", directory, "-matrix", matrix, "-prefix", "../"},
		"empty matrix":     {"-directory", directory, "-matrix", matrix},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code == 0 || stderr.Len() == 0 {
				t.Fatalf("run=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func mutationCoverageFixture(t *testing.T, matrix githubMatrix) (string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(t.TempDir(), "matrix.json")
	encoded, err := json.Marshal(matrix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, path
}

func writeMutationSummary(t *testing.T, directory, name string, summary mutationSummary) {
	t.Helper()
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "mutago-summary-adapter-"+name+".json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
