// Command check_mutation_coverage verifies Mutago shard evidence and enforces
// weighted mutation thresholds at the native build-owner boundary. Shards are
// an execution detail; their independent sizes must not redefine the gate.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

const maximumEvidenceBytes = 1 << 20

var evidenceNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type matrixCell struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	Runner     string `json:"runner"`
	CgoEnabled string `json:"cgo_enabled"`
	ShardIndex int    `json:"shard_index"`
	ShardCount int    `json:"shard_count"`
}

type githubMatrix struct {
	Include []matrixCell `json:"include"`
}

type mutationSummary struct {
	TotalMutantsCount int64   `json:"totalMutantsCount"`
	KilledCount       int64   `json:"killedCount"`
	NotCoveredCount   int64   `json:"notCoveredCount"`
	EscapedCount      int64   `json:"escapedCount"`
	ErrorCount        int64   `json:"errorCount"`
	SkippedCount      int64   `json:"skippedCount"`
	Msi               float64 `json:"msi"`
	CoveredCodeMsi    float64 `json:"coveredCodeMsi"`
}

type ownerEvidence struct {
	Owner                 string  `json:"owner"`
	ShardCount            int     `json:"shardCount"`
	TotalMutantsCount     int64   `json:"totalMutantsCount"`
	KilledCount           int64   `json:"killedCount"`
	NotCoveredCount       int64   `json:"notCoveredCount"`
	EscapedCount          int64   `json:"escapedCount"`
	ErrorCount            int64   `json:"errorCount"`
	SkippedCount          int64   `json:"skippedCount"`
	Msi                   float64 `json:"msi"`
	CoveredCodeMsi        float64 `json:"coveredCodeMsi"`
	AffectedMutants       bool    `json:"affectedMutants"`
	MinimumMsiPercent     float64 `json:"minimumMsiPercent"`
	MinimumCoveredPercent float64 `json:"minimumCoveredMsiPercent"`
}

type aggregateEvidence struct {
	SchemaVersion int             `json:"schemaVersion"`
	Passed        bool            `json:"passed"`
	Failures      []string        `json:"failures,omitempty"`
	Owners        []ownerEvidence `json:"owners"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check-mutation-coverage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "directory containing Mutago summary JSON files")
	matrixPath := flags.String("matrix", "", "native mutation matrix JSON file")
	prefix := flags.String("prefix", "", "summary filename prefix after mutago-summary-")
	minimumMsi := flags.Float64("min-msi", 80, "minimum weighted MSI percentage")
	minimumCovered := flags.Float64("min-covered-msi", 80, "minimum weighted covered-code MSI percentage")
	output := flags.String("output", "", "optional aggregate evidence JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *directory == "" || *matrixPath == "" ||
		*minimumMsi < 0 || *minimumMsi > 100 || *minimumCovered < 0 || *minimumCovered > 100 ||
		!validPrefix(*prefix) {
		_, _ = fmt.Fprintln(stderr, "mutation coverage arguments are invalid")
		return 2
	}
	evidence, err := evaluate(*directory, *matrixPath, *prefix, *minimumMsi, *minimumCovered)
	if *output != "" && evidence.SchemaVersion != 0 {
		if writeErr := writeEvidence(*output, evidence); writeErr != nil {
			_, _ = fmt.Fprintf(stderr, "write mutation coverage evidence: %v\n", writeErr)
			return 1
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation coverage gate failed: %v\n", err)
		return 1
	}
	for _, owner := range evidence.Owners {
		if !owner.AffectedMutants {
			_, _ = fmt.Fprintf(stdout, "%s: no affected mutants\n", owner.Owner)
			continue
		}
		_, _ = fmt.Fprintf(
			stdout, "%s: MSI %.2f%%, covered-code MSI %.2f%% (%d shards, %d mutants)\n",
			owner.Owner, owner.Msi*100, owner.CoveredCodeMsi*100, owner.ShardCount, owner.TotalMutantsCount,
		)
	}
	return 0
}

func evaluate(
	directory, matrixPath, prefix string,
	minimumMsi, minimumCovered float64,
) (aggregateEvidence, error) {
	var matrix githubMatrix
	if err := readStrictJSON(matrixPath, &matrix); err != nil {
		return aggregateEvidence{}, fmt.Errorf("read matrix: %w", err)
	}
	if err := validateMatrix(matrix); err != nil {
		return aggregateEvidence{}, err
	}
	if err := validateEvidenceSet(directory, matrix, prefix); err != nil {
		return aggregateEvidence{}, err
	}
	byOwner := make(map[string]*ownerEvidence)
	for _, cell := range matrix.Include {
		path := filepath.Join(directory, "mutago-summary-"+prefix+cell.Name+".json")
		var summary mutationSummary
		if err := readStrictJSON(path, &summary); err != nil {
			return aggregateEvidence{}, fmt.Errorf("read %s: %w", cell.Name, err)
		}
		if err := validateSummary(summary); err != nil {
			return aggregateEvidence{}, fmt.Errorf("validate %s: %w", cell.Name, err)
		}
		owner := byOwner[cell.Owner]
		if owner == nil {
			owner = &ownerEvidence{
				Owner: cell.Owner, MinimumMsiPercent: minimumMsi,
				MinimumCoveredPercent: minimumCovered,
			}
			byOwner[cell.Owner] = owner
		}
		owner.ShardCount++
		owner.TotalMutantsCount += summary.TotalMutantsCount
		owner.KilledCount += summary.KilledCount
		owner.NotCoveredCount += summary.NotCoveredCount
		owner.EscapedCount += summary.EscapedCount
		owner.ErrorCount += summary.ErrorCount
		owner.SkippedCount += summary.SkippedCount
	}

	owners := make([]ownerEvidence, 0, len(byOwner))
	var gateFailures []error
	var failureMessages []string
	for _, owner := range byOwner {
		owner.AffectedMutants = owner.TotalMutantsCount > 0
		owner.Msi, owner.CoveredCodeMsi = scores(
			owner.TotalMutantsCount, owner.KilledCount, owner.ErrorCount,
			owner.SkippedCount, owner.NotCoveredCount,
		)
		if owner.AffectedMutants && owner.Msi*100+1e-9 < minimumMsi {
			failure := fmt.Errorf(
				"%s weighted MSI %.2f%% is below %.2f%%", owner.Owner, owner.Msi*100, minimumMsi,
			)
			gateFailures = append(gateFailures, failure)
			failureMessages = append(failureMessages, failure.Error())
		}
		if owner.AffectedMutants && owner.CoveredCodeMsi*100+1e-9 < minimumCovered {
			failure := fmt.Errorf(
				"%s weighted covered-code MSI %.2f%% is below %.2f%%",
				owner.Owner, owner.CoveredCodeMsi*100, minimumCovered,
			)
			gateFailures = append(gateFailures, failure)
			failureMessages = append(failureMessages, failure.Error())
		}
		owners = append(owners, *owner)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].Owner < owners[j].Owner })
	sort.Strings(failureMessages)
	evidence := aggregateEvidence{
		SchemaVersion: 1, Passed: len(gateFailures) == 0, Failures: failureMessages, Owners: owners,
	}
	return evidence, errors.Join(gateFailures...)
}

func validateEvidenceSet(directory string, matrix githubMatrix, prefix string) error {
	expected := make(map[string]struct{}, len(matrix.Include))
	for _, cell := range matrix.Include {
		expected["mutago-summary-"+prefix+cell.Name+".json"] = struct{}{}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read mutation evidence directory: %w", err)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, present := expected[entry.Name()]; !present {
			return fmt.Errorf("unexpected mutation evidence %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect mutation evidence %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("mutation evidence %q is not a regular file", entry.Name())
		}
		seen[entry.Name()] = struct{}{}
	}
	for name := range expected {
		if _, present := seen[name]; !present {
			return fmt.Errorf("required mutation evidence %q is missing", name)
		}
	}
	return nil
}

func validateMatrix(matrix githubMatrix) error {
	if len(matrix.Include) == 0 {
		return errors.New("mutation matrix is empty")
	}
	type ownerState struct {
		count   int
		indices map[int]struct{}
	}
	owners := make(map[string]*ownerState)
	names := make(map[string]struct{}, len(matrix.Include))
	for _, cell := range matrix.Include {
		if !evidenceNamePattern.MatchString(cell.Name) || !evidenceNamePattern.MatchString(cell.Owner) ||
			cell.ShardCount <= 0 || cell.ShardIndex < 0 || cell.ShardIndex >= cell.ShardCount ||
			cell.Name != fmt.Sprintf("%s-%02d", cell.Owner, cell.ShardIndex) {
			return fmt.Errorf("mutation matrix cell %q is invalid", cell.Name)
		}
		if _, duplicate := names[cell.Name]; duplicate {
			return fmt.Errorf("mutation matrix cell %q is duplicated", cell.Name)
		}
		names[cell.Name] = struct{}{}
		state := owners[cell.Owner]
		if state == nil {
			state = &ownerState{count: cell.ShardCount, indices: make(map[int]struct{})}
			owners[cell.Owner] = state
		}
		if state.count != cell.ShardCount {
			return fmt.Errorf("mutation matrix owner %q has inconsistent shard counts", cell.Owner)
		}
		state.indices[cell.ShardIndex] = struct{}{}
	}
	for owner, state := range owners {
		if len(state.indices) != state.count {
			return fmt.Errorf("mutation matrix owner %q is missing shards", owner)
		}
	}
	return nil
}

func validateSummary(summary mutationSummary) error {
	counts := []int64{
		summary.TotalMutantsCount, summary.KilledCount, summary.NotCoveredCount,
		summary.EscapedCount, summary.ErrorCount, summary.SkippedCount,
	}
	for _, count := range counts {
		if count < 0 {
			return errors.New("mutation counts must be non-negative")
		}
	}
	total := summary.KilledCount + summary.NotCoveredCount + summary.EscapedCount +
		summary.ErrorCount + summary.SkippedCount
	if summary.TotalMutantsCount != total {
		return fmt.Errorf("total mutant count %d does not match result counts %d", summary.TotalMutantsCount, total)
	}
	msi, covered := scores(total, summary.KilledCount, summary.ErrorCount, summary.SkippedCount, summary.NotCoveredCount)
	if !validScore(summary.Msi) || !validScore(summary.CoveredCodeMsi) ||
		math.Abs(summary.Msi-msi) > 1e-9 || math.Abs(summary.CoveredCodeMsi-covered) > 1e-9 {
		return errors.New("reported mutation scores do not match result counts")
	}
	return nil
}

func scores(total, killed, errored, skipped, notCovered int64) (float64, float64) {
	if total == 0 {
		return 0, 0
	}
	effectiveKilled := killed + errored + skipped
	msi := float64(effectiveKilled) / float64(total)
	coveredTotal := total - notCovered
	if coveredTotal == 0 {
		return msi, 0
	}
	return msi, float64(effectiveKilled) / float64(coveredTotal)
}

func validScore(score float64) bool {
	return !math.IsNaN(score) && !math.IsInf(score, 0) && score >= 0 && score <= 1
}

func validPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	return evidenceNamePattern.MatchString(prefix[:len(prefix)-1]) && prefix[len(prefix)-1] == '-'
}

func readStrictJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maximumEvidenceBytes {
		return errors.New("evidence must be a bounded regular file")
	}
	// #nosec G304 -- the caller supplies a CI-owned matrix or summary path;
	// regular-file, size, schema, count, and score checks constrain its use.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maximumEvidenceBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("evidence contains trailing JSON values")
	}
	return nil
}

func writeEvidence(path string, evidence aggregateEvidence) error {
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".mutation-evidence-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
