// Package main implements AgentMemory's launcher statement-coverage policy.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	launcherPathPrefix       = "apps/launcher/"
	maximumDiffLineBytes     = 4 << 20
	initialDiffScannerBuffer = 64 << 10
)

var hunkHeaderPattern = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

type coverageBlock struct {
	File        string
	StartLine   uint64
	StartColumn uint64
	EndLine     uint64
	EndColumn   uint64
	Statements  uint64
	Count       uint64
}

func (b coverageBlock) Covered() bool {
	return b.Count > 0
}

type coverageProfile struct {
	Blocks []coverageBlock
}

type packageCoverage struct {
	Package    string
	Statements uint64
	Covered    uint64
	Percent    float64
	Passed     bool
	Missing    bool
}

type changedCoverage struct {
	Statements uint64
	Covered    uint64
	Percent    float64
	Passed     bool
}

type lineRange struct {
	Start uint64
	End   uint64
}

type changedLines map[string][]lineRange

func (c changedLines) Contains(file string, line uint64) bool {
	for _, candidate := range c[file] {
		if line >= candidate.Start && line <= candidate.End {
			return true
		}
	}
	return false
}

func (c changedLines) intersects(file string, start uint64, end uint64) bool {
	for _, candidate := range c[file] {
		if start <= candidate.End && candidate.Start <= end {
			return true
		}
	}
	return false
}

func parseProfile(reader io.Reader, modulePath string) (coverageProfile, error) {
	scanner := bufio.NewScanner(reader)
	lineNumber := 0
	profile := coverageProfile{Blocks: make([]coverageBlock, 0)}
	indices := make(map[coverageBlockIdentity]int)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if lineNumber == 1 {
			if line != "mode: set" && line != "mode: count" && line != "mode: atomic" {
				return coverageProfile{}, fmt.Errorf("coverage profile line 1 has an unsupported mode")
			}
			continue
		}
		if line == "" {
			return coverageProfile{}, fmt.Errorf("coverage profile line %d is empty", lineNumber)
		}
		block, err := parseCoverageBlock(line, modulePath)
		if err != nil {
			return coverageProfile{}, fmt.Errorf("coverage profile line %d: %w", lineNumber, err)
		}
		identity := block.identity()
		if index, duplicate := indices[identity]; duplicate {
			if profile.Blocks[index].Statements != block.Statements {
				return coverageProfile{}, fmt.Errorf(
					"coverage profile line %d: duplicate block statement count changed", lineNumber,
				)
			}
			if block.Covered() {
				profile.Blocks[index].Count = 1
			}
			continue
		}
		indices[identity] = len(profile.Blocks)
		profile.Blocks = append(profile.Blocks, block)
	}
	if err := scanner.Err(); err != nil {
		return coverageProfile{}, fmt.Errorf("read coverage profile: %w", err)
	}
	if lineNumber == 0 {
		return coverageProfile{}, errors.New("coverage profile is empty")
	}
	return profile, nil
}

func parseCoverageBlock(line string, modulePath string) (coverageBlock, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return coverageBlock{}, errors.New("block must contain location, statement count, and execution count")
	}
	separator := strings.LastIndexByte(fields[0], ':')
	if separator <= 0 || separator == len(fields[0])-1 {
		return coverageBlock{}, errors.New("block location is malformed")
	}
	file, err := normalizeProfilePath(fields[0][:separator], modulePath)
	if err != nil {
		return coverageBlock{}, err
	}
	startLine, startColumn, endLine, endColumn, err := parseSpan(fields[0][separator+1:])
	if err != nil {
		return coverageBlock{}, err
	}
	statements, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return coverageBlock{}, errors.New("statement count must be a non-negative integer")
	}
	count, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return coverageBlock{}, errors.New("execution count must be a non-negative integer")
	}
	return coverageBlock{
		File:        file,
		StartLine:   startLine,
		StartColumn: startColumn,
		EndLine:     endLine,
		EndColumn:   endColumn,
		Statements:  statements,
		Count:       count,
	}, nil
}

func normalizeProfilePath(file string, modulePath string) (string, error) {
	normalized := strings.TrimPrefix(file, strings.TrimSuffix(modulePath, "/")+"/")
	normalized = path.Clean(normalized)
	if normalized == "." || path.IsAbs(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", errors.New("coverage path escapes the module")
	}
	return normalized, nil
}

func parseSpan(value string) (uint64, uint64, uint64, uint64, error) {
	start, end, found := strings.Cut(value, ",")
	if !found {
		return 0, 0, 0, 0, errors.New("coverage span is malformed")
	}
	startLine, startColumn, err := parsePosition(start)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	endLine, endColumn, err := parsePosition(end)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if endLine < startLine || endLine == startLine && endColumn < startColumn {
		return 0, 0, 0, 0, errors.New("coverage span ends before it starts")
	}
	return startLine, startColumn, endLine, endColumn, nil
}

type coverageBlockIdentity struct {
	file                   string
	startLine, startColumn uint64
	endLine, endColumn     uint64
}

func (b coverageBlock) identity() coverageBlockIdentity {
	return coverageBlockIdentity{
		file: b.File, startLine: b.StartLine, startColumn: b.StartColumn,
		endLine: b.EndLine, endColumn: b.EndColumn,
	}
}

func parsePosition(value string) (uint64, uint64, error) {
	line, column, found := strings.Cut(value, ".")
	if !found {
		return 0, 0, errors.New("coverage position is malformed")
	}
	lineNumber, lineErr := strconv.ParseUint(line, 10, 64)
	columnNumber, columnErr := strconv.ParseUint(column, 10, 64)
	if lineErr != nil || columnErr != nil || lineNumber == 0 || columnNumber == 0 {
		return 0, 0, errors.New("coverage position must contain positive line and column numbers")
	}
	return lineNumber, columnNumber, nil
}

func evaluatePackages(
	profile coverageProfile,
	expected map[string]struct{},
	threshold float64,
) []packageCoverage {
	resultsByPackage := make(map[string]*packageCoverage, len(expected))
	for packagePath := range expected {
		resultsByPackage[packagePath] = &packageCoverage{Package: packagePath, Missing: true}
	}
	for _, block := range profile.Blocks {
		if block.Statements == 0 || !strings.HasPrefix(block.File, launcherPathPrefix) {
			continue
		}
		packagePath := path.Dir(block.File)
		result, found := resultsByPackage[packagePath]
		if !found {
			continue
		}
		result.Missing = false
		result.Statements += block.Statements
		if block.Covered() {
			result.Covered += block.Statements
		}
	}

	results := make([]packageCoverage, 0, len(resultsByPackage))
	for _, result := range resultsByPackage {
		if result.Statements > 0 {
			result.Percent = percentage(result.Covered, result.Statements)
			result.Passed = result.Percent >= threshold
		}
		results = append(results, *result)
	}
	sort.Slice(results, func(left int, right int) bool {
		return results[left].Package < results[right].Package
	})
	return results
}

func evaluateChanged(profile coverageProfile, changed changedLines, threshold float64) changedCoverage {
	result := changedCoverage{}
	for _, block := range profile.Blocks {
		if block.Statements == 0 || !changed.intersects(block.File, block.StartLine, block.EndLine) {
			continue
		}
		result.Statements += block.Statements
		if block.Covered() {
			result.Covered += block.Statements
		}
	}
	if result.Statements == 0 {
		result.Percent = 100
		result.Passed = true
		return result
	}
	result.Percent = percentage(result.Covered, result.Statements)
	result.Passed = result.Percent >= threshold
	return result
}

func percentage(covered uint64, statements uint64) float64 {
	return 100 * float64(covered) / float64(statements)
}

func parseChangedLines(reader io.Reader) (changedLines, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, initialDiffScannerBuffer), maximumDiffLineBytes)
	result := make(changedLines)
	currentFile := ""
	deletedTarget := false
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.HasPrefix(line, "+++ ") {
			currentFile = strings.TrimPrefix(line, "+++ ")
			if currentFile == "/dev/null" {
				currentFile = ""
				deletedTarget = true
				continue
			}
			deletedTarget = false
			currentFile = strings.TrimPrefix(currentFile, "b/")
			currentFile = path.Clean(currentFile)
			if path.IsAbs(currentFile) || currentFile == ".." || strings.HasPrefix(currentFile, "../") {
				return nil, fmt.Errorf("diff line %d has an unsafe path", lineNumber)
			}
			continue
		}
		if !strings.HasPrefix(line, "@@") {
			continue
		}
		if currentFile == "" && !deletedTarget {
			return nil, fmt.Errorf("diff line %d has a hunk without a target file", lineNumber)
		}
		matches := hunkHeaderPattern.FindStringSubmatch(line)
		if matches == nil {
			return nil, fmt.Errorf("diff line %d has a malformed hunk header", lineNumber)
		}
		start, err := strconv.ParseUint(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("diff line %d has an invalid hunk start", lineNumber)
		}
		count := uint64(1)
		if matches[2] != "" {
			count, err = strconv.ParseUint(matches[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("diff line %d has an invalid hunk length", lineNumber)
			}
		}
		if deletedTarget {
			continue
		}
		if count == 0 {
			continue
		}
		if start == 0 || count-1 > ^uint64(0)-start {
			return nil, fmt.Errorf("diff line %d has an overflowing hunk", lineNumber)
		}
		result[currentFile] = append(result[currentFile], lineRange{Start: start, End: start + count - 1})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read git diff: %w", err)
	}
	return result, nil
}
