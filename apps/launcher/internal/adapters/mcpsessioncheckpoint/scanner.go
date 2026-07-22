// Package mcpsessioncheckpoint captures a bounded, privacy-filtered workspace delta on the host.
package mcpsessioncheckpoint

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const (
	maximumFiles       = 10_000
	maximumFileBytes   = 2 * 1024 * 1024
	maximumPayload     = 16 * 1024 * 1024
	maximumIgnoreBytes = 256 * 1024
)

var errCheckpoint = errors.New("PF-005 workspace checkpoint is unavailable")

// Change is one relative, content-addressed workspace observation.
type Change struct {
	RelativePath string
	SHA256       string
	Content      []byte
	Deleted      bool
}

// Batch is one bounded session delta; host absolute paths never cross this boundary.
type Batch struct {
	SessionID            string
	WorkspaceFingerprint string
	Changes              []Change
	Partial              bool
}

// Sink durably accepts one ordered delta or returns an error before ACK.
type Sink interface {
	Upload(context.Context, Batch) error
}

type snapshot struct {
	digests map[string]string
	partial bool
}

// Scanner owns per-session baselines until terminal checkpoint.
type Scanner struct {
	sink      Sink
	mu        sync.Mutex
	baselines map[string]snapshot
}

// NewScanner constructs a bounded scanner with a durable sink.
func NewScanner(sink Sink) (*Scanner, error) {
	if nilCapability(sink) {
		return nil, errCheckpoint
	}
	return &Scanner{sink: sink, baselines: make(map[string]snapshot)}, nil
}

// Begin durably streams the bounded initial snapshot before the agent receives the mount.
func (s *Scanner) Begin(ctx context.Context, plan mcpsession.ExecutionPlan) error {
	if s == nil || ctx == nil || !plan.Valid() || nilCapability(s.sink) {
		return errCheckpoint
	}
	s.mu.Lock()
	_, exists := s.baselines[plan.SessionID()]
	s.mu.Unlock()
	if exists {
		return errCheckpoint
	}
	baseline, contents, err := scan(ctx, plan.Workspace().RealPath(), true)
	if err != nil {
		return err
	}
	initial := changedFiles(map[string]string{}, baseline.digests, contents)
	batch := Batch{
		SessionID: plan.SessionID(), WorkspaceFingerprint: plan.Workspace().PathFingerprint(),
		Changes: initial, Partial: baseline.partial,
	}
	if err := s.sink.Upload(ctx, batch); err != nil {
		clearChanges(initial)
		return err
	}
	clearChanges(initial)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.baselines[plan.SessionID()]; exists {
		return errCheckpoint
	}
	s.baselines[plan.SessionID()] = baseline
	return nil
}

// Checkpoint streams only changed authorized relative files and forgets its baseline after ACK.
func (s *Scanner) Checkpoint(ctx context.Context, plan mcpsession.ExecutionPlan) error {
	if s == nil || ctx == nil || !plan.Valid() || nilCapability(s.sink) {
		return errCheckpoint
	}
	s.mu.Lock()
	baseline, exists := s.baselines[plan.SessionID()]
	s.mu.Unlock()
	if !exists {
		return errCheckpoint
	}
	current, contents, err := scan(ctx, plan.Workspace().RealPath(), true)
	if err != nil {
		return err
	}
	changes := changedFiles(baseline.digests, current.digests, contents)
	batch := Batch{
		SessionID: plan.SessionID(), WorkspaceFingerprint: plan.Workspace().PathFingerprint(),
		Changes: changes, Partial: baseline.partial || current.partial,
	}
	if err := s.sink.Upload(ctx, batch); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.baselines, plan.SessionID())
	s.mu.Unlock()
	clearChanges(changes)
	return nil
}

func scan(ctx context.Context, root string, retain bool) (snapshot, map[string][]byte, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return snapshot{}, nil, errCheckpoint
	}
	policy, err := loadPolicy(root)
	if err != nil {
		return snapshot{}, nil, err
	}
	digests := make(map[string]string)
	contents := make(map[string][]byte)
	files, bytesRead, partial := 0, int64(0), false
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkError error) error {
		if walkError != nil {
			return errCheckpoint
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errCheckpoint
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if denied(relative, entry.IsDir(), policy) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		if files >= maximumFiles {
			partial = true
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return errCheckpoint
		}
		if info.Size() < 0 || info.Size() > maximumFileBytes || bytesRead+info.Size() > maximumPayload {
			partial = true
			return nil
		}
		content, err := readStableFile(path, info)
		if err != nil {
			return err
		}
		bytesRead += int64(len(content))
		files++
		digest := sha256.Sum256(content)
		digests[relative] = hex.EncodeToString(digest[:])
		if retain {
			contents[relative] = content
		} else {
			clear(content)
		}
		return nil
	})
	if err != nil {
		clearContentMap(contents)
		return snapshot{}, nil, err
	}
	return snapshot{digests: digests, partial: partial}, contents, nil
}

func readStableFile(path string, before os.FileInfo) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- child of exact host-resolved workspace; links are excluded.
	if err != nil {
		return nil, errCheckpoint
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	if err != nil || len(content) > maximumFileBytes {
		clear(content)
		return nil, errCheckpoint
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != int64(len(content)) {
		clear(content)
		return nil, errCheckpoint
	}
	return content, nil
}

type ignorePolicy struct{ patterns []string }

func loadPolicy(root string) (ignorePolicy, error) {
	patterns := []string{}
	for _, name := range []string{".agentmemoryignore", ".gitignore"} {
		path := filepath.Join(root, name)
		file, err := os.Open(path) // #nosec G304 -- fixed policy leaf beneath exact root.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ignorePolicy{}, errCheckpoint
		}
		info, statError := file.Stat()
		if statError != nil || !info.Mode().IsRegular() || info.Size() > maximumIgnoreBytes {
			_ = file.Close()
			return ignorePolicy{}, errCheckpoint
		}
		scanner := bufio.NewScanner(io.LimitReader(file, maximumIgnoreBytes+1))
		scanner.Buffer(make([]byte, 4096), maximumIgnoreBytes)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Negated includes are intentionally not honored at this source boundary:
			// privacy exclusions can be relaxed only by Core's explicit policy.
			line = strings.TrimPrefix(line, "!")
			line = strings.TrimPrefix(filepath.ToSlash(line), "/")
			if line != "" && utf8.ValidString(line) && !strings.ContainsRune(line, '\x00') {
				patterns = append(patterns, line)
			}
		}
		scanError := scanner.Err()
		closeError := file.Close()
		if scanError != nil || closeError != nil {
			return ignorePolicy{}, errCheckpoint
		}
	}
	return ignorePolicy{patterns: patterns}, nil
}

func denied(relative string, directory bool, policy ignorePolicy) bool {
	segments := strings.Split(relative, "/")
	for _, segment := range segments {
		lower := strings.ToLower(segment)
		if lower == ".git" || lower == ".agentmemory" || lower == "node_modules" ||
			lower == "vendor" || lower == "__pycache__" || strings.HasPrefix(lower, ".env") ||
			lower == ".agentmemoryignore" || lower == ".gitignore" ||
			strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") ||
			lower == "id_rsa" || lower == "id_ed25519" {
			return true
		}
	}
	for _, pattern := range policy.patterns {
		candidate := strings.TrimSuffix(pattern, "/")
		if matched, _ := filepath.Match(candidate, relative); matched {
			return true
		}
		if !strings.Contains(candidate, "/") {
			for _, segment := range segments {
				if matched, _ := filepath.Match(candidate, segment); matched {
					return true
				}
			}
		}
		if directory && (relative == candidate || strings.HasPrefix(relative+"/", candidate+"/")) {
			return true
		}
	}
	return false
}

func changedFiles(before, after map[string]string, contents map[string][]byte) []Change {
	paths := make([]string, 0, len(before)+len(after))
	seen := make(map[string]struct{}, len(before)+len(after))
	for path, digest := range after {
		if before[path] != digest {
			paths = append(paths, path)
			seen[path] = struct{}{}
		}
	}
	for path := range before {
		if _, exists := after[path]; !exists {
			if _, duplicate := seen[path]; !duplicate {
				paths = append(paths, path)
			}
		}
	}
	slices.Sort(paths)
	changes := make([]Change, 0, len(paths))
	for _, path := range paths {
		digest, exists := after[path]
		if !exists {
			digest = before[path]
		}
		changes = append(changes, Change{
			RelativePath: path, SHA256: digest,
			Content: append([]byte(nil), contents[path]...), Deleted: !exists,
		})
	}
	clearContentMap(contents)
	return changes
}

func clearContentMap(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

func clearChanges(changes []Change) {
	for index := range changes {
		clear(changes[index].Content)
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete capabilities are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
