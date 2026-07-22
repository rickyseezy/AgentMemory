package mcpsessioncheckpoint

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

func TestPF005ScannerUploadsOnlyChangedPrivacyAuthorizedRelativeContent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCheckpointFile(t, root, "keep.txt", "before")
	writeCheckpointFile(t, root, "delete.txt", "delete me")
	writeCheckpointFile(t, root, ".agentmemoryignore", "ignored.txt\nprivate/\n")
	writeCheckpointFile(t, root, "ignored.txt", "private")
	writeCheckpointFile(t, root, ".env.production", "TOKEN=secret")
	writeCheckpointFile(t, root, "private/value.txt", "private")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	plan := checkpointPlan(t, root)
	sink := &checkpointSink{}
	scanner, err := NewScanner(sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.Begin(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 1 || len(sink.batches) != 1 || len(sink.batches[0].Changes) != 2 {
		t.Fatalf("initial batch=%+v calls=%d", sink.batches, sink.calls)
	}
	writeCheckpointFile(t, root, "keep.txt", "after")
	writeCheckpointFile(t, root, "added/α.go", "package alpha\n")
	writeCheckpointFile(t, root, "ignored.txt", "changed private")
	if err := os.Remove(filepath.Join(root, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Checkpoint(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	batch := sink.batches[1]
	if sink.calls != 2 || batch.SessionID != plan.SessionID() ||
		batch.WorkspaceFingerprint != plan.Workspace().PathFingerprint() || batch.Partial {
		t.Fatalf("batch=%+v calls=%d", batch, sink.calls)
	}
	if len(batch.Changes) != 3 {
		t.Fatalf("changes=%+v", batch.Changes)
	}
	wanted := map[string]string{"added/α.go": "package alpha\n", "delete.txt": "", "keep.txt": "after"}
	for _, change := range batch.Changes {
		if string(change.Content) != wanted[change.RelativePath] ||
			change.Deleted != (change.RelativePath == "delete.txt") ||
			!mcpsession.ValidSHA256Digest(change.SHA256) ||
			strings.Contains(change.RelativePath, root) {
			t.Fatalf("change=%+v", change)
		}
	}
}

func TestPF005ScannerRetainsBaselineUntilDurableAckAndRejectsPartialAuthority(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCheckpointFile(t, root, "file.txt", "before")
	plan := checkpointPlan(t, root)
	sink := &checkpointSink{}
	scanner, _ := NewScanner(sink)
	if err := scanner.Begin(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	sink.err = errors.New("unavailable")
	writeCheckpointFile(t, root, "file.txt", "after")
	if err := scanner.Checkpoint(t.Context(), plan); err == nil {
		t.Fatal("sink failure hidden")
	}
	sink.err = nil
	if err := scanner.Checkpoint(t.Context(), plan); err != nil || sink.calls != 3 {
		t.Fatalf("retry error=%v calls=%d", err, sink.calls)
	}
	if err := scanner.Checkpoint(t.Context(), plan); err == nil {
		t.Fatal("checkpoint replay without baseline accepted")
	}
	if _, err := NewScanner(nil); err == nil {
		t.Fatal("nil sink accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := scanner.Begin(ctx, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Begin()=%v", err)
	}
}

func TestPF005ScannerDoesNotRetainInitialBaselineBeforeDurableAck(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCheckpointFile(t, root, "source.go", "package source\n")
	plan := checkpointPlan(t, root)
	sink := &checkpointSink{err: errors.New("unavailable")}
	scanner, _ := NewScanner(sink)
	if err := scanner.Begin(t.Context(), plan); err == nil {
		t.Fatal("initial upload failure hidden")
	}
	sink.err = nil
	if err := scanner.Begin(t.Context(), plan); err != nil {
		t.Fatalf("initial retry failed: %v", err)
	}
	if sink.calls != 2 || len(sink.batches[1].Changes) != 1 ||
		string(sink.batches[1].Changes[0].Content) != "package source\n" {
		t.Fatalf("batches=%+v calls=%d", sink.batches, sink.calls)
	}
}

type checkpointSink struct {
	batches []Batch
	err     error
	calls   int
}

func (s *checkpointSink) Upload(_ context.Context, batch Batch) error {
	s.calls++
	stored := Batch{
		SessionID: batch.SessionID, WorkspaceFingerprint: batch.WorkspaceFingerprint,
		Partial: batch.Partial, Changes: make([]Change, len(batch.Changes)),
	}
	for index, change := range batch.Changes {
		stored.Changes[index] = Change{
			RelativePath: change.RelativePath, SHA256: change.SHA256,
			Content: append([]byte(nil), change.Content...), Deleted: change.Deleted,
		}
	}
	s.batches = append(s.batches, stored)
	return s.err
}

func checkpointPlan(t testing.TB, root string) mcpsession.ExecutionPlan {
	t.Helper()
	workspace, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: root, RealPath: root, DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("a", 64), GitCoverage: mcpsession.GitCoverageNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	credential, err := mcpsession.NewCredentialLease(
		strings.Repeat("c", 64), "/owner/session.credential", issued, issued.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := mcpsession.NewExecutionPlan(mcpsession.ExecutionPlanInput{
		SessionID:      "019d2b4e-7a10-7def-8abc-0123456789ab",
		InstallationID: "019d2b4e-7a11-7def-8abc-0123456789ab", AgentID: "codex",
		ReleaseID: "v1.0.0", ManifestDigest: strings.Repeat("d", 64), SecurityEpoch: 1,
		RuntimeEndpoint: "unix:///var/run/docker.sock", Workspace: workspace,
		Image:   "registry.local/agentmemory/mcp-session@sha256:" + strings.Repeat("b", 64),
		Network: "agentmemory_019d2b4e7a117def8abc0123456789ab_internal", Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func writeCheckpointFile(t testing.TB, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPF005ChangedFilesAreCanonicalAndCallerOwned(t *testing.T) {
	t.Parallel()
	content := []byte("value")
	changes := changedFiles(
		map[string]string{"z": "old", "deleted": "old"},
		map[string]string{"a": "new", "z": "new"},
		map[string][]byte{"a": content, "z": bytes.Clone(content)},
	)
	if len(changes) != 3 || changes[0].RelativePath != "a" ||
		changes[1].RelativePath != "deleted" || changes[2].RelativePath != "z" {
		t.Fatalf("changes=%+v", changes)
	}
}
