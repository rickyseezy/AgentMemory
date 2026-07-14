//go:build linux || (darwin && cgo)

package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

var testJournalKey = []byte("0123456789abcdef0123456789abcdef")

func TestPF001InstallJournalContract(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(directory, "install.journal")
	journal := mustJournal(t, path, testJournalKey)

	_, err := journal.LoadLatest(context.Background())
	assertErrorIs(t, err, journalport.ErrNotFound)

	first := testSnapshot(1)
	if err := journal.Append(context.Background(), 0, first); err != nil {
		t.Fatalf("append first snapshot: %v", err)
	}
	assertPrivateModes(t, directory, path)
	assertSnapshotEqual(t, mustLoad(t, journal), first)

	// A newly constructed adapter proves persisted state can drive a resume.
	restarted := mustJournal(t, path, testJournalKey)
	second := testSnapshot(2)
	if err := restarted.Append(context.Background(), 1, second); err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	assertSnapshotEqual(t, mustLoad(t, restarted), second)

	stale := testSnapshot(2)
	stale.Payload = json.RawMessage(`{"state":"must-not-win"}`)
	err = restarted.Append(context.Background(), 1, stale)
	assertErrorIs(t, err, journalport.ErrConflict)
	assertSnapshotEqual(t, mustLoad(t, restarted), second)

	differentOperation := testSnapshot(3)
	differentOperation.OperationID = "different-operation"
	err = restarted.Append(context.Background(), 2, differentOperation)
	assertErrorIs(t, err, journalport.ErrConflict)
	assertSnapshotEqual(t, mustLoad(t, restarted), second)
}

func TestPF001InstallJournalCopiesCallerPayload(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	snapshot := testSnapshot(1)
	if err := journal.Append(context.Background(), 0, snapshot); err != nil {
		t.Fatalf("append: %v", err)
	}
	snapshot.Payload[2] = 'X'

	loaded := mustLoad(t, journal)
	if string(loaded.Payload) != `{"state":"phase-1"}` {
		t.Fatalf("stored payload aliases caller memory: %s", loaded.Payload)
	}
}

func TestPF001InstallJournalConfirmsVisibleRevisionDurability(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	snapshot := testSnapshot(1)
	if err := journal.Append(context.Background(), 0, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := journal.ConfirmDurable(context.Background(), snapshot.OperationID, snapshot.Revision); err != nil {
		t.Fatalf("confirm current revision: %v", err)
	}
	assertPrivateModes(t, filepath.Dir(path), path)

	for _, input := range []struct {
		operationID string
		revision    uint64
		want        error
	}{
		{operationID: "", revision: 1, want: journalport.ErrInvalidSnapshot},
		{operationID: snapshot.OperationID, revision: 0, want: journalport.ErrInvalidSnapshot},
		{operationID: "different-operation", revision: 1, want: journalport.ErrConflict},
		{operationID: snapshot.OperationID, revision: 2, want: journalport.ErrConflict},
	} {
		err := journal.ConfirmDurable(context.Background(), input.operationID, input.revision)
		assertErrorIs(t, err, input.want)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err := journal.ConfirmDurable(cancelled, snapshot.OperationID, snapshot.Revision)
	assertErrorIs(t, err, journalport.ErrIO)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("confirm cancellation cause = %v", err)
	}
}

func TestPF001InstallJournalRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	valid := testSnapshot(1)
	tests := map[string]struct {
		expected uint64
		change   func(*journalport.Snapshot)
	}{
		"empty operation ID": {
			change: func(snapshot *journalport.Snapshot) { snapshot.OperationID = "" },
		},
		"operation ID with path separator": {
			change: func(snapshot *journalport.Snapshot) { snapshot.OperationID = "../../escape" },
		},
		"operation ID outside domain alphabet": {
			change: func(snapshot *journalport.Snapshot) { snapshot.OperationID = "operation:one" },
		},
		"nonsequential revision": {
			expected: 1,
		},
		"zero capture time": {
			change: func(snapshot *journalport.Snapshot) { snapshot.CapturedAt = time.Time{} },
		},
		"empty payload": {
			change: func(snapshot *journalport.Snapshot) { snapshot.Payload = nil },
		},
		"invalid JSON payload": {
			change: func(snapshot *journalport.Snapshot) { snapshot.Payload = json.RawMessage(`{"broken"`) },
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := valid
			snapshot.Payload = append(json.RawMessage(nil), valid.Payload...)
			if test.change != nil {
				test.change(&snapshot)
			}
			path := filepath.Join(t.TempDir(), "private", "install.journal")
			journal := mustJournal(t, path, testJournalKey)
			err := journal.Append(context.Background(), test.expected, snapshot)
			assertErrorIs(t, err, journalport.ErrInvalidSnapshot)
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid snapshot created journal, stat error: %v", statErr)
			}
		})
	}
}

func TestPF001InstallJournalSerializesConcurrentAppends(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- journal.Append(context.Background(), 0, testSnapshot(1))
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, journalport.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent append error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results: successes=%d conflicts=%d", successes, conflicts)
	}
	if latest := mustLoad(t, journal); latest.Revision != 1 {
		t.Fatalf("latest revision = %d, want 1", latest.Revision)
	}
}

func TestPF001InstallJournalRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := NewInstallJournal("", testJournalKey)
	assertErrorIs(t, err, journalport.ErrInvalidSnapshot)
	_, err = NewInstallJournal("journal", []byte("short"))
	assertErrorIs(t, err, journalport.ErrInvalidSnapshot)
}

func TestPF001InstallJournalDetectsTampering(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*persistedJournal){
		"format version": func(document *persistedJournal) {
			document.FormatVersion = journalFormatVersion + 1
		},
		"operation ID": func(document *persistedJournal) {
			document.OperationID = ""
		},
		"empty history": func(document *persistedJournal) {
			document.Entries = nil
		},
		"payload": func(document *persistedJournal) {
			document.Entries[0].Payload = json.RawMessage(`{"state":"tampered"}`)
		},
		"capture time": func(document *persistedJournal) {
			document.Entries[0].CapturedAt = "not-a-time"
		},
		"entry hash": func(document *persistedJournal) {
			document.Entries[0].Hash = strings.Repeat("a", sha256HexLength)
		},
		"hash chain": func(document *persistedJournal) {
			document.Entries[1].PreviousHash = strings.Repeat("b", sha256HexLength)
		},
		"entry MAC": func(document *persistedJournal) {
			document.Entries[1].MAC = strings.Repeat("c", sha256HexLength)
		},
		"terminal hash": func(document *persistedJournal) {
			document.TerminalHash = strings.Repeat("d", sha256HexLength)
		},
		"document MAC": func(document *persistedJournal) {
			document.MAC = strings.Repeat("e", sha256HexLength)
		},
		"missing history entry": func(document *persistedJournal) {
			document.Entries = document.Entries[1:]
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, journal := journalWithTwoEntries(t)
			document := readPersistedJournal(t, path)
			mutate(&document)
			writePersistedJournal(t, path, document)

			_, err := journal.LoadLatest(context.Background())
			assertErrorIs(t, err, journalport.ErrCorrupt)
		})
	}
}

func TestPF001InstallJournalDigestComparisonRejectsMalformedHex(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("a", sha256HexLength)
	if equalHexDigest("not-hex", valid) {
		t.Fatal("malformed actual digest passed comparison")
	}
	if equalHexDigest(valid, "not-hex") {
		t.Fatal("malformed expected digest passed comparison")
	}
}

func TestPF001InstallJournalRejectsWrongAuthenticationKey(t *testing.T) {
	t.Parallel()

	path, _ := journalWithTwoEntries(t)
	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	journal := mustJournal(t, path, wrongKey)
	_, err := journal.LoadLatest(context.Background())
	assertErrorIs(t, err, journalport.ErrCorrupt)
}

func TestPF001InstallJournalRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"truncated":       []byte(`{"format_version":1`),
		"unknown field":   []byte(`{"format_version":1,"unexpected":true}`),
		"trailing object": []byte(`{} {}`),
		"oversized":       make([]byte, maximumJournalBytes+1),
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("create directory: %v", err)
			}
			path := filepath.Join(directory, "install.journal")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write malformed journal: %v", err)
			}
			journal := mustJournal(t, path, testJournalKey)
			_, err := journal.LoadLatest(context.Background())
			assertErrorIs(t, err, journalport.ErrCorrupt)
		})
	}
}

func TestPF001InstallJournalEnforcesOwnerOnlyFilesystemBoundary(t *testing.T) {
	t.Run("journal permissions", func(t *testing.T) {
		path, journal := journalWithTwoEntries(t)
		//nolint:gosec // G302: this test deliberately creates an unsafe mode; owner=security expiry=2027-07-13.
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("change mode: %v", err)
		}
		_, err := journal.LoadLatest(context.Background())
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})

	t.Run("directory permissions", func(t *testing.T) {
		path, journal := journalWithTwoEntries(t)
		directory := filepath.Dir(path)
		//nolint:gosec // G302: this test deliberately creates an unsafe mode; owner=security expiry=2027-07-13.
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatalf("change mode: %v", err)
		}
		t.Cleanup(func() {
			//nolint:gosec // G302: 0700 is the required owner-only directory mode; owner=security expiry=2027-07-13.
			_ = os.Chmod(directory, 0o700)
		})
		_, err := journal.LoadLatest(context.Background())
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})

	t.Run("symbolic link", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("not a journal"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		path := filepath.Join(directory, "install.journal")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		journal := mustJournal(t, path, testJournalKey)
		_, err := journal.LoadLatest(context.Background())
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})
}

func TestPF001InstallJournalRejectsForeignOrUnavailableOwnership(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat does not expose syscall.Stat_t")
	}
	foreign := *status
	foreign.Uid ^= 1
	err = verifyCurrentOwner(fileInfoWithSystem{FileInfo: info, system: &foreign}, "inspect")
	assertErrorIs(t, err, journalport.ErrUnsafePermission)
	err = verifyCurrentOwner(fileInfoWithSystem{FileInfo: info, system: struct{}{}}, "inspect")
	assertErrorIs(t, err, journalport.ErrUnsafePermission)
}

func TestPF001InstallJournalHonorsCancellationBeforeMutation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := journal.Append(ctx, 0, testSnapshot(1))
	assertErrorIs(t, err, journalport.ErrIO)
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cancelled append created journal, stat error: %v", statErr)
	}
}

func TestPF001InstallJournalReportsBoundaryFailures(t *testing.T) {
	t.Parallel()

	t.Run("missing expected revision", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "private", "install.journal")
		journal := mustJournal(t, path, testJournalKey)
		err := journal.Append(context.Background(), 1, testSnapshot(2))
		assertErrorIs(t, err, journalport.ErrConflict)
	})

	t.Run("cancelled load", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "private", "install.journal")
		journal := mustJournal(t, path, testJournalKey)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := journal.LoadLatest(ctx)
		assertErrorIs(t, err, journalport.ErrIO)
	})

	t.Run("parent is a file", func(t *testing.T) {
		t.Parallel()
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
			t.Fatalf("write parent fixture: %v", err)
		}
		journal := mustJournal(t, filepath.Join(parent, "install.journal"), testJournalKey)
		err := journal.Append(context.Background(), 0, testSnapshot(1))
		assertErrorIs(t, err, journalport.ErrIO)
	})

	t.Run("unsafe abandoned temporary", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		stale := filepath.Join(directory, ".install.journal.attacker.tmp")
		if err := os.Symlink(target, stale); err != nil {
			t.Fatalf("create temporary symlink: %v", err)
		}
		journal := mustJournal(t, filepath.Join(directory, "install.journal"), testJournalKey)
		err := journal.Append(context.Background(), 0, testSnapshot(1))
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})

	t.Run("direct non-directory verification", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte("file"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		err := verifyPrivateDirectory(context.Background(), path)
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})

	t.Run("sync missing directory", func(t *testing.T) {
		t.Parallel()
		err := syncDirectory(context.Background(), filepath.Join(t.TempDir(), "missing"))
		assertErrorIs(t, err, journalport.ErrIO)
	})
}

func TestPF001InstallJournalAtomicWriteFailureCheckpoints(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected atomic-write failure")
	for checkpoint := checkpointTempCreated; checkpoint <= checkpointDirectorySynced; checkpoint++ {
		checkpoint := checkpoint
		t.Run(fmt.Sprintf("checkpoint_%d", checkpoint), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "private", "install.journal")
			journal, err := newInstallJournal(path, testJournalKey, func(reached writeCheckpoint) error {
				if reached == checkpoint {
					return injected
				}
				return nil
			})
			if err != nil {
				t.Fatalf("construct journal: %v", err)
			}
			err = journal.Append(context.Background(), 0, testSnapshot(1))
			assertErrorIs(t, err, journalport.ErrIO)
			if !errors.Is(err, injected) {
				t.Fatalf("checkpoint error does not retain cause: %v", err)
			}
		})
	}
}

func TestPF001InstallJournalCancellationDuringAtomicWrite(t *testing.T) {
	t.Parallel()

	tests := map[string]writeCheckpoint{
		"before temporary write": checkpointTempCreated,
		"before rename":          checkpointTempClosed,
	}
	for name, checkpoint := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "private", "install.journal")
			ctx, cancel := context.WithCancel(context.Background())
			journal, err := newInstallJournal(path, testJournalKey, func(reached writeCheckpoint) error {
				if reached == checkpoint {
					cancel()
				}
				return nil
			})
			if err != nil {
				t.Fatalf("construct journal: %v", err)
			}
			err = journal.Append(ctx, 0, testSnapshot(1))
			assertErrorIs(t, err, journalport.ErrIO)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("atomic cancellation does not retain cause: %v", err)
			}
		})
	}
}

func TestPF001InstallJournalReportsRenameAndParentSyncFailures(t *testing.T) {
	t.Parallel()

	t.Run("rename destination is a directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "install.journal")
		journal, err := newInstallJournal(path, testJournalKey, func(reached writeCheckpoint) error {
			if reached == checkpointTempClosed {
				return os.Mkdir(path, 0o700)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("construct journal: %v", err)
		}
		err = journal.Append(context.Background(), 0, testSnapshot(1))
		assertErrorIs(t, err, journalport.ErrIO)
	})

	t.Run("parent disappears before fsync", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "private")
		movedDirectory := filepath.Join(root, "moved")
		path := filepath.Join(directory, "install.journal")
		journal, err := newInstallJournal(path, testJournalKey, func(reached writeCheckpoint) error {
			if reached == checkpointRenamed {
				return os.Rename(directory, movedDirectory)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("construct journal: %v", err)
		}
		err = journal.Append(context.Background(), 0, testSnapshot(1))
		assertErrorIs(t, err, journalport.ErrUnsafePermission)
	})
}

func TestPF001InstallJournalRejectsGrowthPastDurabilityBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	payload := json.RawMessage(`"` + strings.Repeat("a", maximumPayloadBytes-2) + `"`)
	for revision := uint64(1); revision <= 3; revision++ {
		snapshot := testSnapshot(revision)
		snapshot.Payload = payload
		if err := journal.Append(context.Background(), revision-1, snapshot); err != nil {
			t.Fatalf("append in-bound revision %d: %v", revision, err)
		}
	}
	overflow := testSnapshot(4)
	overflow.Payload = payload
	err := journal.Append(context.Background(), 3, overflow)
	assertErrorIs(t, err, journalport.ErrIO)
	if latest := mustLoad(t, journal); latest.Revision != 3 {
		t.Fatalf("oversized append changed durable revision to %d", latest.Revision)
	}
}

func TestPF001InstallJournalSurvivesProcessKillAtEveryAtomicWriteCheckpoint(t *testing.T) {
	if os.Getenv("AGENTMEMORY_JOURNAL_CRASH_HELPER") != "" {
		runCrashHelper(t)
		return
	}

	for checkpoint := checkpointTempCreated; checkpoint <= checkpointDirectorySynced; checkpoint++ {
		checkpoint := checkpoint
		t.Run(fmt.Sprintf("checkpoint_%d", checkpoint), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private", "install.journal")
			journal := mustJournal(t, path, testJournalKey)
			if err := journal.Append(context.Background(), 0, testSnapshot(1)); err != nil {
				t.Fatalf("write baseline: %v", err)
			}

			//nolint:gosec // G204: os.Args[0] is this signed test binary, not user input; owner=security expiry=2027-07-13.
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPF001InstallJournalSurvivesProcessKillAtEveryAtomicWriteCheckpoint$")
			command.Env = append(os.Environ(),
				"AGENTMEMORY_JOURNAL_CRASH_HELPER=1",
				"AGENTMEMORY_JOURNAL_PATH="+path,
				"AGENTMEMORY_JOURNAL_CHECKPOINT="+strconv.Itoa(int(checkpoint)),
			)
			err := command.Run()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 91 {
				t.Fatalf("helper must be killed at checkpoint %d, got %v", checkpoint, err)
			}

			restarted := mustJournal(t, path, testJournalKey)
			latest := mustLoad(t, restarted)
			expectedRevision := uint64(1)
			if checkpoint >= checkpointRenamed {
				expectedRevision = 2
			}
			if latest.Revision != expectedRevision {
				t.Fatalf("after checkpoint %d: revision = %d, want %d", checkpoint, latest.Revision, expectedRevision)
			}

			// Resume from the authenticated durable revision. Append also removes
			// an abandoned owner-only temp file left by a pre-rename kill.
			next := testSnapshot(expectedRevision + 1)
			if err := restarted.Append(context.Background(), expectedRevision, next); err != nil {
				t.Fatalf("resume after checkpoint %d: %v", checkpoint, err)
			}
			assertSnapshotEqual(t, mustLoad(t, restarted), next)
			assertNoJournalTemporaries(t, path)
		})
	}
}

func runCrashHelper(t *testing.T) {
	t.Helper()
	checkpoint, err := parseWriteCheckpoint(os.Getenv("AGENTMEMORY_JOURNAL_CHECKPOINT"))
	if err != nil {
		t.Fatalf("parse crash checkpoint: %v", err)
	}
	journal, err := newInstallJournal(
		os.Getenv("AGENTMEMORY_JOURNAL_PATH"),
		testJournalKey,
		func(reached writeCheckpoint) error {
			if reached == checkpoint {
				os.Exit(91)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("construct crash journal: %v", err)
	}
	if err := journal.Append(context.Background(), 1, testSnapshot(2)); err != nil {
		t.Fatalf("append in crash helper: %v", err)
	}
	t.Fatal("crash checkpoint was not reached")
}

func parseWriteCheckpoint(value string) (writeCheckpoint, error) {
	switch value {
	case "1":
		return checkpointTempCreated, nil
	case "2":
		return checkpointTempWritten, nil
	case "3":
		return checkpointTempSynced, nil
	case "4":
		return checkpointTempClosed, nil
	case "5":
		return checkpointRenamed, nil
	case "6":
		return checkpointDirectorySynced, nil
	default:
		return 0, fmt.Errorf("unsupported checkpoint %q", value)
	}
}

func FuzzPF001InstallJournalRejectsUnauthenticatedBytes(f *testing.F) {
	f.Add([]byte(`{"format_version":1}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > maximumJournalBytes+1 {
			t.Skip()
		}
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
		path := filepath.Join(directory, "install.journal")
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("write fuzz input: %v", err)
		}
		journal := mustJournal(t, path, testJournalKey)
		_, err := journal.LoadLatest(context.Background())
		if err == nil {
			t.Fatal("unauthenticated fuzz input unexpectedly passed verification")
		}
		if !errors.Is(err, journalport.ErrCorrupt) {
			t.Fatalf("unexpected error type: %v", err)
		}
	})
}

const sha256HexLength = 64

type fileInfoWithSystem struct {
	os.FileInfo
	system any
}

func (f fileInfoWithSystem) Sys() any { return f.system }

func testSnapshot(revision uint64) journalport.Snapshot {
	return journalport.Snapshot{
		OperationID: "018f4d50-4154-7902-b2a0-7c164ae2549f",
		Revision:    revision,
		CapturedAt:  time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(fmt.Sprintf(`{"state":"phase-%d"}`, revision)),
	}
}

func mustJournal(t *testing.T, path string, key []byte) *InstallJournal {
	t.Helper()
	journal, err := NewInstallJournal(path, key)
	if err != nil {
		t.Fatalf("construct journal: %v", err)
	}
	return journal
}

func mustLoad(t *testing.T, journal *InstallJournal) journalport.Snapshot {
	t.Helper()
	snapshot, err := journal.LoadLatest(context.Background())
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	return snapshot
}

func journalWithTwoEntries(t *testing.T) (string, *InstallJournal) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "install.journal")
	journal := mustJournal(t, path, testJournalKey)
	if err := journal.Append(context.Background(), 0, testSnapshot(1)); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if err := journal.Append(context.Background(), 1, testSnapshot(2)); err != nil {
		t.Fatalf("append second: %v", err)
	}
	return path, journal
}

func readPersistedJournal(t *testing.T, path string) persistedJournal {
	t.Helper()
	//nolint:gosec // G304: path is created under this test's private TempDir; owner=security expiry=2027-07-13.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted journal: %v", err)
	}
	var document persistedJournal
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode persisted journal: %v", err)
	}
	return document
}

func writePersistedJournal(t *testing.T, path string, document persistedJournal) {
	t.Helper()
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode tampered journal: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write tampered journal: %v", err)
	}
}

func assertSnapshotEqual(t *testing.T, actual journalport.Snapshot, expected journalport.Snapshot) {
	t.Helper()
	if actual.OperationID != expected.OperationID ||
		actual.Revision != expected.Revision ||
		!actual.CapturedAt.Equal(expected.CapturedAt) ||
		string(actual.Payload) != string(compactJSON(expected.Payload)) {
		t.Fatalf("snapshot mismatch\nactual:   %+v\nexpected: %+v", actual, expected)
	}
}

func assertErrorIs(t *testing.T, actual error, expected error) {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", actual, expected)
	}
}

func assertPrivateModes(t *testing.T, directory string, path string) {
	t.Helper()
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if directoryInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("directory is not owner-only: %04o", directoryInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %04o, want 0600", fileInfo.Mode().Perm())
	}
}

func assertNoJournalTemporaries(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("list journal directory: %v", err)
	}
	prefix := "." + filepath.Base(path) + "."
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("abandoned temporary remains after resume: %s", entry.Name())
		}
	}
}
