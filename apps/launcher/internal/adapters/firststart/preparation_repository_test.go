package firststart

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001PreparationRepositoryPersistsAndConfirmsExactState(t *testing.T) {
	t.Parallel()
	provider := newPreparationJournalProvider()
	repository, err := NewPreparationRepository(provider, preparationClock{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	acquired, err := repository.Acquire(context.Background(), candidate)
	if err != nil || !samePreparation(acquired, candidate) {
		t.Fatalf("Acquire()=%+v,%v", acquired, err)
	}
	loaded, err := repository.Load(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil || !samePreparation(loaded, candidate) {
		t.Fatalf("Load()=%+v,%v", loaded, err)
	}
	digest, _ := install.BindPlan([]byte("canonical plan"))
	confirmed, err := repository.ConfirmPlan(context.Background(), loaded, digest)
	if err != nil || !confirmed.Confirmed() || !confirmed.ConfirmedPlanDigest().Equal(digest) {
		t.Fatalf("ConfirmPlan()=%+v,%v", confirmed, err)
	}
	loaded, err = repository.Load(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil || !samePreparation(loaded, confirmed) {
		t.Fatalf("confirmed Load()=%+v,%v", loaded, err)
	}
	journal := provider.forCodex(t)
	if journal.confirmations != 4 || len(journal.snapshots) != 2 {
		t.Fatalf("confirmations=%d snapshots=%d", journal.confirmations, len(journal.snapshots))
	}
}

func TestPF001PreparationRepositoryConcurrentAcquireReturnsOneDurableWinner(t *testing.T) {
	t.Parallel()
	provider := newPreparationJournalProvider()
	repository, _ := NewPreparationRepository(provider, preparationClock{})
	first := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	second := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	secondDocument, _ := encodePreparation(second)
	firstDocument, _ := encodePreparation(first)
	if string(secondDocument) != string(firstDocument) {
		t.Fatal("deterministic fixture unexpectedly differs")
	}

	const callers = 24
	results := make(chan firststartapp.Preparation, callers)
	errorsChannel := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			state, err := repository.Acquire(context.Background(), first)
			results <- state
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if !samePreparation(result, first) {
			t.Fatal("acquire returned a non-winning state")
		}
	}
	if snapshots := len(provider.forCodex(t).snapshots); snapshots != 1 {
		t.Fatalf("snapshots=%d", snapshots)
	}
}

func TestPF001PreparationRepositoryResolvesAmbiguousDurableWrites(t *testing.T) {
	t.Parallel()
	provider := newPreparationJournalProvider()
	repository, _ := NewPreparationRepository(provider, preparationClock{})
	candidate := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	journal := provider.forCodex(t)
	journal.appendAfterCommitErr = installjournal.ErrIO
	acquired, err := repository.Acquire(context.Background(), candidate)
	if err != nil || !samePreparation(acquired, candidate) {
		t.Fatalf("ambiguous acquire=%+v,%v", acquired, err)
	}
	journal.appendAfterCommitErr = installjournal.ErrIO
	digest, _ := install.BindPlan([]byte("plan"))
	confirmed, err := repository.ConfirmPlan(context.Background(), acquired, digest)
	if err != nil || !confirmed.ConfirmedPlanDigest().Equal(digest) {
		t.Fatalf("ambiguous confirm=%+v,%v", confirmed, err)
	}
}

func TestPF001PreparationRepositoryRejectsConflictsCorruptionAndPartialComposition(t *testing.T) {
	t.Parallel()
	var typedNil *preparationJournalProvider
	if repository, err := NewPreparationRepository(typedNil, preparationClock{}); repository != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("typed nil=%v,%v", repository, err)
	}
	provider := newPreparationJournalProvider()
	repository, _ := NewPreparationRepository(provider, preparationClock{})
	if _, err := repository.Load(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrPreparationNotFound) {
		t.Fatalf("missing=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context contract test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := repository.Load(nil, agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil context=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.Load(cancelled, agentconfigdomain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled=%v", err)
	}
	candidate := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	if _, err := repository.Acquire(context.Background(), firststartapp.Preparation{}); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("invalid acquire=%v", err)
	}
	acquired, _ := repository.Acquire(context.Background(), candidate)
	foreign := preparationForRepositoryTest(t, agentconfigdomain.AgentHostClaude)
	digest, _ := install.BindPlan([]byte("plan"))
	if _, err := repository.ConfirmPlan(context.Background(), foreign, digest); !errors.Is(err, firststartapp.ErrPreparationNotFound) {
		t.Fatalf("missing confirmation=%v", err)
	}
	changed, _ := firststartapp.NewPreparation(acquired.Host(), acquired.TemplateDigest(), acquired.OperationID(), []string{
		"changed", acquired.GenerationID(), acquired.BrainID(), acquired.OwnerPrincipalID(), acquired.OwnerGrantID(), acquired.AgentEntryID(),
	}, acquired.SecurityEpoch())
	if _, err := repository.ConfirmPlan(context.Background(), changed, digest); !errors.Is(err, firststartapp.ErrConflict) {
		t.Fatalf("changed confirmation=%v", err)
	}
	journal := provider.forCodex(t)
	journal.snapshots[0].Payload = append(journal.snapshots[0].Payload, ' ')
	if _, err := repository.Load(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("noncanonical=%v", err)
	}
}

func TestPF001PreparationCodecRejectsEveryEnvelopeViolation(t *testing.T) {
	t.Parallel()
	state := preparationForRepositoryTest(t, agentconfigdomain.AgentHostCodex)
	payload, _ := encodePreparation(state)
	operationID, _ := preparationOperationID(agentconfigdomain.AgentHostCodex)
	base := installjournal.Snapshot{OperationID: operationID.String(), Revision: 1,
		CapturedAt: preparationClock{}.Now(), Payload: payload}
	for name, mutate := range map[string]func(*installjournal.Snapshot){
		"operation":     func(s *installjournal.Snapshot) { s.OperationID = "foreign" },
		"revision zero": func(s *installjournal.Snapshot) { s.Revision = 0 },
		"revision high": func(s *installjournal.Snapshot) { s.Revision = 3 },
		"time":          func(s *installjournal.Snapshot) { s.CapturedAt = time.Time{} },
		"empty":         func(s *installjournal.Snapshot) { s.Payload = nil },
		"unknown": func(s *installjournal.Snapshot) {
			s.Payload = append(s.Payload[:len(s.Payload)-1], []byte(`,"unknown":true}`)...)
		},
		"trailing": func(s *installjournal.Snapshot) { s.Payload = append(s.Payload, []byte(`{}`)...) },
		"wrong host": func(s *installjournal.Snapshot) {
			s.Payload = bytesReplace(s.Payload, `"host":"codex"`, `"host":"claude"`)
		},
		"bad template": func(s *installjournal.Snapshot) {
			s.Payload = bytesReplace(s.Payload, `"template_digest":"`, `"template_digest":"bad`)
		},
		"bad operation": func(s *installjournal.Snapshot) {
			s.Payload = bytesReplace(s.Payload, state.OperationID().String(), "*")
		},
		"confirmed at revision one": func(s *installjournal.Snapshot) {
			digest, _ := install.BindPlan([]byte("plan"))
			confirmed, _ := state.WithConfirmedPlan(digest)
			s.Payload, _ = encodePreparation(confirmed)
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			candidate.Payload = append([]byte(nil), base.Payload...)
			mutate(&candidate)
			if _, err := decodePreparation(candidate, operationID, agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrIntegrity) {
				t.Fatalf("decode=%v", err)
			}
		})
	}
}

func TestPF001PreparationRepositoryMapsClosedJournalFailures(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]error{
		"deadline":   context.DeadlineExceeded,
		"conflict":   installjournal.ErrConflict,
		"corrupt":    installjournal.ErrCorrupt,
		"permission": installjournal.ErrUnsafePermission,
		"invalid":    installjournal.ErrInvalidSnapshot,
		"io":         installjournal.ErrIO,
	} {
		if err := mapPreparationJournalError(input); err == nil {
			t.Fatalf("%s mapped to nil", name)
		}
	}
	if _, err := preparationOperationID(agentconfigdomain.AgentHost("bad")); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("invalid host operation=%v", err)
	}
	repository, _ := NewPreparationRepository(newPreparationJournalProvider(), zeroPreparationClock{})
	operationID, _ := preparationOperationID(agentconfigdomain.AgentHostCodex)
	if _, err := repository.snapshot(operationID, 1, []byte(`{}`)); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("zero clock snapshot=%v", err)
	}
}

func preparationForRepositoryTest(t testing.TB, host agentconfigdomain.AgentHost) firststartapp.Preparation {
	t.Helper()
	template, _ := install.BindPlan([]byte("verified template"))
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	state, err := firststartapp.NewPreparation(host, template, operation, []string{
		"019f5f20-0000-7abc-8123-0123456789ab", "019f5f21-0000-7abc-8123-0123456789ab",
		"019f5f22-0000-7abc-8123-0123456789ab", "019f5f23-0000-7abc-8123-0123456789ab",
		"019f5f24-0000-7abc-8123-0123456789ab", "019f5f25-0000-7abc-8123-0123456789ab",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

type preparationClock struct{}

func (preparationClock) Now() time.Time {
	return time.Date(2026, 7, 14, 12, 0, 0, 123456000, time.UTC)
}

type zeroPreparationClock struct{}

func (zeroPreparationClock) Now() time.Time { return time.Time{} }

type preparationJournalProvider struct {
	mu       sync.Mutex
	journals map[string]*preparationMemoryJournal
}

func newPreparationJournalProvider() *preparationJournalProvider {
	return &preparationJournalProvider{journals: make(map[string]*preparationMemoryJournal)}
}

func (p *preparationJournalProvider) JournalFor(_ context.Context, operationID install.OperationID) (installjournal.Journal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	journal := p.journals[operationID.String()]
	if journal == nil {
		journal = &preparationMemoryJournal{}
		p.journals[operationID.String()] = journal
	}
	return journal, nil
}

func (p *preparationJournalProvider) forCodex(t testing.TB) *preparationMemoryJournal {
	t.Helper()
	operationID, err := preparationOperationID(agentconfigdomain.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := p.JournalFor(context.Background(), operationID)
	return journal.(*preparationMemoryJournal)
}

type preparationMemoryJournal struct {
	mu                   sync.Mutex
	snapshots            []installjournal.Snapshot
	appendAfterCommitErr error
	confirmations        int
}

func (j *preparationMemoryJournal) Append(_ context.Context, expected uint64, snapshot installjournal.Snapshot) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if uint64(len(j.snapshots)) != expected {
		return installjournal.ErrConflict
	}
	copyOf := snapshot
	copyOf.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshots = append(j.snapshots, copyOf)
	err := j.appendAfterCommitErr
	j.appendAfterCommitErr = nil
	return err
}

func (j *preparationMemoryJournal) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.snapshots) == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	copyOf := j.snapshots[len(j.snapshots)-1]
	copyOf.Payload = append([]byte(nil), copyOf.Payload...)
	return copyOf, nil
}

func (j *preparationMemoryJournal) ConfirmDurable(_ context.Context, operationID string, revision uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.snapshots) == 0 || j.snapshots[len(j.snapshots)-1].OperationID != operationID ||
		j.snapshots[len(j.snapshots)-1].Revision != revision {
		return installjournal.ErrConflict
	}
	j.confirmations++
	return nil
}

func bytesReplace(source []byte, old, replacement string) []byte {
	return []byte(stringReplace(string(source), old, replacement))
}

func stringReplace(source, old, replacement string) string {
	for index := 0; index+len(old) <= len(source); index++ {
		if source[index:index+len(old)] == old {
			return source[:index] + replacement + source[index+len(old):]
		}
	}
	return source
}
