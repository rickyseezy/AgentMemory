package bootstrapresolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ProtectedBootstrapResolverPublishesReplaysAdvancesAndResolves(t *testing.T) {
	t.Parallel()
	journals := &memoryProvider{journals: make(map[string]*memoryJournal)}
	canonical := []byte("canonical plan")
	planDigest, _ := install.BindPlan(canonical)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan := fakePlan{digest: planDigest, operation: operationID,
		installation: "019f5f20-1234-7abc-8123-0123456789ab",
		host:         agentconfigdomain.AgentHostCodex, canonical: canonical}
	operations := &fakeOperations{operation: operationID, plan: planDigest}
	repository, err := New(journals, fakePlans{plan: plan}, operations, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewBinding(1, plan.host, plan.installation, operationID, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence() != 1 || first.Host() != plan.host || first.InstallationID() != plan.installation ||
		first.OperationID() != operationID || !first.PlanDigest().Equal(planDigest) {
		t.Fatal("binding accessors lost authority")
	}
	if err := repository.Publish(context.Background(), install.Digest{}, first); err != nil {
		t.Fatal(err)
	}
	if err := repository.Publish(context.Background(), install.Digest{}, first); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	resolved, err := repository.ResolveBootstrap(context.Background(), plan.host)
	if err != nil || !resolved.Valid() || resolved.InstallationID() != plan.installation ||
		resolved.OperationID() != operationID || string(resolved.CanonicalPlan()) != string(canonical) {
		t.Fatalf("resolved=%+v error=%v", resolved, err)
	}
	secondOperation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	secondPlan := []byte("successor plan")
	secondDigest, _ := install.BindPlan(secondPlan)
	second, _ := NewBinding(2, plan.host, plan.installation, secondOperation, secondDigest)
	if err := repository.Publish(context.Background(), first.Digest(), second); err != nil {
		t.Fatal(err)
	}
	if err := repository.Publish(context.Background(), first.Digest(), first); !errors.Is(err, mcpbootstrapapp.ErrBootstrapConflict) {
		t.Fatalf("stale publish error=%v", err)
	}
	journal := journals.journalForHost(t, plan.host)
	if journal.snapshot.Revision != 2 || journal.confirms != 2 {
		t.Fatalf("revision=%d confirms=%d", journal.snapshot.Revision, journal.confirms)
	}
}

func TestPF001ProtectedBootstrapResolverRejectsMissingTamperAndSubstitution(t *testing.T) {
	t.Parallel()
	journals := &memoryProvider{journals: make(map[string]*memoryJournal)}
	canonical := []byte("canonical plan")
	digest, _ := install.BindPlan(canonical)
	operation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan := fakePlan{digest: digest, operation: operation,
		installation: "019f5f20-1234-7abc-8123-0123456789ab",
		host:         agentconfigdomain.AgentHostCodex, canonical: canonical}
	repository, _ := New(journals, fakePlans{plan: plan}, &fakeOperations{operation: operation, plan: digest}, fixedClock{})
	if _, err := repository.ResolveBootstrap(context.Background(), plan.host); !errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	binding, _ := NewBinding(1, plan.host, plan.installation, operation, digest)
	if err := repository.Publish(context.Background(), install.Digest{}, binding); err != nil {
		t.Fatal(err)
	}
	journal := journals.journalForHost(t, plan.host)
	journal.snapshot.Payload = append(journal.snapshot.Payload, '\n')
	if _, err := repository.ResolveBootstrap(context.Background(), plan.host); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("tamper error=%v", err)
	}
	journal.snapshot.Payload, _ = encodeBinding(binding)
	repository.plans = fakePlans{plan: fakePlan{digest: digest, operation: operation,
		installation: plan.installation, host: agentconfigdomain.AgentHostClaude, canonical: canonical}}
	if _, err := repository.ResolveBootstrap(context.Background(), plan.host); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("host substitution error=%v", err)
	}
	repository.plans = fakePlans{plan: plan}
	repository.operations = &fakeOperations{err: errors.New("missing")}
	if _, err := repository.ResolveBootstrap(context.Background(), plan.host); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("operation substitution error=%v", err)
	}
}

func TestPF001ProtectedBootstrapResolverRejectsInvalidCompositionAndCAS(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil, nil, nil); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("composition error=%v", err)
	}
	operation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	digest, _ := install.BindPlan([]byte("plan"))
	if _, err := NewBinding(0, agentconfigdomain.AgentHostCodex,
		"019f5f20-1234-7abc-8123-0123456789ab", operation, digest); err == nil {
		t.Fatal("zero sequence accepted")
	}
	journals := &memoryProvider{journals: make(map[string]*memoryJournal)}
	repository, _ := New(journals, fakePlans{}, &fakeOperations{}, fixedClock{})
	binding, _ := NewBinding(2, agentconfigdomain.AgentHostCodex,
		"019f5f20-1234-7abc-8123-0123456789ab", operation, digest)
	if err := repository.Publish(context.Background(), install.Digest{}, binding); !errors.Is(err, mcpbootstrapapp.ErrBootstrapConflict) {
		t.Fatalf("non-first error=%v", err)
	}
	if _, err := repository.ResolveBootstrap(context.Background(), agentconfigdomain.AgentHost("unknown")); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("unknown host error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := repository.Publish(cancelled, install.Digest{}, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
}

func TestPF001ProtectedBootstrapResolverMapsJournalFailuresWithoutLeakingDetails(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input error
		want  error
	}{
		{input: nil, want: nil},
		{input: installjournal.ErrNotFound, want: mcpbootstrapapp.ErrBootstrapNotFound},
		{input: installjournal.ErrConflict, want: mcpbootstrapapp.ErrBootstrapConflict},
		{input: installjournal.ErrCorrupt, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{input: installjournal.ErrUnsafePermission, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{input: installjournal.ErrInvalidSnapshot, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{input: installjournal.ErrIO, want: mcpbootstrapapp.ErrBootstrapUnavailable},
	} {
		mapped := mapJournalError(test.input)
		if test.want == nil && mapped != nil || test.want != nil && !errors.Is(mapped, test.want) {
			t.Fatalf("mapJournalError(%v)=%v want %v", test.input, mapped, test.want)
		}
	}
	if _, err := pointerOperationID(agentconfigdomain.AgentHost("invalid")); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid pointer host error=%v", err)
	}
}

type fakePlan struct {
	digest       install.PlanDigest
	operation    install.OperationID
	installation string
	host         agentconfigdomain.AgentHost
	canonical    []byte
}

func (p fakePlan) Digest() install.PlanDigest             { return p.digest }
func (p fakePlan) OperationID() install.OperationID       { return p.operation }
func (p fakePlan) InstallationID() string                 { return p.installation }
func (p fakePlan) AgentHost() agentconfigdomain.AgentHost { return p.host }
func (p fakePlan) CanonicalBytes() []byte                 { return append([]byte(nil), p.canonical...) }

type fakePlans struct {
	plan PlanAuthority
	err  error
}

func (p fakePlans) LoadPlan(context.Context, install.PlanDigest) (PlanAuthority, error) {
	return p.plan, p.err
}

type fakeOperations struct {
	operation install.OperationID
	plan      install.PlanDigest
	err       error
}

func (o *fakeOperations) VerifyOperation(_ context.Context, operation install.OperationID, plan install.PlanDigest) error {
	if o.err != nil {
		return o.err
	}
	if operation != o.operation || !plan.Equal(o.plan) {
		return errors.New("substituted")
	}
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC) }

type memoryProvider struct{ journals map[string]*memoryJournal }

func (p *memoryProvider) JournalFor(_ context.Context, operation install.OperationID) (installjournal.Journal, error) {
	journal := p.journals[operation.String()]
	if journal == nil {
		journal = &memoryJournal{}
		p.journals[operation.String()] = journal
	}
	return journal, nil
}

func (p *memoryProvider) journalForHost(t testing.TB, host agentconfigdomain.AgentHost) *memoryJournal {
	t.Helper()
	id, err := pointerOperationID(host)
	if err != nil {
		t.Fatal(err)
	}
	return p.journals[id.String()]
}

type memoryJournal struct {
	snapshot installjournal.Snapshot
	confirms int
}

func (j *memoryJournal) Append(_ context.Context, expected uint64, snapshot installjournal.Snapshot) error {
	if j.snapshot.Revision != expected {
		return installjournal.ErrConflict
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshot = snapshot
	return nil
}

func (j *memoryJournal) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	if j.snapshot.Revision == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	result := j.snapshot
	result.Payload = append([]byte(nil), result.Payload...)
	return result, nil
}

func (j *memoryJournal) ConfirmDurable(_ context.Context, operation string, revision uint64) error {
	if operation != j.snapshot.OperationID || revision != j.snapshot.Revision {
		return installjournal.ErrConflict
	}
	j.confirms++
	return nil
}
