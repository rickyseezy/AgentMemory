package agentconfigapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	testInstallationID = "018f0c74-7b5d-7cc1-8a2c-4f1ae7c16a01"
	testEntryID        = "018f0c74-7b5d-7cc1-9a2c-4f1ae7c16a02"
)

type fakeStore struct {
	snapshot      agentconfig.Snapshot
	applyReceipt  agentconfig.ApplyReceipt
	restoreResult agentconfig.RestoreReceipt
	detectErr     error
	readErr       error
	applyErr      error
	restoreErr    error
	applyCalls    int
	restoreCalls  int
}

func (f *fakeStore) Detect(context.Context, agentconfig.ConfigLocation) (agentconfig.Detection, error) {
	if f.detectErr != nil {
		return agentconfig.Detection{}, f.detectErr
	}
	return agentconfig.NewDetection(f.snapshot.Exists()), nil
}

func (f *fakeStore) Read(context.Context, agentconfig.ConfigLocation) (agentconfig.Snapshot, error) {
	if f.readErr != nil {
		return agentconfig.Snapshot{}, f.readErr
	}
	if !f.snapshot.Exists() {
		return agentconfig.Snapshot{}, agentconfig.ErrNotFound
	}
	return f.snapshot, nil
}

func (f *fakeStore) ApplyAtomic(_ context.Context, _ agentconfig.ConfigLocation, plan domain.MergePlan) (agentconfig.ApplyReceipt, error) {
	f.applyCalls++
	if f.applyErr != nil {
		return agentconfig.ApplyReceipt{}, f.applyErr
	}
	f.snapshot = mustSnapshot(true, plan.AfterContent())
	return f.applyReceipt, nil
}

func (f *fakeStore) RestoreBackup(_ context.Context, _ agentconfig.ConfigLocation, receipt agentconfig.ApplyReceipt) (agentconfig.RestoreReceipt, error) {
	f.restoreCalls++
	if f.restoreErr != nil {
		return agentconfig.RestoreReceipt{}, f.restoreErr
	}
	if receipt.OriginalExisted() {
		f.snapshot = mustSnapshot(true, []byte(`{"future":true}`))
	} else {
		f.snapshot = mustSnapshot(false, nil)
	}
	return f.restoreResult, nil
}

type fakeVerifier struct {
	err   error
	calls int
}

type fakeDocumentPolicy struct {
	hosts       map[domain.AgentHost]bool
	validateErr error
	verifyErr   error
	validate    int
	plans       int
	verifies    int
}

func (f *fakeDocumentPolicy) Supports(host domain.AgentHost) bool { return f.hosts[host] }

func (f *fakeDocumentPolicy) Validate([]byte) error {
	f.validate++
	return f.validateErr
}

func (f *fakeDocumentPolicy) PlanMerge(
	content []byte,
	existed bool,
	target domain.Target,
	_ domain.Digest,
) (domain.MergePlan, error) {
	f.plans++
	return domain.NewMergePlan(
		domain.MergeActionNoChange,
		existed,
		content,
		content,
		domain.DigestBytes([]byte("managed Codex block")),
		target,
	)
}

func (f *fakeDocumentPolicy) VerifyManagedEntry([]byte, domain.Target) error {
	f.verifies++
	return f.verifyErr
}

func (f *fakeVerifier) Verify(context.Context, domain.Target) error {
	f.calls++
	return f.err
}

func TestPF001ApplicationRoutesCodexThroughInjectedSyntaxPolicy(t *testing.T) {
	t.Parallel()
	digest := domain.DigestBytes([]byte("signed launcher"))
	target, err := domain.NewTargetForAgent(
		domain.AgentHostCodex,
		testInstallationID,
		testEntryID,
		"/opt/agentmemory/bin/agentmemory",
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustSnapshot(true, []byte("model = \"gpt-5\"\n"))
	store := &fakeStore{snapshot: snapshot}
	verifier := &fakeVerifier{}
	policy := &fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{domain.AgentHostCodex: true}}
	application, err := New(store, verifier, policy)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := agentconfig.NewConfigLocation("/home/user/.codex/config.toml")
	result, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if result.Changed() || policy.validate != 1 || policy.plans != 1 || policy.verifies != 1 || verifier.calls != 1 {
		t.Fatalf("Codex routing changed=%t validate=%d plans=%d verifies=%d invocation=%d",
			result.Changed(), policy.validate, policy.plans, policy.verifies, verifier.calls)
	}
}

func TestPF001ApplicationRejectsMissingOrAmbiguousSyntaxPolicies(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	verifier := &fakeVerifier{}
	typedNil := (*fakeDocumentPolicy)(nil)
	tests := []struct {
		name     string
		policies []agentconfig.DocumentPolicy
	}{
		{name: "typed nil", policies: []agentconfig.DocumentPolicy{typedNil}},
		{name: "no host", policies: []agentconfig.DocumentPolicy{&fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{}}}},
		{name: "generic override", policies: []agentconfig.DocumentPolicy{&fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{domain.AgentHostGeneric: true}}}},
		{name: "multiple hosts", policies: []agentconfig.DocumentPolicy{&fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{
			domain.AgentHostCodex: true, domain.AgentHostGemini: true,
		}}}},
		{name: "duplicate Codex", policies: []agentconfig.DocumentPolicy{
			&fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{domain.AgentHostCodex: true}},
			&fakeDocumentPolicy{hosts: map[domain.AgentHost]bool{domain.AgentHostCodex: true}},
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(store, verifier, test.policies...); !errors.Is(err, ErrInvalidDependency) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}

	application, err := New(store, verifier)
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTargetForAgent(
		domain.AgentHostCodex,
		testInstallationID,
		testEntryID,
		"/opt/agentmemory",
		domain.DigestBytes([]byte("launcher")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.PlanMerge(nil, false, target, domain.Digest{}); !errors.Is(err, agentconfig.ErrUnsupportedPlatform) {
		t.Fatalf("missing Codex policy error = %v", err)
	}
}

func TestPF001MergeAppliesVerifiesAndReturnsReceipt(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	store := &fakeStore{snapshot: mustSnapshot(true, []byte(`{"future":true}`))}
	plan, err := domain.PlanMerge(store.snapshot.Content(), true, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	store.applyReceipt = mustApplyReceipt(
		true, plan.BeforeDigest(), plan.AfterDigest(), plan.ManagedEntryDigest(),
		"/private/backups/config-"+plan.BeforeDigest().String()+".json", plan.BeforeDigest(),
	)
	verifier := &fakeVerifier{}
	application, err := New(store, verifier)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	result, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if !result.Changed() || !result.Receipt().AfterDigest().Equal(plan.AfterDigest()) || store.applyCalls != 1 || verifier.calls != 1 {
		t.Fatalf("Merge() result/calls are incomplete: changed=%t apply=%d verify=%d", result.Changed(), store.applyCalls, verifier.calls)
	}
	if !result.Plan().AfterDigest().Equal(plan.AfterDigest()) {
		t.Fatal("MergeResult.Plan() lost the merge plan")
	}
}

func TestPF001MergeCompensatesInvocationFailure(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	store := &fakeStore{snapshot: mustSnapshot(false, nil)}
	plan, err := domain.PlanMerge(nil, false, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	store.applyReceipt = mustApplyReceipt(false, domain.Digest{}, plan.AfterDigest(), plan.ManagedEntryDigest(), "", domain.Digest{})
	store.restoreResult = mustRestoreReceipt(false, domain.Digest{})
	verifyErr := errors.New("bounded verifier failure")
	application, _ := New(store, &fakeVerifier{err: verifyErr})
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	_, err = application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if !errors.Is(err, ErrInvocationVerification) || !errors.Is(err, verifyErr) || store.restoreCalls != 1 || store.snapshot.Exists() {
		t.Fatalf("Merge() error=%v restoreCalls=%d exists=%t", err, store.restoreCalls, store.snapshot.Exists())
	}
}

func TestPF001MergeReportsCompensationConflictWithoutOverwriting(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	store := &fakeStore{
		snapshot:   mustSnapshot(false, nil),
		restoreErr: agentconfig.ErrConflict,
	}
	plan, _ := domain.PlanMerge(nil, false, target, domain.Digest{})
	store.applyReceipt = mustApplyReceipt(false, domain.Digest{}, plan.AfterDigest(), plan.ManagedEntryDigest(), "", domain.Digest{})
	application, _ := New(store, &fakeVerifier{err: errors.New("verification failed")})
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	_, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if !errors.Is(err, ErrInvocationVerification) || !errors.Is(err, ErrCompensationFailed) || !errors.Is(err, agentconfig.ErrConflict) {
		t.Fatalf("Merge() error = %v, want verification and compensation conflict", err)
	}
}

func TestPF001MergeRejectsUnprovenCompensationReceipt(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	store := &fakeStore{snapshot: mustSnapshot(false, nil)}
	plan, _ := domain.PlanMerge(nil, false, target, domain.Digest{})
	store.applyReceipt = mustApplyReceipt(false, domain.Digest{}, plan.AfterDigest(), plan.ManagedEntryDigest(), "", domain.Digest{})
	application, _ := New(store, &fakeVerifier{err: errors.New("verification failed")})
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	_, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if !errors.Is(err, ErrInvocationVerification) || !errors.Is(err, ErrCompensationFailed) || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("Merge(unproven restore) error = %v", err)
	}
}

func TestPF001MergeNoChangeSkipsFilesystemMutation(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	first, _ := domain.PlanMerge(nil, false, target, domain.Digest{})
	store := &fakeStore{snapshot: mustSnapshot(true, first.AfterContent())}
	verifier := &fakeVerifier{}
	application, _ := New(store, verifier)
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	result, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target})
	if err != nil || result.Changed() || store.applyCalls != 0 || verifier.calls != 1 {
		t.Fatalf("Merge() result error=%v changed=%t apply=%d verify=%d", err, result.Changed(), store.applyCalls, verifier.calls)
	}
}

func TestPF001ApplicationRejectsMissingOrTypedNilDependencies(t *testing.T) {
	t.Parallel()
	var typedNil *fakeStore
	for _, test := range []struct {
		store    agentconfig.Store
		verifier agentconfig.InvocationVerifier
	}{
		{},
		{store: typedNil, verifier: &fakeVerifier{}},
		{store: &fakeStore{}},
	} {
		if _, err := New(test.store, test.verifier); !errors.Is(err, ErrInvalidDependency) {
			t.Fatalf("New() error = %v, want ErrInvalidDependency", err)
		}
	}
}

func TestPF001MergeStopsOnCancellationDetectionAndInvalidDocument(t *testing.T) {
	t.Parallel()
	target := testTarget(t)
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	application, _ := New(&fakeStore{}, &fakeVerifier{})
	if _, err := application.Merge(ctx, MergeRequest{Location: location, Target: target}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Merge(cancelled) error=%v", err)
	}
	if _, err := application.Merge(context.Background(), MergeRequest{Target: target}); !errors.Is(err, agentconfig.ErrInvalidArgument) {
		t.Fatalf("Merge(invalid location) error=%v", err)
	}
	detectErr := errors.New("detection failure")
	application, _ = New(&fakeStore{detectErr: detectErr}, &fakeVerifier{})
	if _, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target}); !errors.Is(err, detectErr) {
		t.Fatalf("Merge(detect failure) error=%v", err)
	}
	application, _ = New(&fakeStore{snapshot: mustSnapshot(true, []byte("not json"))}, &fakeVerifier{})
	if _, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target}); !errors.Is(err, domain.ErrInvalidDocument) {
		t.Fatalf("Merge(invalid document) error=%v", err)
	}
	readErr := errors.New("bounded read failure")
	application, _ = New(&fakeStore{snapshot: mustSnapshot(true, []byte(`{}`)), readErr: readErr}, &fakeVerifier{})
	if _, err := application.Merge(context.Background(), MergeRequest{Location: location, Target: target}); !errors.Is(err, readErr) {
		t.Fatalf("Merge(read failure) error=%v", err)
	}
}

func TestPF001ApplicationRejectsUnverifiedInvocationAndExercisesClosedDependencyKinds(t *testing.T) {
	t.Parallel()

	if nilInterface(1) || !nilInterface(nil) {
		t.Fatal("dependency nil detection changed")
	}
	target := testTarget(t)
	location, _ := agentconfig.NewConfigLocation("/home/user/.config/agent/config.json")
	verifier := &fakeVerifier{}
	application, _ := New(&fakeStore{snapshot: mustSnapshot(true, []byte(`{"mcpServers":{}}`))}, verifier)
	if err := application.VerifyInvocation(context.Background(), location, target); err == nil || verifier.calls != 0 {
		t.Fatalf("VerifyInvocation(unowned config) error=%v verifierCalls=%d", err, verifier.calls)
	}

	plan, err := domain.PlanMerge([]byte(`{"future":true}`), true, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	restored := mustRestoreReceipt(true, plan.BeforeDigest())
	if !restoreMatchesPlan(restored, plan) {
		t.Fatal("exact original-file restore receipt did not match its merge plan")
	}
}

func testTarget(t *testing.T) domain.Target {
	t.Helper()
	target, err := domain.NewTarget(testInstallationID, testEntryID, "/opt/agentmemory/bin/agentmemory", domain.DigestBytes([]byte("signed launcher")))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func mustSnapshot(exists bool, content []byte) agentconfig.Snapshot {
	snapshot, err := agentconfig.NewSnapshot(exists, content)
	if err != nil {
		panic(err)
	}
	return snapshot
}

func mustApplyReceipt(
	existed bool,
	before domain.Digest,
	after domain.Digest,
	entry domain.Digest,
	backupPath string,
	backup domain.Digest,
) agentconfig.ApplyReceipt {
	receipt, err := agentconfig.NewApplyReceipt(true, existed, before, after, entry, backupPath, backup)
	if err != nil {
		panic(err)
	}
	return receipt
}

func mustRestoreReceipt(exists bool, digest domain.Digest) agentconfig.RestoreReceipt {
	receipt, err := agentconfig.NewRestoreReceipt(exists, digest)
	if err != nil {
		panic(err)
	}
	return receipt
}
