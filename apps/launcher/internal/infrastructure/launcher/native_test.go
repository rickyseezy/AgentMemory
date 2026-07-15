package launcher

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installworker"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001NativeRootsAreAbsolutePurposeSeparatedAndDeterministic(t *testing.T) {
	t.Parallel()
	roots, err := defaultNativeRoots()
	if err != nil || !roots.valid() {
		t.Fatalf("defaultNativeRoots()=%+v,%v", roots, err)
	}
	if roots.OperationState == roots.BootstrapPointer || roots.OperationState == roots.SetupDecisions ||
		roots.BootstrapPointer == roots.SetupDecisions || roots.PreparationState == roots.OperationState ||
		roots.PreparationState == roots.BootstrapPointer || roots.PreparationState == roots.SetupDecisions ||
		roots.RuntimeState == roots.OperationState || roots.ReleaseAnchorState == roots.OperationState ||
		roots.RuntimeConsentKeyState == roots.RuntimeState || roots.RuntimeConsentKeyState == roots.SetupDecisions ||
		roots.RuntimeConsentReceiptState == roots.RuntimeState ||
		roots.RuntimeConsentReceiptState == roots.RuntimeConsentKeyState ||
		roots.RuntimeReplayState == roots.RuntimeState ||
		roots.RuntimeReplayState == roots.RuntimeConsentReceiptState ||
		roots.RuntimeOwnershipState == roots.RuntimeState ||
		roots.RuntimeRemovalState == roots.RuntimeState ||
		roots.RuntimeRemovalState == roots.RuntimeOwnershipState ||
		roots.ReleaseAnchorState == roots.RuntimeState || roots.RuntimeCatalogAnchorState == roots.RuntimeState ||
		roots.RuntimeCatalogAnchorState == roots.ReleaseAnchorState {
		t.Fatalf("default roots are not purpose separated: %+v", roots)
	}
	root := t.TempDir()
	valid := nativeTestRoots(root)
	if !valid.valid() {
		t.Fatalf("valid roots rejected: %+v", valid)
	}
	missingConsent := valid
	missingConsent.RuntimeConsentKeyState = ""
	missingConsentReceipts := valid
	missingConsentReceipts.RuntimeConsentReceiptState = ""
	missingReplay := valid
	missingReplay.RuntimeReplayState = ""
	missingContinuation := valid
	missingContinuation.RebootContinuationState = ""
	missingOwnership := valid
	missingOwnership.RuntimeOwnershipState = ""
	missingRemoval := valid
	missingRemoval.RuntimeRemovalState = ""
	for name, candidate := range map[string]NativeRoots{
		"empty": {},
		"relative": {OperationState: "relative", BootstrapPointer: valid.BootstrapPointer, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"unclean": {OperationState: root + "/state/../other", BootstrapPointer: valid.BootstrapPointer, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"duplicate": {OperationState: valid.OperationState, BootstrapPointer: valid.OperationState, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.OperationState, RuntimeState: valid.OperationState, ReleaseAnchorState: valid.OperationState, CanonicalPlans: valid.CanonicalPlans},
		"missing preparation": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"missing runtime": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"missing runtime ownership":        missingOwnership,
		"missing runtime removal":          missingRemoval,
		"missing runtime consent":          missingConsent,
		"missing runtime consent receipts": missingConsentReceipts,
		"missing runtime replay":           missingReplay,
		"missing reboot continuation":      missingContinuation,
		"missing release anchor": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, CanonicalPlans: valid.CanonicalPlans},
		"missing runtime catalog anchor": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState,
			ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"missing plan": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState},
	} {
		if candidate.valid() {
			t.Fatalf("%s roots accepted: %+v", name, candidate)
		}
	}
}

func TestPF001NativeRootsFailClosedWithoutAnOSConfigurationAuthority(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	if roots, err := defaultNativeRoots(); err == nil || roots != (NativeRoots{}) {
		t.Fatalf("defaultNativeRoots() = (%+v, %v)", roots, err)
	}
}

func TestPF001NativeCompositionUsesPurposeSeparatedJournalAuthoritiesAndResolvesMissing(t *testing.T) {
	t.Parallel()
	roots := nativeTestRoots(t.TempDir())
	var observed []string
	var mu sync.Mutex
	journalFactory := func(locator *bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		mu.Lock()
		observed = append(observed, locator.Root())
		mu.Unlock()
		return nativeMissingJournalProvider{}, nil
	}
	composition, err := composeNative(context.Background(), roots, journalFactory, pendingReadySurface{})
	if err != nil || composition.factory == nil || composition.resources == nil || composition.preparations == nil ||
		composition.plans == nil || composition.operations == nil || composition.runtimeState == nil ||
		composition.runtimeOwnership == nil || composition.runtimeRemoval == nil ||
		composition.consentSigner == nil || composition.consentBroker == nil || composition.removalConsentBroker == nil ||
		composition.consentRepository == nil ||
		composition.replayJournals == nil ||
		composition.releaseAnchor == nil || composition.runtimeCatalogAnchor == nil || composition.artifacts == nil || composition.resourceState == nil ||
		composition.capacityState == nil || composition.artifactStore == nil || composition.activations == nil ||
		composition.hostPointers == nil || composition.installLock == nil {
		t.Fatalf("composeNative()=%+v,%v", composition, err)
	}
	if len(observed) != 14 || observed[0] != roots.OperationState ||
		observed[1] != roots.BootstrapPointer || observed[2] != roots.SetupDecisions ||
		observed[3] != roots.PreparationState || observed[4] != roots.RuntimeState ||
		observed[5] != roots.RuntimeOwnershipState || observed[6] != roots.RuntimeRemovalState ||
		observed[7] != roots.RuntimeConsentReceiptState || observed[8] != roots.RuntimeReplayState ||
		observed[9] != roots.ReleaseAnchorState || observed[10] != roots.RuntimeCatalogAnchorState ||
		observed[11] != roots.ArtifactState || observed[12] != roots.ResourceState ||
		observed[13] != roots.ActiveReleaseState {
		t.Fatalf("journal roots=%q", observed)
	}
	if _, err := composition.factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) {
		t.Fatalf("missing protected pointer error=%v", err)
	}
	if err := composition.resources.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := composition.resources.Close(context.Background()); err != nil {
		t.Fatalf("idempotent resource close error=%v", err)
	}
}

func TestPF001NativeFactoryOwnsProductionResourcesOnEveryExit(t *testing.T) {
	t.Parallel()
	newFactory := func(production nativeProductionComposer) *NativeFactory {
		return &NativeFactory{
			roots: func() (NativeRoots, error) { return nativeTestRoots(t.TempDir()), nil },
			journals: func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			},
			ready: pendingReadySurface{}, production: production,
		}
	}
	if runner, err := newFactory(func(context.Context, *nativeComposition) (nativeProductionFirstStart, error) {
		return nativeProductionFirstStart{}, errors.New("private production failure")
	}).BuildMCP(t.Context(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("failed production runner=%T error=%v", runner, err)
	}
	production := func(context.Context, *nativeComposition) (nativeProductionFirstStart, error) {
		return nativeProductionFirstStart{
			Factory: &Factory{}, Supervisor: &installworker.Supervisor{}, Release: &nativeReleaseAuthority{},
		}, nil
	}
	if runner, err := newFactory(production).BuildMCP(t.Context(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid production factory runner=%T error=%v", runner, err)
	}
	if runner, err := newFactory(func(
		ctx context.Context,
		composition *nativeComposition,
	) (nativeProductionFirstStart, error) {
		if err := composition.resources.Close(context.WithoutCancel(ctx)); err != nil {
			return nativeProductionFirstStart{}, err
		}
		return production(ctx, composition)
	}).BuildMCP(t.Context(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("closed composition runner=%T error=%v", runner, err)
	}
}

func TestPF001NativeCompositionCreatesOperationScopedDurableReplayAuthority(t *testing.T) {
	t.Parallel()
	composition, err := composeNative(
		t.Context(), nativeTestRoots(t.TempDir()),
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = composition.resources.Close(context.Background()) })
	operation, err := install.NewOperationID("019f6001-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := composition.newRuntimeReplayLedger(operation)
	if err != nil || ledger == nil {
		t.Fatalf("newRuntimeReplayLedger()=%v,%v", ledger, err)
	}
	for _, candidate := range []*nativeComposition{nil, {}} {
		if ledger, err := candidate.newRuntimeReplayLedger(operation); ledger != nil ||
			!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("incomplete replay composition accepted: %v,%v", ledger, err)
		}
	}
	if ledger, err := composition.newRuntimeReplayLedger(install.OperationID{}); ledger != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("zero operation replay accepted: %v,%v", ledger, err)
	}
}

func TestPF001NativeCompositionRejectsIncompleteAuthoritiesAtEveryBoundary(t *testing.T) {
	t.Parallel()
	roots := nativeTestRoots(t.TempDir())
	for name, run := range map[string]func() error{
		"nil context": func() error {
			//lint:ignore SA1012 Deliberate nil-context composition attack.
			//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
			_, err := composeNative(nil, roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, pendingReadySurface{})
			return err
		},
		"invalid roots": func() error {
			_, err := composeNative(context.Background(), NativeRoots{}, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, pendingReadySurface{})
			return err
		},
		"nil journal factory": func() error {
			_, err := composeNative(context.Background(), roots, nil, pendingReadySurface{})
			return err
		},
		"nil Ready": func() error {
			_, err := composeNative(context.Background(), roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, (*readyStub)(nil))
			return err
		},
	} {
		if err := run(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for failAt := 1; failAt <= 14; failAt++ {
		for _, returnNil := range []bool{false, true} {
			calls := 0
			_, err := composeNative(context.Background(), roots,
				func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
					calls++
					if calls == failAt {
						if returnNil {
							return nil, nil
						}
						return nil, errors.New("private journal failure")
					}
					return nativeMissingJournalProvider{}, nil
				}, pendingReadySurface{})
			if !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) || calls != failAt {
				t.Fatalf("failAt=%d nil=%t calls=%d error=%v", failAt, returnNil, calls, err)
			}
		}
	}
	calls := 0
	_, err := composeNative(context.Background(), roots,
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			calls++
			if calls == 10 {
				return nativePlainJournalProvider{}, nil
			}
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{})
	if err == nil || calls != 14 {
		t.Fatalf("ordinary release-anchor journal accepted: calls=%d error=%v", calls, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = composeNative(cancelled, roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		return nativeMissingJournalProvider{}, nil
	}, pendingReadySurface{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled composition error=%v", err)
	}
}

func TestPF001NativeFactoryBuildMapsOnlyRealProtectedStateFailures(t *testing.T) {
	t.Parallel()
	if factory := NewNativeFactory(); factory == nil {
		t.Fatal("NewNativeFactory() returned nil")
	}
	roots := nativeTestRoots(t.TempDir())
	factory := &NativeFactory{
		roots: func() (NativeRoots, error) { return roots, nil },
		journals: func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		},
		ready: pendingReadySurface{},
	}
	if _, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) {
		t.Fatalf("BuildMCP(missing) error=%v", err)
	}
	for name, run := range map[string]func() error{
		"nil factory": func() error {
			var candidate *NativeFactory
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil context": func() error {
			//lint:ignore SA1012 Deliberate nil-context boundary attack.
			//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
			_, err := factory.BuildMCP(nil, agentconfigdomain.AgentHostCodex)
			return err
		},
		"invalid host": func() error {
			_, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHost("invalid"))
			return err
		},
		"nil roots": func() error {
			candidate := *factory
			candidate.roots = nil
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil journals": func() error {
			candidate := *factory
			candidate.journals = nil
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil Ready": func() error {
			candidate := *factory
			candidate.ready = (*readyStub)(nil)
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"root failure": func() error {
			candidate := *factory
			candidate.roots = func() (NativeRoots, error) { return NativeRoots{}, errors.New("private") }
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"invalid resolved roots": func() error {
			candidate := *factory
			candidate.roots = func() (NativeRoots, error) { return NativeRoots{}, nil }
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
	} {
		if err := run(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.BuildMCP(cancelled, agentconfigdomain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled factory error=%v", err)
	}
	compositionFailure := *factory
	compositionFailure.journals = func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		return nil, errors.New("private")
	}
	if _, err := compositionFailure.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("composition failure error=%v", err)
	}
}

func TestPF001NativeFactoryResumeRejectsInvalidAndMissingContinuationAuthority(t *testing.T) {
	t.Parallel()
	var absent *NativeFactory
	if err := absent.ResumeInstallation(t.Context(), strings.Repeat("a", 64)); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("nil resume factory error = %v", err)
	}
	factory := &NativeFactory{
		roots: func() (NativeRoots, error) { return nativeTestRoots(t.TempDir()), nil },
		journals: func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		},
		ready: pendingReadySurface{},
		production: func(context.Context, *nativeComposition) (nativeProductionFirstStart, error) {
			return nativeProductionFirstStart{}, errors.New("must not reach missing-record production")
		},
	}
	for _, token := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if err := factory.ResumeInstallation(t.Context(), token); !errors.Is(err, ErrResumeIntegrity) {
			t.Fatalf("invalid token error = %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := factory.ResumeInstallation(cancelled, strings.Repeat("a", 64)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resume error = %v", err)
	}
	rootFailure := *factory
	rootFailure.roots = func() (NativeRoots, error) { return NativeRoots{}, errors.New("private root failure") }
	if err := rootFailure.ResumeInstallation(t.Context(), strings.Repeat("a", 64)); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("root failure error = %v", err)
	}
	compositionFailure := *factory
	compositionFailure.journals = func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		return nil, errors.New("private journal failure")
	}
	if err := compositionFailure.ResumeInstallation(t.Context(), strings.Repeat("a", 64)); !errors.Is(err, ErrResumeUnavailable) {
		t.Fatalf("composition failure error = %v", err)
	}
	if err := factory.ResumeInstallation(t.Context(), strings.Repeat("a", 64)); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("missing continuation error = %v", err)
	}
}

func TestPF001NativeFactoryResumeJoinsRecordAndPendingOperationBeforePlan(t *testing.T) {
	t.Parallel()
	roots := nativeTestRoots(t.TempDir())
	journals := newNativeSharedJournalFactory()
	composition, err := composeNative(t.Context(), roots, journals.provider, pendingReadySurface{})
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	planDigest, _ := install.BindPlan([]byte("canonical plan absent from repository"))
	operation, _ := install.NewOperation(operationID, planDigest)
	if err := composition.operations.Save(t.Context(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	fact, _ := install.NewNonSecretFact("probe_status", "verified")
	boundary, _ := install.NewCompensationBoundary("remove_agentmemory_owned_partial")
	action, _ := install.NewSafeAction("setup.continue")
	evidence, _ := install.NewStepEvidence(install.StepEvidenceInput{
		Phase: install.PhaseVerifyHost, Attempt: 1, PlanDigest: planDigest,
		InputDigest: install.DigestBytes([]byte("input")), OutputDigest: install.DigestBytes([]byte("output")),
		Facts: []install.NonSecretFact{fact}, RuntimeOwnership: install.RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary, NextSafeAction: action,
	})
	_ = operation.CompleteStep(evidence)
	if err := composition.operations.Save(t.Context(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	receipt := install.DigestBytes([]byte("resume"))
	resumeAction, _ := install.NewSafeAction("setup.resume_after_restart")
	checkpoint, _ := install.NewRebootCheckpoint(planDigest, install.PhaseEnsureContainerRuntime, 1, receipt, resumeAction)
	_ = operation.MarkRebootPending(planDigest, checkpoint)
	if err := composition.operations.Save(t.Context(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, _ := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: "/opt/AgentMemory/bin/agentmemory", LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID: operationID, JournalPath: "/owner/install-operation.json",
		JournalDigest: install.DigestBytes([]byte("journal")), ExpiresAt: now.Add(rebootcontinuation.MaximumLifetime),
		Nonce: rebootcontinuation.NonceBytes([]byte("one use")),
	}, now)
	if err := composition.continuationRecords.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	token, _ := rebootcontinuation.TokenFor(operationID)
	if err := composition.resources.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	factory := &NativeFactory{
		roots: func() (NativeRoots, error) { return roots, nil }, journals: journals.provider,
		ready: pendingReadySurface{}, production: func(context.Context, *nativeComposition) (nativeProductionFirstStart, error) {
			return nativeProductionFirstStart{}, errors.New("plan failure must precede production")
		},
	}
	if err := factory.ResumeInstallation(t.Context(), token); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("missing canonical plan error = %v", err)
	}

	verifiedComposition, err := composeNative(t.Context(), roots, journals.provider, pendingReadySurface{})
	if err != nil {
		t.Fatal(err)
	}
	verifiedOperation, err := verifiedComposition.operations.Load(t.Context(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifiedOperation.VerifyResume(planDigest, receipt); err != nil {
		t.Fatal(err)
	}
	if err := verifiedComposition.operations.Save(t.Context(), verifiedOperation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := verifiedComposition.resources.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := factory.ResumeInstallation(t.Context(), token); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("ResumeVerified missing canonical plan error = %v", err)
	}

	runningComposition, err := composeNative(t.Context(), roots, journals.provider, pendingReadySurface{})
	if err != nil {
		t.Fatal(err)
	}
	runningOperation, err := runningComposition.operations.Load(t.Context(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	if action, resumeError := runningOperation.Resume(planDigest); resumeError != nil || action != install.ResumeActionCurrentPhase {
		t.Fatalf("Resume() = (%v, %v)", action, resumeError)
	}
	if err := runningComposition.operations.Save(t.Context(), runningOperation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := runningComposition.resources.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := factory.ResumeInstallation(t.Context(), token); !errors.Is(err, ErrResumeIntegrity) {
		t.Fatalf("stale running continuation error = %v", err)
	}
	cleanedComposition, err := composeNative(t.Context(), roots, journals.provider, pendingReadySurface{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanedComposition.resources.Close(context.Background()) }()
	if _, err := cleanedComposition.continuationRecords.LoadByToken(t.Context(), token); !errors.Is(err, rebootapp.ErrRecordNotFound) {
		t.Fatalf("stale continuation cleanup error = %v", err)
	}
}

func TestPF001NativeContinuationResumesOnlyPendingOrDurablyVerifiedState(t *testing.T) {
	t.Parallel()
	for _, state := range []install.State{install.StateRebootPending, install.StateResumeVerified} {
		if !nativeContinuationStateMayResume(state) {
			t.Fatalf("state %s was rejected", state)
		}
	}
	for _, state := range []install.State{
		install.StateUnknown, install.StateRunning, install.StateFailedRecoverable,
		install.StatePausedForAdministrator, install.StateCancelled, install.StateUnsupportedHost,
		install.StateRuntimeConflict, install.StateReady,
	} {
		if nativeContinuationStateMayResume(state) {
			t.Fatalf("state %s was accepted", state)
		}
	}
}

func TestPF001NativeResumeMapsOnlyClosedInstallerErrors(t *testing.T) {
	t.Parallel()
	if mapped := mapNativeResumeRunError(nil); mapped != nil {
		t.Fatalf("nil run error mapped to %v", mapped)
	}
	_, validationError := (&installapp.InstallApplication{}).Install(t.Context(), installapp.InstallCommand{})
	if mapped := mapNativeResumeRunError(validationError); !errors.Is(mapped, ErrResumeIntegrity) {
		t.Fatalf("validation error mapped to %v", mapped)
	}
	for _, deadline := range []error{context.Canceled, context.DeadlineExceeded} {
		if mapped := mapNativeResumeRunError(deadline); !errors.Is(mapped, deadline) {
			t.Fatalf("deadline %v mapped to %v", deadline, mapped)
		}
	}
	private := errors.New("private worker failure")
	if mapped := mapNativeResumeRunError(private); !errors.Is(mapped, ErrResumeUnavailable) ||
		errors.Is(mapped, private) {
		t.Fatalf("private error mapped to %v", mapped)
	}
}

func TestPF001BoundCancellationUsesExactAggregateCASAuthority(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	cancellation := &boundCancellation{binding: binding, repository: repository}
	if err := cancellation.RequestCancellation(context.Background()); err != nil {
		t.Fatalf("RequestCancellation() error=%v", err)
	}
	if repository.requests.Load() != 1 || repository.last.OperationID != binding.OperationID() ||
		!repository.last.PlanDigest.Equal(binding.PlanDigest()) || repository.last.ObservedAggregateVersion != 0 {
		t.Fatalf("cancellation request=%+v calls=%d", repository.last, repository.requests.Load())
	}

	cancelledOperation, _ := install.NewOperation(binding.OperationID(), binding.PlanDigest())
	if err := cancelledOperation.Cancel(binding.PlanDigest()); err != nil {
		t.Fatal(err)
	}
	repository.operation = cancelledOperation
	before := repository.requests.Load()
	if err := cancellation.RequestCancellation(context.Background()); err != nil || repository.requests.Load() != before {
		t.Fatalf("cancelled replay error=%v calls=%d", err, repository.requests.Load())
	}
	terminal, _ := install.NewOperation(binding.OperationID(), binding.PlanDigest())
	if err := terminal.MarkUnsupportedHost(binding.PlanDigest()); err != nil {
		t.Fatal(err)
	}
	repository.operation = terminal
	if err := cancellation.RequestCancellation(context.Background()); !errors.Is(err, setupprogressapp.ErrAuthorityConflict) {
		t.Fatalf("terminal cancellation error=%v", err)
	}
}

func TestPF001BoundAcceptDeliversConsentAndRetryResumesExactInstaller(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	supervisor := &nativeSupervisorStub{}
	canonical := []byte("canonical plan")
	consent := &nativeConsentSink{}
	control := &boundCancellation{
		binding: binding, repository: repository, supervisor: supervisor, canonical: canonical,
		consent: consent,
	}
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionAccept, setupprogressapp.DecisionRetry,
	} {
		if err := invokeNativeDecision(t, control, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d41"); err != nil {
			t.Fatal(err)
		}
	}
	if consent.submits.Load() != 1 || supervisor.calls.Load() != 1 ||
		supervisor.command.OperationID != binding.OperationID().String() ||
		string(supervisor.command.CanonicalPlan) != "canonical plan" {
		t.Fatalf("consent=%d resume=%d command=%+v", consent.submits.Load(), supervisor.calls.Load(), supervisor.command)
	}
	canonical[0] = 'X'
	if string(supervisor.command.CanonicalPlan) != "canonical plan" {
		t.Fatal("resume command aliased caller plan bytes")
	}
	supervisor.err = errors.New("private")
	if err := invokeNativeDecision(t, control, binding, setupprogressapp.DecisionRetry,
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d42"); err == nil {
		t.Fatal("failed supervisor accepted")
	}
}

func TestPF001BoundCancellationRejectsEveryInvalidAuthorityResponse(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	cancellation := &boundCancellation{binding: binding, repository: repository}
	var nilRepository *nativeCancellationRepository
	invalidBinding := setupprogressapp.Binding{}
	for name, candidate := range map[string]*boundCancellation{
		"nil":              nil,
		"invalid binding":  {binding: invalidBinding, repository: repository},
		"typed repository": {binding: binding, repository: nilRepository},
	} {
		if err := candidate.RequestCancellation(context.Background()); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := cancellation.RequestCancellation(nil); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cancellation.RequestCancellation(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}

	foreignID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignOperation, _ := install.NewOperation(foreignID, binding.PlanDigest())
	foreignPlan, _ := install.BindPlan([]byte("foreign-plan"))
	foreignPlanOperation, _ := install.NewOperation(binding.OperationID(), foreignPlan)
	for name, configure := range map[string]func(){
		"load error":        func() { repository.operation, repository.loadErr = operation, errors.New("private") },
		"nil aggregate":     func() { repository.operation, repository.loadErr = nil, nil },
		"foreign operation": func() { repository.operation, repository.loadErr = foreignOperation, nil },
		"foreign plan":      func() { repository.operation, repository.loadErr = foreignPlanOperation, nil },
	} {
		repository.operation, repository.loadErr = operation, nil
		configure()
		if err := cancellation.RequestCancellation(context.Background()); err == nil ||
			errors.Is(err, setupprogressapp.ErrAuthorityConflict) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	repository.operation, repository.loadErr = operation, nil
	repository.requestErr = errors.New("private")
	if err := cancellation.RequestCancellation(context.Background()); err == nil {
		t.Fatal("request failure accepted")
	}
	repository.requestErr, repository.invalidIntent = nil, true
	if err := cancellation.RequestCancellation(context.Background()); err == nil {
		t.Fatal("invalid intent accepted")
	}
}

func TestPF001BoundCancellationDispatchesOnlyClosedSetupDecisions(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	cancellation := &boundCancellation{binding: binding, repository: repository}
	if err := invokeNativeDecision(t, cancellation, binding, setupprogressapp.DecisionCancel,
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d41"); err != nil || repository.requests.Load() != 1 {
		t.Fatalf("cancel error=%v calls=%d", err, repository.requests.Load())
	}
	consent := &nativeConsentSink{}
	cancellation.consent = consent
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionAccept, setupprogressapp.DecisionDecline,
	} {
		if err := invokeNativeDecision(t, cancellation, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d42"); err != nil {
			t.Fatalf("decision=%s error=%v", decision, err)
		}
	}
	if consent.submits.Load() != 2 || repository.requests.Load() != 1 {
		t.Fatalf("consent=%d cancellation=%d", consent.submits.Load(), repository.requests.Load())
	}
	consent.submitErr = context.Canceled
	if err := invokeNativeDecision(t, cancellation, binding, setupprogressapp.DecisionAccept,
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d44"); !setupprogressapp.IsDeadlineError(err) {
		t.Fatalf("cancelled consent error=%v", err)
	}
	consent.submitErr = errors.New("private")
	if err := invokeNativeDecision(t, cancellation, binding, setupprogressapp.DecisionDecline,
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d45"); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsanitized consent error=%v", err)
	}
	cancellation.consent = nil
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionAccept, setupprogressapp.DecisionDecline,
		setupprogressapp.DecisionRetry,
	} {
		err := invokeNativeDecision(t, cancellation, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d43")
		if !setupprogressapp.IsConflictError(err) {
			t.Fatalf("unavailable decision=%s error=%v", decision, err)
		}
	}
	var nilCancellation *boundCancellation
	if err := nilCancellation.ApplySetupDecision(context.Background(), setupprogressapp.DecisionCommand{}); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("nil decision effect error=%v", err)
	}
}

func TestPF001NativeRuntimeFactoryBuildsBoundProgressSetupAndCancellation(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	operation, _ := install.NewOperation(resolved.OperationID(), resolved.PlanDigest())
	repository := &nativeCancellationRepository{operation: operation}
	setup := &nativeSetupStub{}
	resources := &nativeResources{plans: &nativePlanCloser{}}
	factory := &nativeRuntimeFactory{
		operations: repository, runtime: nativeMissingRuntimeOperations{}, runtimePlans: nativeMissingRuntimePlans{},
		decisions: nativeMissingJournalProvider{}, consent: &nativeConsentSink{}, clock: fixedResolverClock{},
		ready: &readyStub{err: errors.New("not Ready")}, resources: resources,
		decodePlan: func([]byte) (runtimePlanProjection, error) {
			return runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, 4096), nil
		},
		setup: func(_ context.Context, progress *setupprogressapp.Application) (nativeSetupController, error) {
			if progress == nil || progress.Binding().OperationID() != resolved.OperationID() {
				t.Fatal("setup received unbound progress application")
			}
			return setup, nil
		},
	}
	runtime, err := factory.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved)
	if err != nil || runtime.Progress == nil || runtime.Setup != setup || runtime.Cancellation == nil ||
		runtime.Ready == nil || runtime.Lifecycle == nil {
		t.Fatalf("BuildBootstrapRuntime()=%+v,%v", runtime, err)
	}
	status, err := runtime.Progress.Current(context.Background())
	if err != nil || status.OperationID() != resolved.OperationID() || status.Progress().TotalBytes != 4096 {
		t.Fatalf("progress.Current()=%+v,%v", status, err)
	}
	if err := runtime.Setup.OpenSetup(context.Background()); err != nil || setup.opens.Load() != 1 {
		t.Fatalf("OpenSetup() error=%v opens=%d", err, setup.opens.Load())
	}
	if err := runtime.Cancellation.RequestCancellation(context.Background()); err != nil || repository.requests.Load() != 1 {
		t.Fatalf("RequestCancellation() error=%v calls=%d", err, repository.requests.Load())
	}
	if err := runtime.Lifecycle.Close(context.Background()); err != nil || setup.closes.Load() != 1 {
		t.Fatalf("lifecycle.Close() error=%v closes=%d", err, setup.closes.Load())
	}
}

func TestPF001NativeRuntimeFactoryRejectsPlanAndDependencySubstitution(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	operation, _ := install.NewOperation(resolved.OperationID(), resolved.PlanDigest())
	base := nativeRuntimeFactory{
		operations: &nativeCancellationRepository{operation: operation},
		runtime:    nativeMissingRuntimeOperations{}, runtimePlans: nativeMissingRuntimePlans{},
		decisions: nativeMissingJournalProvider{}, consent: &nativeConsentSink{}, clock: fixedResolverClock{},
		ready: &readyStub{err: errors.New("not Ready")}, resources: &nativeResources{plans: &nativePlanCloser{}},
		decodePlan: func([]byte) (runtimePlanProjection, error) {
			return runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, 1), nil
		},
		setup: func(context.Context, *setupprogressapp.Application) (nativeSetupController, error) {
			return &nativeSetupStub{}, nil
		},
	}
	var nilFactory *nativeRuntimeFactory
	if _, err := nilFactory.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil factory error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := base.BuildBootstrapRuntime(nil, agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := base.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHost("invalid"), resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid host error=%v", err)
	}
	if _, err := base.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, mcpbootstrapapp.ResolvedBootstrap{}); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid resolved error=%v", err)
	}

	for name, mutate := range map[string]func(*nativeRuntimeFactory){
		"operations":    func(f *nativeRuntimeFactory) { f.operations = (*nativeCancellationRepository)(nil) },
		"runtime":       func(f *nativeRuntimeFactory) { f.runtime = (*nativeMissingRuntimeOperations)(nil) },
		"runtime plans": func(f *nativeRuntimeFactory) { f.runtimePlans = (*nativeMissingRuntimePlans)(nil) },
		"decisions":     func(f *nativeRuntimeFactory) { f.decisions = (*nativeMissingJournalProvider)(nil) },
		"consent":       func(f *nativeRuntimeFactory) { f.consent = (*nativeConsentSink)(nil) },
		"clock":         func(f *nativeRuntimeFactory) { f.clock = nil },
		"Ready":         func(f *nativeRuntimeFactory) { f.ready = (*readyStub)(nil) },
		"resources":     func(f *nativeRuntimeFactory) { f.resources = nil },
		"decoder":       func(f *nativeRuntimeFactory) { f.decodePlan = nil },
		"setup":         func(f *nativeRuntimeFactory) { f.setup = nil },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := candidate.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("missing %s error=%v", name, err)
		}
	}

	foreignID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignDigest, _ := install.BindPlan([]byte("foreign-plan"))
	projections := map[string]runtimePlanProjection{
		"digest":       {digest: foreignDigest, operationID: resolved.OperationID(), installationID: resolved.InstallationID(), host: agentconfigdomain.AgentHostCodex},
		"operation":    {digest: resolved.PlanDigest(), operationID: foreignID, installationID: resolved.InstallationID(), host: agentconfigdomain.AgentHostCodex},
		"installation": {digest: resolved.PlanDigest(), operationID: resolved.OperationID(), installationID: "foreign", host: agentconfigdomain.AgentHostCodex},
		"host":         runtimeProjection(resolved, agentconfigdomain.AgentHostClaude, 1),
		"bytes":        runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, setupprogressapp.MaximumSafeInteger+1),
	}
	for name, projection := range projections {
		candidate := base
		candidate.decodePlan = func([]byte) (runtimePlanProjection, error) { return projection, nil }
		if _, err := candidate.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("substituted %s error=%v", name, err)
		}
	}
	decoderFailure := base
	decoderFailure.decodePlan = func([]byte) (runtimePlanProjection, error) {
		return runtimePlanProjection{}, errors.New("private")
	}
	if _, err := decoderFailure.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("decoder failure error=%v", err)
	}
	setupFailure := base
	setupFailure.setup = func(context.Context, *setupprogressapp.Application) (nativeSetupController, error) {
		return nil, errors.New("private")
	}
	if _, err := setupFailure.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); err == nil ||
		errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("setup failure error=%v", err)
	}
	consentFailure := base
	consentFailure.consent = &nativeConsentSink{bindErr: errors.New("private")}
	if _, err := consentFailure.BuildBootstrapRuntime(
		context.Background(), agentconfigdomain.AgentHostCodex, resolved,
	); !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("consent bind failure=%v", err)
	}
}

type nativeMissingRuntimeOperations struct{}

func (nativeMissingRuntimeOperations) Load(
	context.Context,
	string,
) (*runtimeinstall.Operation, error) {
	return nil, runtimeinstallapp.ErrOperationNotFound
}

type nativeMissingRuntimePlans struct{}

func (nativeMissingRuntimePlans) LoadRuntimePlan(
	context.Context,
	install.OperationID,
	install.PlanDigest,
) (installplanapp.RuntimePlanAuthority, error) {
	return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanNotFound
}

type nativeConsentSink struct {
	bindErr   error
	submitErr error
	binds     atomic.Int32
	submits   atomic.Int32
}

func (s *nativeConsentSink) Bind(setupprogressapp.Binding) error {
	s.binds.Add(1)
	return s.bindErr
}

func (s *nativeConsentSink) SubmitRuntimeConsent(
	context.Context,
	setupprogressapp.Binding,
	setupprogressapp.Decision,
	string,
) error {
	s.submits.Add(1)
	return s.submitErr
}

func TestPF001NativeSetupLifecycleResourcesAndPendingReadyFailClosed(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	binding, _ := setupprogressapp.NewBinding(resolved.OperationID(), resolved.PlanDigest())
	progress := progressApplication(t, binding)
	controller, err := newNativeSetupController(context.Background(), progress)
	if err == nil && controller != nil {
		if closeError := controller.Close(context.Background()); closeError != nil {
			t.Fatalf("native controller Close() error=%v", closeError)
		}
	} else if browser, browserError := setuphost.NewBrowserOpener(); browserError == nil || browser != nil {
		t.Fatalf("newNativeSetupController()=%T,%v", controller, err)
	}
	if _, err := newNativeSetupController(context.Background(), nil); err == nil {
		t.Fatal("nil progress setup controller succeeded")
	}
	if _, err := decodeRuntimePlan([]byte("not a canonical plan")); err == nil {
		t.Fatal("invalid canonical runtime plan decoded")
	}
	readyProjection := runtimePlanProjection{
		installationID: "019f5f20-1234-7abc-8123-0123456789ab",
		coreEndpoint:   "http://127.0.0.1:38765", credentialPath: filepath.Join(t.TempDir(), "credential"),
	}
	if ready, err := newNativeReadySurface(context.Background(), readyProjection); err != nil || ready == nil {
		t.Fatalf("newNativeReadySurface()=%T,%v", ready, err)
	}
	readyProjection.coreEndpoint = "https://remote.example"
	if ready, err := newNativeReadySurface(context.Background(), readyProjection); err == nil || ready != nil {
		t.Fatalf("remote newNativeReadySurface()=%T,%v", ready, err)
	}
	if surface, err := (pendingReadySurface{}).ReadySurface(context.Background()); err == nil ||
		len(surface.Tools) != 0 || len(surface.Resources) != 0 {
		t.Fatalf("pending Ready surface=%+v,%v", surface, err)
	}

	if err := (*nativeResources)(nil).Close(context.Background()); err != nil {
		t.Fatalf("nil resources close error=%v", err)
	}
	if err := (*nativeResources)(nil).addClosers(&nativeRuntimeCloserStub{}); err == nil {
		t.Fatal("nil resources accepted a managed closer")
	}
	var typedNilCloser *nativeRuntimeCloserStub
	if err := (&nativeResources{}).addClosers(typedNilCloser); err == nil {
		t.Fatal("resources accepted a typed-nil managed closer")
	}
	managedCloser := &nativeRuntimeCloserStub{}
	failingManagedCloser := &nativeRuntimeCloserStub{err: errors.New("private managed close")}
	managedResources := &nativeResources{}
	if err := managedResources.addClosers(managedCloser, failingManagedCloser); err != nil {
		t.Fatal(err)
	}
	if err := managedResources.Close(context.Background()); err == nil ||
		managedCloser.calls != 1 || failingManagedCloser.calls != 1 {
		t.Fatalf("managed resource close error=%v calls=%d/%d", err, managedCloser.calls, failingManagedCloser.calls)
	}
	if err := managedResources.addClosers(&nativeRuntimeCloserStub{}); err == nil {
		t.Fatal("closed resources accepted another managed closer")
	}
	//lint:ignore SA1012 Deliberate nil-context resource boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := (&nativeResources{}).Close(nil); err == nil {
		t.Fatal("resources accepted a nil close context")
	}
	closer := &nativePlanCloser{}
	artifactCloser := &nativePlanCloser{}
	resources := &nativeResources{plans: closer, artifacts: artifactCloser}
	if err := resources.Close(context.Background()); err != nil || closer.calls.Load() != 1 || artifactCloser.calls.Load() != 1 {
		t.Fatalf("resources close error=%v plan_calls=%d artifact_calls=%d", err, closer.calls.Load(), artifactCloser.calls.Load())
	}
	if err := resources.Close(context.Background()); err != nil || closer.calls.Load() != 1 || artifactCloser.calls.Load() != 1 {
		t.Fatalf("resources replay error=%v plan_calls=%d artifact_calls=%d", err, closer.calls.Load(), artifactCloser.calls.Load())
	}
	failingResources := &nativeResources{
		plans:     &nativePlanCloser{err: errors.New("private")},
		artifacts: &nativePlanCloser{err: errors.New("private artifact")},
	}
	if err := failingResources.Close(context.Background()); err == nil {
		t.Fatal("failing plan closer was hidden")
	}
	setup := &nativeSetupStub{closeErr: errors.New("setup close")}
	lifecycle := &nativeRuntimeLifecycle{
		controller: setup,
		resources:  &nativeResources{plans: &nativePlanCloser{err: errors.New("plan close")}},
	}
	if err := lifecycle.Close(context.Background()); err == nil || setup.closes.Load() != 1 {
		t.Fatalf("joined lifecycle error=%v closes=%d", err, setup.closes.Load())
	}
	var nilLifecycle *nativeRuntimeLifecycle
	if err := nilLifecycle.Close(context.Background()); err == nil {
		t.Fatal("nil lifecycle close succeeded")
	}
	//lint:ignore SA1012 Deliberate nil-context lifecycle attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := (&nativeRuntimeLifecycle{}).Close(nil); err == nil {
		t.Fatal("nil-context lifecycle close succeeded")
	}
	if err := (&nativeRuntimeLifecycle{}).Close(context.Background()); err != nil {
		t.Fatalf("empty lifecycle close error=%v", err)
	}
}

func TestPF001NativePlatformJournalProviderConstructsWithoutCreatingAuthority(t *testing.T) {
	t.Parallel()
	locator, err := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "native-journal"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newPlatformJournalProvider(locator)
	if err != nil || provider == nil {
		t.Fatalf("newPlatformJournalProvider()=%T,%v", provider, err)
	}
	if provider, err := newPlatformJournalProvider(nil); provider != nil || err == nil {
		t.Fatalf("nil-locator journal provider=%T error=%v", provider, err)
	}
}

func TestPF001NativeNilClassificationCoversEveryNilableKind(t *testing.T) {
	t.Parallel()
	var pointer *nativeSetupStub
	var mapping map[string]string
	var slice []string
	var function func()
	var channel chan struct{}
	for _, value := range []any{nil, pointer, mapping, slice, function, channel} {
		if !nilAny(value) {
			t.Fatalf("nilAny(%T)=false", value)
		}
	}
	for _, value := range []any{struct{}{}, 1, "value", make(chan struct{})} {
		if nilAny(value) {
			t.Fatalf("nilAny(%T)=true", value)
		}
	}
}

func nativeTestRoots(root string) NativeRoots {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return NativeRoots{
		OperationState: filepath.Join(root, "operation"), BootstrapPointer: filepath.Join(root, "pointer"),
		SetupDecisions: filepath.Join(root, "decisions"), PreparationState: filepath.Join(root, "preparation"),
		RuntimeState:               filepath.Join(root, "runtime"),
		RuntimeOwnershipState:      filepath.Join(root, "runtime-ownership"),
		RuntimeRemovalState:        filepath.Join(root, "runtime-removal"),
		RuntimeConsentKeyState:     filepath.Join(root, "runtime-consent-key"),
		RuntimeConsentReceiptState: filepath.Join(root, "runtime-consent-receipt"),
		RuntimeReplayState:         filepath.Join(root, "runtime-replay"),
		RebootContinuationState:    filepath.Join(root, "reboot-continuation"),
		ReleaseAnchorState:         filepath.Join(root, "release-anchor"),
		RuntimeCatalogAnchorState:  filepath.Join(root, "runtime-catalog-anchor"),
		ArtifactState:              filepath.Join(root, "artifacts"), ResourceState: filepath.Join(root, "resources"),
		AgentConfigurationBackups: filepath.Join(root, "agent-configuration-backups"),
		ArtifactCAS:               filepath.Join(root, "artifact-cas"),
		ActiveReleaseState:        filepath.Join(root, "active-release"), InstallationLock: filepath.Join(root, "installation.lock"),
		ReadinessState: filepath.Join(root, "readiness"),
		CanonicalPlans: filepath.Join(root, "plans"),
	}
}

type nativeMissingJournalProvider struct{}

func (nativeMissingJournalProvider) JournalFor(ctx context.Context, operationID install.OperationID) (journalport.Journal, error) {
	owner, err := install.BindOwner("native-test-machine", "native-test-principal")
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)))
	if err != nil {
		return nil, err
	}
	keyRef, err := keys.Ensure(ctx, operationID, owner)
	if err != nil {
		return nil, err
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		return nil, err
	}
	return bootstrapadapter.NewAnchoredJournal(nativeMissingJournal{}, anchors, keyRef, operationID, owner)
}

type nativePlainJournalProvider struct{}

func (nativePlainJournalProvider) JournalFor(context.Context, install.OperationID) (journalport.Journal, error) {
	return nativeMissingJournal{}, nil
}

type nativeMissingJournal struct{}

func (nativeMissingJournal) Append(context.Context, uint64, journalport.Snapshot) error {
	return journalport.ErrConflict
}

func (nativeMissingJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	return journalport.Snapshot{}, journalport.ErrNotFound
}

func (nativeMissingJournal) ConfirmDurable(context.Context, string, uint64) error {
	return journalport.ErrNotFound
}

type nativeSharedJournalFactory struct {
	mu        sync.Mutex
	providers map[string]*nativeSharedJournalProvider
}

func newNativeSharedJournalFactory() *nativeSharedJournalFactory {
	return &nativeSharedJournalFactory{providers: make(map[string]*nativeSharedJournalProvider)}
}

func (f *nativeSharedJournalFactory) provider(
	locator *bootstrapadapter.OperationLocator,
) (filesystem.OperationJournalProvider, error) {
	if f == nil || locator == nil {
		return nil, errors.New("shared journal locator is required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	provider := f.providers[locator.Root()]
	if provider == nil {
		var err error
		provider, err = newNativeSharedJournalProvider()
		if err != nil {
			return nil, err
		}
		f.providers[locator.Root()] = provider
	}
	return provider, nil
}

type nativeSharedJournalProvider struct {
	mu       sync.Mutex
	keys     *bootstrapadapter.MemoryOperationKeySource
	anchors  *bootstrapadapter.MemoryRollbackAnchorStore
	owner    install.OwnerBinding
	journals map[string]*bootstrapadapter.AnchoredJournal
}

func newNativeSharedJournalProvider() (*nativeSharedJournalProvider, error) {
	owner, err := install.BindOwner("native-test-machine", "native-test-principal")
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x6b}, 4096)))
	if err != nil {
		return nil, err
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		return nil, err
	}
	return &nativeSharedJournalProvider{
		keys: keys, anchors: anchors, owner: owner,
		journals: make(map[string]*bootstrapadapter.AnchoredJournal),
	}, nil
}

func (p *nativeSharedJournalProvider) JournalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	if p == nil || ctx == nil || operationID.IsZero() {
		return nil, journalport.ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	journal := p.journals[operationID.String()]
	if journal == nil {
		keyRef, err := p.keys.Ensure(ctx, operationID, p.owner)
		if err != nil {
			return nil, err
		}
		journal, err = bootstrapadapter.NewAnchoredJournal(
			&nativeSharedJournal{}, p.anchors, keyRef, operationID, p.owner,
		)
		if err != nil {
			return nil, err
		}
		p.journals[operationID.String()] = journal
	}
	return journal, nil
}

type nativeSharedJournal struct {
	mu     sync.Mutex
	latest *journalport.Snapshot
}

func (j *nativeSharedJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	if j == nil || ctx == nil {
		return journalport.ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	currentRevision := uint64(0)
	if j.latest != nil {
		currentRevision = j.latest.Revision
	}
	if expectedPreviousRevision != currentRevision || snapshot.Revision != currentRevision+1 {
		return journalport.ErrConflict
	}
	cloned := cloneNativeJournalSnapshot(snapshot)
	j.latest = &cloned
	return nil
}

func (j *nativeSharedJournal) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	if j == nil || ctx == nil {
		return journalport.Snapshot{}, journalport.ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return journalport.Snapshot{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.latest == nil {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	return cloneNativeJournalSnapshot(*j.latest), nil
}

func (j *nativeSharedJournal) ConfirmDurable(
	ctx context.Context,
	operationID string,
	revision uint64,
) error {
	if j == nil || ctx == nil {
		return journalport.ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.latest == nil {
		return journalport.ErrNotFound
	}
	if j.latest.OperationID != operationID || j.latest.Revision != revision {
		return journalport.ErrConflict
	}
	return nil
}

func cloneNativeJournalSnapshot(snapshot journalport.Snapshot) journalport.Snapshot {
	cloned := snapshot
	cloned.Payload = append([]byte(nil), snapshot.Payload...)
	return cloned
}

func nativeCancellationFixture(t testing.TB) (setupprogressapp.Binding, *install.Operation) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	digest, _ := install.BindPlan([]byte("canonical-plan"))
	binding, err := setupprogressapp.NewBinding(operationID, digest)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := install.NewOperation(operationID, digest)
	if err != nil {
		t.Fatal(err)
	}
	return binding, operation
}

type nativeCancellationRepository struct {
	operation     *install.Operation
	loadErr       error
	requestErr    error
	invalidIntent bool
	requests      atomic.Int32
	last          installapp.CancellationRequest
}

type nativeSupervisorStub struct {
	command installapp.InstallCommand
	calls   atomic.Int32
	err     error
}

func (s *nativeSupervisorStub) EnsureRunning(_ context.Context, command installapp.InstallCommand) error {
	s.command = command
	s.calls.Add(1)
	return s.err
}

func (r *nativeCancellationRepository) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.loadErr
}

func (r *nativeCancellationRepository) Request(
	_ context.Context,
	request installapp.CancellationRequest,
) (installapp.CancellationIntent, error) {
	r.requests.Add(1)
	r.last = request
	if r.requestErr != nil || r.invalidIntent {
		return installapp.CancellationIntent{}, r.requestErr
	}
	return installapp.NewRequestedCancellationIntentForAdapter(request, request.ObservedAggregateVersion+1)
}

func invokeNativeDecision(
	t testing.TB,
	effect *boundCancellation,
	binding setupprogressapp.Binding,
	decision setupprogressapp.Decision,
	key string,
) error {
	t.Helper()
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence: 1, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: setupprogressapp.StateRunning, Phase: setupprogressapp.PhaseVerifyHost,
		MessageKey: setupprogressapp.MessageVerifying,
		Progress:   setupprogressapp.Progress{TotalStages: 14}, SafeAction: setupprogressapp.ActionCancel,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := &nativeDecisionForwarder{snapshot: snapshot, effect: effect}
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{
		PlanDigest: binding.PlanDigest().String(), Decision: decision, IdempotencyKey: key,
	})
	return err
}

type nativeDecisionForwarder struct {
	snapshot setupprogressapp.Snapshot
	effect   *boundCancellation
}

func (a *nativeDecisionForwarder) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	return a.snapshot, nil
}

func (a *nativeDecisionForwarder) WaitSnapshotAfter(context.Context, setupprogressapp.Binding, uint64) (setupprogressapp.Snapshot, error) {
	return a.snapshot, nil
}

func (a *nativeDecisionForwarder) ApplyDecision(
	ctx context.Context,
	command setupprogressapp.DecisionCommand,
) (setupprogressapp.DecisionReceipt, error) {
	if err := a.effect.ApplySetupDecision(ctx, command); err != nil {
		return setupprogressapp.DecisionReceipt{}, err
	}
	return setupprogressapp.NewDecisionReceipt(command.IdempotencyKey(), command.Decision(), a.snapshot)
}

type nativeSetupStub struct {
	opens    atomic.Int32
	closes   atomic.Int32
	openErr  error
	closeErr error
}

func (s *nativeSetupStub) OpenSetup(context.Context) error {
	s.opens.Add(1)
	return s.openErr
}

func (s *nativeSetupStub) Close(context.Context) error {
	s.closes.Add(1)
	return s.closeErr
}

type nativePlanCloser struct {
	calls atomic.Int32
	err   error
}

func (c *nativePlanCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func runtimeProjection(
	resolved mcpbootstrapapp.ResolvedBootstrap,
	host agentconfigdomain.AgentHost,
	total uint64,
) runtimePlanProjection {
	return runtimePlanProjection{
		digest: resolved.PlanDigest(), operationID: resolved.OperationID(),
		installationID: resolved.InstallationID(), host: host, totalBytes: total,
	}
}

var _ mcpbootstrap.ReadySurfaceProvider = pendingReadySurface{}
