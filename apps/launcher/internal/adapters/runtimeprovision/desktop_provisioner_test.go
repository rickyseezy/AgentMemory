package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDesktopProvisionerCompletesWindowsInstallWithExactConsentNativeMutationsAndOwnership(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	runtimeInspector := &desktopRuntimeFake{authority: authority}
	consent := &desktopConsentFake{clock: clock}
	consentRepository := &desktopConsentRepositoryFake{}
	artifacts := &desktopArtifactFake{authority: authority}
	mutations := &desktopMutationFake{clock: clock}
	launcher := &desktopLauncherFake{}
	capabilities := &desktopCapabilitiesFake{}
	provisioner := newDesktopTestProvisioner(t, desktopTestDependencies{
		authority: authority, host: desktopHostEvidence(t, authority, false), runtime: runtimeInspector,
		consent: consent, consentRepository: consentRepository, artifacts: artifacts, mutation: mutations,
		launcher: launcher, capabilities: capabilities, clock: clock,
	})
	application := newDesktopRuntimeApplication(t, provisioner)
	result, err := application.Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: "desktop-windows-install-1", CanonicalPlan: plan.CanonicalBytes(),
	})
	if err != nil || result.State != runtimeinstall.OperationStateReady || result.ErrorCode != runtimeinstallapp.ErrorCodeNone {
		t.Fatalf("Ensure() = state:%s code:%s error:%v", result.State, result.ErrorCode, err)
	}
	receipt, present := result.CompletionReceipt()
	if !present || !receipt.Valid() || receipt.Ownership() != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		receipt.ArtifactDigest() != authority.ArtifactSHA256() {
		t.Fatalf("completion receipt = %#v, present:%t", receipt, present)
	}
	if consent.calls != 1 || consentRepository.stores != 1 || artifacts.acquireCalls != 1 || artifacts.verifyCalls != 2 ||
		!slices.Equal(mutations.operations, []runtimeport.DesktopMutationOperation{
			runtimeport.DesktopMutationInstallPrerequisites, runtimeport.DesktopMutationInstallRuntime,
		}) || launcher.calls != 1 || capabilities.calls != 1 || runtimeInspector.calls != 3 {
		t.Fatalf("effects: consent=%d stores=%d acquire=%d verify=%d mutations=%v launch=%d caps=%d runtime=%d",
			consent.calls, consentRepository.stores, artifacts.acquireCalls, artifacts.verifyCalls,
			mutations.operations, launcher.calls, capabilities.calls, runtimeInspector.calls)
	}
	if mutations.installArtifactDigest.IsZero() || mutations.prerequisiteArtifactDigest != (runtimeinstall.Hash{}) {
		t.Fatal("mutation artifact binding did not distinguish prerequisites from installer")
	}
}

func TestDesktopProvisionerSkipsWindowsPrerequisitesAndVendorUIOnMac(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	mutations := &desktopMutationFake{clock: clock}
	provisioner := newDesktopTestProvisioner(t, desktopTestDependencies{
		authority: authority, host: desktopHostEvidence(t, authority, true), runtime: &desktopRuntimeFake{authority: authority},
		consent: &desktopConsentFake{clock: clock}, consentRepository: &desktopConsentRepositoryFake{},
		artifacts: &desktopArtifactFake{authority: authority}, mutation: mutations,
		launcher: &desktopLauncherFake{}, capabilities: &desktopCapabilitiesFake{}, clock: clock,
	})
	result, err := newDesktopRuntimeApplication(t, provisioner).Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: "desktop-mac-install-1", CanonicalPlan: plan.CanonicalBytes(),
	})
	if err != nil || result.State != runtimeinstall.OperationStateReady {
		t.Fatalf("macOS Ensure() = state:%s error:%v", result.State, err)
	}
	if !slices.Equal(mutations.operations, []runtimeport.DesktopMutationOperation{runtimeport.DesktopMutationInstallRuntime}) {
		t.Fatalf("macOS mutations=%v", mutations.operations)
	}
}

func TestDesktopProvisionerMapsConsentAndNativeElevationDecisions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		consentErr  error
		mutationErr error
		want        runtimeinstall.OperationState
	}{
		{name: "consent declined", consentErr: runtimeport.ErrDesktopConsentDeclined, want: runtimeinstall.OperationStateCancelled},
		{name: "consent unavailable", consentErr: runtimeport.ErrDesktopConsentUnavailable, want: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "elevation denied", mutationErr: runtimeport.ErrDesktopMutationDenied, want: runtimeinstall.OperationStateCancelled},
		{name: "elevation unavailable", mutationErr: runtimeport.ErrDesktopMutationUnavailable, want: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "device policy", mutationErr: runtimeport.ErrDesktopMutationPolicy, want: runtimeinstall.OperationStatePausedForAdministrator},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
			clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
			provisioner := newDesktopTestProvisioner(t, desktopTestDependencies{
				authority: authority, host: desktopHostEvidence(t, authority, false), runtime: &desktopRuntimeFake{authority: authority},
				consent: &desktopConsentFake{clock: clock, err: test.consentErr}, consentRepository: &desktopConsentRepositoryFake{},
				artifacts: &desktopArtifactFake{authority: authority}, mutation: &desktopMutationFake{clock: clock, err: test.mutationErr},
				launcher: &desktopLauncherFake{}, capabilities: &desktopCapabilitiesFake{}, clock: clock,
			})
			result, ensureErr := newDesktopRuntimeApplication(t, provisioner).Ensure(context.Background(), runtimeinstallapp.Command{
				OperationID: "desktop-decision-1", CanonicalPlan: plan.CanonicalBytes(),
			})
			if ensureErr != nil || result.State != test.want {
				t.Fatalf("Ensure() = state:%s err:%v, want %s", result.State, ensureErr, test.want)
			}
		})
	}
}

func TestDesktopProvisionerRejectsForgedConsentArtifactMutationAndCapabilities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*desktopTestDependencies)
	}{
		{name: "consent signature", mutate: func(v *desktopTestDependencies) {
			v.consentAuthenticatorError = runtimeport.ErrDesktopConsentIntegrity
		}},
		{name: "consent store", mutate: func(v *desktopTestDependencies) { v.consentRepository.storeErr = errors.New("disk details") }},
		{name: "artifact acquisition", mutate: func(v *desktopTestDependencies) { v.artifacts.forgeAcquisition = true }},
		{name: "artifact publisher", mutate: func(v *desktopTestDependencies) { v.artifacts.forgeVerification = true }},
		{name: "mutation signature", mutate: func(v *desktopTestDependencies) {
			v.mutationAuthenticatorError = runtimeport.ErrDesktopMutationIntegrity
		}},
		{name: "mutation replay", mutate: func(v *desktopTestDependencies) { v.mutationReplayError = errors.New("replayed details") }},
		{name: "launch zero", mutate: func(v *desktopTestDependencies) { v.launcher.zero = true }},
		{name: "capability zero", mutate: func(v *desktopTestDependencies) { v.capabilities.zero = true }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
			clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
			dependencies := desktopTestDependencies{
				authority: authority, host: desktopHostEvidence(t, authority, false), runtime: &desktopRuntimeFake{authority: authority},
				consent: &desktopConsentFake{clock: clock}, consentRepository: &desktopConsentRepositoryFake{},
				artifacts: &desktopArtifactFake{authority: authority}, mutation: &desktopMutationFake{clock: clock},
				launcher: &desktopLauncherFake{}, capabilities: &desktopCapabilitiesFake{}, clock: clock,
			}
			test.mutate(&dependencies)
			result, ensureErr := newDesktopRuntimeApplication(t, newDesktopTestProvisioner(t, dependencies)).Ensure(
				context.Background(), runtimeinstallapp.Command{OperationID: "desktop-integrity-1", CanonicalPlan: plan.CanonicalBytes()},
			)
			if ensureErr == nil || result.State != runtimeinstall.OperationStateFailedRecoverable ||
				result.ErrorCode != runtimeinstallapp.ErrorCodeIntegrityViolation && result.ErrorCode != runtimeinstallapp.ErrorCodeInternal {
				t.Fatalf("Ensure() = state:%s code:%s err:%v", result.State, result.ErrorCode, ensureErr)
			}
		})
	}
}

func TestDesktopProvisionerPersistsAndResumesOnlySignedRebootReceipt(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	reboot := runtimeinstall.Sum([]byte("signed-reboot-receipt"))
	mutations := &desktopMutationFake{clock: clock, rebootOnPrerequisites: reboot}
	provisioner := newDesktopTestProvisioner(t, desktopTestDependencies{
		authority: authority, host: desktopHostEvidence(t, authority, false), runtime: &desktopRuntimeFake{authority: authority},
		consent: &desktopConsentFake{clock: clock}, consentRepository: &desktopConsentRepositoryFake{},
		artifacts: &desktopArtifactFake{authority: authority}, mutation: mutations,
		launcher: &desktopLauncherFake{}, capabilities: &desktopCapabilitiesFake{}, clock: clock,
	})
	application := newDesktopRuntimeApplication(t, provisioner)
	command := runtimeinstallapp.Command{OperationID: "desktop-reboot-1", CanonicalPlan: plan.CanonicalBytes()}
	first, err := application.Ensure(context.Background(), command)
	if err != nil || first.State != runtimeinstall.OperationStateRebootPending {
		t.Fatalf("first Ensure() = state:%s err:%v", first.State, err)
	}
	receipt, ok := first.RebootReceipt()
	if !ok || receipt != reboot {
		t.Fatalf("reboot receipt = %s, %t", receipt, ok)
	}
	mutations.rebootOnPrerequisites = runtimeinstall.Hash{}
	command.ResumeReceipt = &receipt
	second, err := application.Ensure(context.Background(), command)
	if err != nil || second.State != runtimeinstall.OperationStateReady {
		t.Fatalf("resumed Ensure() = state:%s err:%v", second.State, err)
	}
}

func TestDesktopProvisionerFailsClosedOnMissingDependencyAuthorityAndCancellation(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	valid := desktopDependenciesForTest(t, desktopTestDependencies{
		authority: authority, host: desktopHostEvidence(t, authority, true), runtime: &desktopRuntimeFake{authority: authority},
		consent: &desktopConsentFake{clock: clock}, consentRepository: &desktopConsentRepositoryFake{},
		artifacts: &desktopArtifactFake{authority: authority}, mutation: &desktopMutationFake{clock: clock},
		launcher: &desktopLauncherFake{}, capabilities: &desktopCapabilitiesFake{}, clock: clock,
	})
	fields := []func(*DesktopDependencies){
		func(v *DesktopDependencies) { v.Authority = nil }, func(v *DesktopDependencies) { v.Host = nil },
		func(v *DesktopDependencies) { v.Runtime = nil }, func(v *DesktopDependencies) { v.Consent = nil },
		func(v *DesktopDependencies) { v.ConsentAuthenticator = nil }, func(v *DesktopDependencies) { v.ConsentRepository = nil },
		func(v *DesktopDependencies) { v.Artifacts = nil }, func(v *DesktopDependencies) { v.ArtifactVerifier = nil },
		func(v *DesktopDependencies) { v.Mutation = nil }, func(v *DesktopDependencies) { v.MutationAuthenticator = nil },
		func(v *DesktopDependencies) { v.MutationReplay = nil },
		func(v *DesktopDependencies) { v.Launcher = nil }, func(v *DesktopDependencies) { v.Capabilities = nil },
		func(v *DesktopDependencies) { v.Nonces = nil }, func(v *DesktopDependencies) { v.Clock = nil },
	}
	for _, remove := range fields {
		candidate := valid
		remove(&candidate)
		if provisioner, err := NewDesktopProvisioner(candidate); err == nil || provisioner != nil {
			t.Fatal("incomplete desktop provisioner was constructed")
		}
	}
	typedNil := valid
	var nilRuntime *desktopRuntimeFake
	typedNil.Runtime = nilRuntime
	if _, err := NewDesktopProvisioner(typedNil); err == nil {
		t.Fatal("typed nil desktop dependency was accepted")
	}

	authorityFailure := valid
	authorityFailure.Authority = desktopAuthorityResolverFake{err: runtimeport.ErrDesktopAuthorityUnavailable}
	provisioner, _ := NewDesktopProvisioner(authorityFailure)
	result, ensureErr := newDesktopRuntimeApplication(t, provisioner).Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: "desktop-authority-1", CanonicalPlan: plan.CanonicalBytes(),
	})
	if ensureErr != nil || result.State != runtimeinstall.OperationStatePausedForAdministrator {
		t.Fatalf("authority failure = state:%s err:%v", result.State, ensureErr)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	provisioner, _ = NewDesktopProvisioner(valid)
	result, ensureErr = newDesktopRuntimeApplication(t, provisioner).Ensure(cancelled, runtimeinstallapp.Command{
		OperationID: "desktop-cancel-1", CanonicalPlan: plan.CanonicalBytes(),
	})
	if ensureErr == nil || result.ErrorCode != runtimeinstallapp.ErrorCodeDeadlineExceeded {
		t.Fatalf("cancelled Ensure() = code:%s err:%v", result.ErrorCode, ensureErr)
	}
}

func TestDesktopProvisionerEveryPhaseRejectsAnUnboundRequestBeforeNativeEffects(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	dependencies := desktopTestDependencies{
		authority: authority, host: desktopHostEvidence(t, authority, true),
		runtime: &desktopRuntimeFake{authority: authority}, consent: &desktopConsentFake{clock: clock},
		consentRepository: &desktopConsentRepositoryFake{}, artifacts: &desktopArtifactFake{authority: authority},
		mutation: &desktopMutationFake{clock: clock}, launcher: &desktopLauncherFake{},
		capabilities: &desktopCapabilitiesFake{}, clock: clock,
	}
	provisioner := newDesktopTestProvisioner(t, dependencies)
	request := runtimeinstallapp.Request{}
	phases := []struct {
		name string
		run  func(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error)
	}{
		{name: "detect host", run: provisioner.DetectHost},
		{name: "detect runtime", run: provisioner.DetectRuntime},
		{name: "plan runtime", run: provisioner.PlanRuntime},
		{name: "await consent", run: provisioner.AwaitRuntimeConsent},
		{name: "acquire runtime", run: provisioner.AcquireRuntime},
		{name: "verify artifact", run: provisioner.VerifyRuntimeArtifact},
		{name: "install prerequisites", run: provisioner.InstallPrerequisites},
		{name: "install runtime", run: provisioner.InstallRuntime},
		{name: "await terms", run: provisioner.AwaitThirdPartyTerms},
		{name: "start runtime", run: provisioner.StartRuntime},
		{name: "verify capabilities", run: provisioner.VerifyRuntimeCapabilities},
	}
	for _, phase := range phases {
		phase := phase
		t.Run(phase.name, func(t *testing.T) {
			if _, err := phase.run(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
				t.Fatalf("unbound phase error=%v", err)
			}
		})
	}
	if dependencies.consent.calls != 0 || dependencies.artifacts.acquireCalls != 0 ||
		dependencies.artifacts.verifyCalls != 0 || len(dependencies.mutation.operations) != 0 ||
		dependencies.launcher.calls != 0 || dependencies.capabilities.calls != 0 {
		t.Fatal("unbound requests reached a native effect")
	}
}

func TestDesktopProvisionerInternalMappingsPreserveCancellationAndTypedDecisions(t *testing.T) {
	t.Parallel()
	provisioner := &DesktopProvisioner{}
	for _, decision := range []error{runtimeport.ErrDesktopConsentDeclined, runtimeport.ErrDesktopConsentUnavailable} {
		if _, err := provisioner.desktopConsentError(context.Background(), decision); err != nil {
			t.Fatalf("typed consent decision %v returned error %v", decision, err)
		}
	}
	if _, err := provisioner.desktopConsentError(context.Background(), errors.New("private consent detail")); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("unclassified consent error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provisioner.desktopConsentError(cancelled, errors.New("private consent detail")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled consent error = %v", err)
	}
	for _, safe := range []error{ErrUnsupportedHost, ErrAdministratorRequired, ErrRuntimeConflict, ErrProvisionIntegrity, ErrProbeFailed} {
		if observed := sanitizeDesktopBoundary(context.Background(), safe, errors.New("fallback")); !errors.Is(observed, safe) {
			t.Fatalf("safe boundary error %v became %v", safe, observed)
		}
	}
	if observed := sanitizeDesktopBoundary(context.Background(), errors.New("private"), ErrProbeFailed); !errors.Is(observed, ErrProbeFailed) {
		t.Fatalf("private boundary error = %v", observed)
	}
	if observed := sanitizeDesktopBoundary(cancelled, ErrProbeFailed, ErrProvisionIntegrity); !errors.Is(observed, context.Canceled) {
		t.Fatalf("boundary cancellation = %v", observed)
	}

	provisioner.clock = &fakeClock{now: time.Now()}
	provisioner.nonces = desktopNonceFake{nonce: runtimeport.Nonce{1}}
	if _, _, err := provisioner.freshNonce(context.Background()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("non-UTC clock error = %v", err)
	}
	provisioner.clock = &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	provisioner.nonces = desktopNonceFake{err: errors.New("entropy detail")}
	if _, _, err := provisioner.freshNonce(context.Background()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nonce source error = %v", err)
	}
	provisioner.nonces = desktopNonceFake{}
	if _, _, err := provisioner.freshNonce(context.Background()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero nonce error = %v", err)
	}
	if _, err := provisioner.completed(runtimeinstallapp.Request{}, runtimeport.DesktopAuthority{}, runtimeinstall.Hash{}, runtimeinstall.OwnershipUnknown); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero completion error = %v", err)
	}
}

type desktopTestDependencies struct {
	authority                  runtimeport.DesktopAuthority
	host                       runtimeport.DesktopHostEvidence
	runtime                    *desktopRuntimeFake
	consent                    *desktopConsentFake
	consentRepository          *desktopConsentRepositoryFake
	artifacts                  *desktopArtifactFake
	mutation                   *desktopMutationFake
	launcher                   *desktopLauncherFake
	capabilities               *desktopCapabilitiesFake
	clock                      *fakeClock
	consentAuthenticatorError  error
	mutationAuthenticatorError error
	mutationReplayError        error
}

type desktopNonceFake struct {
	nonce runtimeport.Nonce
	err   error
}

func (f desktopNonceFake) NewPrivilegeNonce(context.Context) (runtimeport.Nonce, error) {
	return f.nonce, f.err
}

func newDesktopTestProvisioner(t testing.TB, input desktopTestDependencies) *DesktopProvisioner {
	t.Helper()
	provisioner, err := NewDesktopProvisioner(desktopDependenciesForTest(t, input))
	if err != nil {
		t.Fatal(err)
	}
	return provisioner
}

func desktopDependenciesForTest(t testing.TB, input desktopTestDependencies) DesktopDependencies {
	t.Helper()
	return DesktopDependencies{
		Authority: desktopAuthorityResolverFake{authority: input.authority},
		Host:      desktopHostFake{evidence: input.host}, Runtime: input.runtime, Consent: input.consent,
		ConsentAuthenticator: desktopConsentAuthenticatorFake{err: input.consentAuthenticatorError},
		ConsentRepository:    input.consentRepository, Artifacts: input.artifacts, ArtifactVerifier: input.artifacts,
		Mutation: input.mutation, MutationAuthenticator: desktopMutationAuthenticatorFake{err: input.mutationAuthenticatorError},
		MutationReplay: desktopMutationReplayFake{err: input.mutationReplayError},
		Launcher:       input.launcher, Capabilities: input.capabilities, Nonces: &incrementingNonces{}, Clock: input.clock,
	}
}

func newDesktopRuntimeApplication(t testing.TB, provisioner *DesktopProvisioner) *runtimeinstallapp.Application {
	t.Helper()
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: &memoryRuntimeRepository{}, Host: provisioner, Detector: provisioner, Catalog: provisioner,
		Consent: provisioner, Fetcher: provisioner, Verifier: provisioner, Prerequisites: provisioner,
		Installer: provisioner, Terms: provisioner, Controller: provisioner, Capabilities: provisioner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

type desktopAuthorityResolverFake struct {
	authority runtimeport.DesktopAuthority
	err       error
}

func (r desktopAuthorityResolverFake) ResolveDesktopAuthority(context.Context, []byte) (runtimeport.DesktopAuthority, error) {
	return r.authority, r.err
}

type desktopHostFake struct {
	evidence runtimeport.DesktopHostEvidence
	err      error
}

func (p desktopHostFake) ProbeDesktopHost(context.Context, runtimeport.DesktopAuthority) (runtimeport.DesktopHostEvidence, error) {
	return p.evidence, p.err
}

type desktopRuntimeFake struct {
	mu        sync.Mutex
	authority runtimeport.DesktopAuthority
	calls     int
	err       error
	conflict  bool
}

func (f *desktopRuntimeFake) InspectDesktopRuntime(
	context.Context,
	runtimeinstall.Plan,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopRuntimeEvidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return runtimeport.DesktopRuntimeEvidence{}, f.err
	}
	if f.calls == 1 {
		return runtimeport.NewDesktopRuntimeEvidence(runtimeport.DesktopRuntimeEvidenceInput{
			Condition: runtimeinstall.RuntimeConditionAbsent,
		})
	}
	input := desktopRuntimeEvidenceInput(f.authority)
	if f.conflict {
		input.TCPListener = true
	}
	return runtimeport.NewDesktopRuntimeEvidence(input)
}

type desktopConsentFake struct {
	mu    sync.Mutex
	clock *fakeClock
	calls int
	err   error
}

func (f *desktopConsentFake) AwaitDesktopConsent(
	_ context.Context,
	request runtimeport.DesktopConsentRequest,
) (runtimeport.DesktopConsentReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return runtimeport.DesktopConsentReceipt{}, f.err
	}
	authority := request.Authority()
	signature := bytes.Repeat([]byte{0x41}, 64)
	return runtimeport.NewDesktopConsentReceipt(runtimeport.DesktopConsentReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(), PlanDigest: authority.PlanDigest(),
		TermsDigest: authority.Terms().Digest(), PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(24 * time.Hour),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	})
}

type desktopConsentAuthenticatorFake struct{ err error }

func (f desktopConsentAuthenticatorFake) VerifyDesktopConsent(
	context.Context,
	runtimeport.DesktopConsentRequest,
	runtimeport.DesktopConsentReceipt,
) error {
	return f.err
}

func (f desktopConsentAuthenticatorFake) VerifyStoredDesktopConsent(
	context.Context,
	runtimeport.DesktopAuthority,
	runtimeport.DesktopConsentReceipt,
) error {
	return f.err
}

type desktopConsentRepositoryFake struct {
	mu       sync.Mutex
	receipt  runtimeport.DesktopConsentReceipt
	stores   int
	storeErr error
	loadErr  error
}

func (f *desktopConsentRepositoryFake) StoreDesktopConsent(
	_ context.Context,
	_ string,
	receipt runtimeport.DesktopConsentReceipt,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stores++
	if f.storeErr != nil {
		return f.storeErr
	}
	f.receipt = receipt
	return nil
}

func (f *desktopConsentRepositoryFake) LoadDesktopConsent(
	context.Context,
	string,
	runtimeinstall.Hash,
) (runtimeport.DesktopConsentReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.receipt, f.loadErr
}

type desktopArtifactFake struct {
	mu                sync.Mutex
	authority         runtimeport.DesktopAuthority
	acquireCalls      int
	verifyCalls       int
	forgeAcquisition  bool
	forgeVerification bool
	err               error
}

func (f *desktopArtifactFake) AcquireDesktopArtifact(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquireCalls++
	return f.evidence(false, f.forgeAcquisition)
}

func (f *desktopArtifactFake) VerifyDesktopArtifact(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	return f.evidence(true, f.forgeVerification)
}

func (f *desktopArtifactFake) evidence(native, forged bool) (runtimeport.DesktopArtifactEvidence, error) {
	if f.err != nil {
		return runtimeport.DesktopArtifactEvidence{}, f.err
	}
	authorityDigest := f.authority.Digest()
	if forged {
		authorityDigest = runtimeinstall.Sum([]byte("forged-authority"))
	}
	publisher := f.authority.Publisher()
	input := runtimeport.DesktopArtifactEvidenceInput{
		AuthorityDigest: authorityDigest, Path: f.authority.ArtifactPath(), SHA256: f.authority.ArtifactSHA256(),
		Bytes: f.authority.ArtifactBytes(), SourceURL: f.authority.ArtifactSourceURL(), TLSVerified: true,
		NativeVerified: native,
	}
	if native {
		input.PublisherKind = publisher.Kind()
		input.PublisherIdentity = publisher.Identity()
		input.CertificateSHA256 = publisher.CertificateSHA256()
	}
	return runtimeport.NewDesktopArtifactEvidence(input)
}

type desktopMutationFake struct {
	mu                         sync.Mutex
	clock                      *fakeClock
	operations                 []runtimeport.DesktopMutationOperation
	prerequisiteArtifactDigest runtimeinstall.Hash
	installArtifactDigest      runtimeinstall.Hash
	rebootOnPrerequisites      runtimeinstall.Hash
	err                        error
}

func (f *desktopMutationFake) ExecuteDesktopMutation(
	_ context.Context,
	request runtimeport.DesktopMutationRequest,
) (runtimeport.DesktopMutationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, request.Operation())
	if request.Operation() == runtimeport.DesktopMutationInstallPrerequisites {
		f.prerequisiteArtifactDigest = request.ArtifactDigest()
	} else {
		f.installArtifactDigest = request.ArtifactDigest()
	}
	if f.err != nil {
		return runtimeport.DesktopMutationReceipt{}, f.err
	}
	exitCode := uint32(0)
	reboot := runtimeinstall.Hash{}
	if request.Operation() == runtimeport.DesktopMutationInstallPrerequisites && !f.rebootOnPrerequisites.IsZero() {
		exitCode = 3010
		reboot = f.rebootOnPrerequisites
	}
	signature := bytes.Repeat([]byte{0x42}, 64)
	return runtimeport.NewDesktopMutationReceipt(runtimeport.DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(), Nonce: request.Nonce(),
		ExitCode: exitCode, PostState: request.ExpectedState(), RebootReceipt: reboot,
		CompletedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(5 * time.Minute),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	})
}

type desktopMutationAuthenticatorFake struct{ err error }

func (f desktopMutationAuthenticatorFake) VerifyDesktopMutation(
	context.Context,
	runtimeport.DesktopMutationRequest,
	runtimeport.DesktopMutationReceipt,
) error {
	return f.err
}

type desktopMutationReplayFake struct{ err error }

func (f desktopMutationReplayFake) ConsumeDesktopMutation(
	context.Context,
	runtimeport.Nonce,
	runtimeinstall.Hash,
) error {
	return f.err
}

type desktopLauncherFake struct {
	mu    sync.Mutex
	calls int
	zero  bool
	err   error
}

func (f *desktopLauncherFake) LaunchDesktopRuntime(context.Context, runtimeport.DesktopAuthority) (runtimeinstall.Hash, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return runtimeinstall.Hash{}, f.err
	}
	if f.zero {
		return runtimeinstall.Hash{}, nil
	}
	return runtimeinstall.Sum([]byte("desktop-launch")), nil
}

type desktopCapabilitiesFake struct {
	mu    sync.Mutex
	calls int
	zero  bool
	err   error
}

func (f *desktopCapabilitiesFake) VerifyDesktopCapabilities(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return runtimeinstall.Hash{}, f.err
	}
	if f.zero {
		return runtimeinstall.Hash{}, nil
	}
	return runtimeinstall.Sum([]byte("desktop-capabilities")), nil
}

func desktopAdapterAuthority(t testing.TB, platform runtimeinstall.Platform) (runtimeinstall.Plan, runtimeport.DesktopAuthority) {
	t.Helper()
	architecture := runtimeinstall.ArchitectureARM64
	if platform == runtimeinstall.PlatformWindows {
		architecture = runtimeinstall.ArchitectureAMD64
	}
	host, err := runtimeinstall.NewHostCapabilities(
		platform, architecture, "26.0", true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		platform, architecture, "docker_desktop", "4.70.0", "stable", 7,
		runtimeinstall.Sum([]byte("desktop-catalog-"+platform.String())), desktopTerms(runtimeinstall.Sum([]byte("docker-terms"))),
		500<<20, 2<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	input := runtimeport.DesktopAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), Platform: platform, Architecture: architecture,
		PrincipalID: "uid:501", UserName: "agentmemory", MachineDigest: runtimeinstall.Sum([]byte("desktop-machine")),
		HomeDirectory: "/Users/agentmemory", OSProduct: "macos", MinimumOSVersion: "26.0", MaximumOSVersion: "26.9.9",
		MinimumBuild: 25_000, MaximumBuild: 25_999, MinimumCPUs: 4, MinimumTotalMemory: 16 << 30,
		MinimumAvailableMemory: 12 << 30, MinimumFreeDisk: 30 << 30, RuntimeVersion: "4.70.0",
		EngineVersion: "29.6.1", ComposeVersion: "5.1.4", Endpoint: "unix:///Users/agentmemory/.docker/run/docker.sock",
		ArtifactPath:   "/Users/agentmemory/Library/Caches/AgentMemory/runtime/Docker.dmg",
		ArtifactSHA256: runtimeinstall.Sum([]byte("docker-desktop-artifact")), ArtifactBytes: 500 << 20,
		ArtifactSourceURL: "https://desktop.docker.com/mac/main/arm64/Docker.dmg",
		Publisher: runtimeport.DesktopPublisherInput{
			Kind: runtimeport.DesktopPublisherAppleNotarized, Identity: "developer-id-application-docker-inc-9bnsxjn65r",
			SigningKeyIdentity: "apple-developer-id-9bnsxjn65r", PackageIdentity: "com.docker.docker",
			CertificateSHA256: runtimeinstall.Sum([]byte("docker-apple-certificate")),
		},
		Terms: runtimeport.DesktopTermsInput{
			ID: "docker-subscription-service-agreement", Version: "2025.07.02",
			URL: "https://www.docker.com/legal/docker-subscription-service-agreement/", Digest: runtimeinstall.Sum([]byte("docker-terms")),
		},
		InstallerArguments: []string{"--accept-license", "--user=agentmemory"}, ApplicationPath: "/Applications/Docker.app",
		ApplicationExecutable: "/Applications/Docker.app/Contents/MacOS/Docker Desktop",
		DockerCLIPath:         "/Applications/Docker.app/Contents/Resources/bin/docker",
		ComposePluginPath:     "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
		ProbeImage:            "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:" + runtimeinstall.Sum([]byte("desktop-probe-image")).String(),
		ProbeImageDigest:      runtimeinstall.Sum([]byte("desktop-probe-image")), ProbeContractVersion: "1",
		CapabilityPolicyDigest: runtimeinstall.Sum([]byte("desktop-capability-policy")), VendorUIMandatory: false,
	}
	if platform == runtimeinstall.PlatformWindows {
		input.PrincipalID = "sid:S-1-5-21-1000-1001-1002-1003"
		input.UserName = "Agent User"
		input.HomeDirectory = `C:\Users\Agent User`
		input.OSProduct = "windows-11"
		input.MinimumOSVersion, input.MaximumOSVersion = "10.0.0", "10.0.0"
		input.MinimumBuild, input.MaximumBuild = 22_631, 26_199
		input.Endpoint = "npipe:////./pipe/docker_engine"
		input.ArtifactPath = `C:\Users\Agent User\AppData\Local\AgentMemory\runtime\Docker Desktop Installer.exe`
		input.ArtifactSourceURL = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
		input.Publisher = runtimeport.DesktopPublisherInput{
			Kind: runtimeport.DesktopPublisherAuthenticode, Identity: "microsoft-authenticode-docker-inc",
			SigningKeyIdentity: "docker-authenticode-2026", PackageIdentity: "com.docker.docker",
			CertificateSHA256: runtimeinstall.Sum([]byte("docker-windows-certificate")),
		}
		input.InstallerArguments = []string{"install", "--user", "--quiet", "--accept-license", "--backend=wsl-2", "--no-windows-containers"}
		input.ApplicationPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop`
		input.ApplicationExecutable = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe`
		input.DockerCLIPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe`
		input.ComposePluginPath = `C:\Users\Agent User\AppData\Local\Programs\DockerDesktop\resources\cli-plugins\docker-compose.exe`
		input.RebootExitCodes = []uint32{1641, 3010}
		input.WindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}
		input.MinimumWSLVersion = "2.1.5"
	}
	authority, err := runtimeport.NewDesktopAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	return plan, authority
}

func desktopHostEvidence(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	prerequisitesReady bool,
) runtimeport.DesktopHostEvidence {
	t.Helper()
	input := runtimeport.DesktopHostEvidenceInput{
		Platform: authority.Platform(), Architecture: authority.Architecture(), OSProduct: authority.OSProduct(),
		OSVersion: authority.MinimumOSVersion(), Build: authority.MinimumBuild(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), CPUs: authority.MinimumCPUs(), TotalMemory: authority.MinimumTotalMemory(),
		AvailableMemory: authority.MinimumAvailableMemory(), FreeDisk: authority.MinimumFreeDisk(),
		Virtualization: true, LocalFilesystem: true, AtRestEncryption: true,
	}
	if authority.Platform() == runtimeinstall.PlatformWindows && prerequisitesReady {
		input.EnabledWindowsFeatures = authority.WindowsFeatures()
		input.WSLVersion = authority.MinimumWSLVersion()
	}
	evidence, err := runtimeport.NewDesktopHostEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func desktopRuntimeEvidenceInput(authority runtimeport.DesktopAuthority) runtimeport.DesktopRuntimeEvidenceInput {
	return runtimeport.DesktopRuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Ownership: runtimeinstall.OwnershipReusedExternal,
		Product: "docker_desktop", RuntimeVersion: authority.RuntimeVersion(), EngineVersion: authority.EngineVersion(),
		ComposeVersion: authority.ComposeVersion(), Endpoint: authority.Endpoint(), ApplicationPresent: true,
		ApplicationRunning: true, PublisherVerified: true, LocalEndpoint: true, LinuxContainers: true,
		UnrelatedWorkloads: authority.UnrelatedWorkloads(),
	}
}
