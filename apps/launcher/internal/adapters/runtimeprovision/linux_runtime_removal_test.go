//go:build darwin || linux

package runtimeprovision

import (
	"errors"
	"slices"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001LinuxRuntimeRemovalPresenceProvesExactPackagesOrCompleteAbsence(t *testing.T) {
	t.Parallel()
	plan, authority, _, _ := linuxRemovalComponentsFixture(t)
	for name, test := range map[string]struct {
		matches bool
		absent  bool
		want    bool
	}{
		"present": {matches: true},
		"absent":  {absent: true, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			probe := &privilegePackageStateProbeStub{
				managedMatches: []bool{test.matches}, managedAbsent: []bool{test.absent},
			}
			verifier, err := NewLinuxRuntimeRemovalPresenceVerifier(
				staticAuthorityResolver{authority: authority}, probe,
			)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := verifier.InspectManagedRuntime(t.Context(), plan)
			if err != nil || proof.Absent != test.want || proof.PlanDigest != plan.Digest() ||
				proof.OwnershipDigest != plan.OwnershipRecordDigest() || proof.EvidenceDigest.IsZero() ||
				probe.managedCalls != 1 || probe.absentCalls != btoi(!test.matches) {
				t.Fatalf("proof=%+v managed=%d absent=%d error=%v", proof, probe.managedCalls, probe.absentCalls, err)
			}
		})
	}
}

func TestPF001LinuxRuntimeRemovalPresenceFailsClosedOnMixedOrUntrustedState(t *testing.T) {
	t.Parallel()
	plan, authority, _, _ := linuxRemovalComponentsFixture(t)
	for name, test := range map[string]struct {
		resolver runtimeport.AuthorityResolver
		probe    PrivilegePackageStateProbe
	}{
		"mixed package state": {
			resolver: staticAuthorityResolver{authority: authority},
			probe:    &privilegePackageStateProbeStub{managedMatches: []bool{false}, managedAbsent: []bool{false}},
		},
		"resolver failure": {
			resolver: staticAuthorityResolver{err: errors.New("signed authority unavailable")},
			probe:    &privilegePackageStateProbeStub{},
		},
		"package database failure": {
			resolver: staticAuthorityResolver{authority: authority},
			probe:    &privilegePackageStateProbeStub{err: errors.New("package database unavailable")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			verifier, err := NewLinuxRuntimeRemovalPresenceVerifier(test.resolver, test.probe)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.InspectManagedRuntime(t.Context(), plan); err == nil {
				t.Fatal("uncertain Linux runtime presence was accepted")
			}
		})
	}
	if verifier, err := NewLinuxRuntimeRemovalPresenceVerifier(nil, &privilegePackageStateProbeStub{}); err == nil || verifier != nil {
		t.Fatal("incomplete Linux presence verifier was accepted")
	}
	if digest, err := linuxRemovalPackageStateDigest(runtimeport.LinuxAuthority{}, false); err == nil || !digest.IsZero() {
		t.Fatalf("invalid package-state digest=%s error=%v", digest, err)
	}
}

func TestPF001LinuxRuntimeRemoverBindsConsentAndScanToAuthenticatedPrivilegeReceipt(t *testing.T) {
	t.Parallel()
	plan, authority, ownership, scan := linuxRemovalComponentsFixture(t)
	clock := &fakeClock{now: time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)}
	broker := &fakePrivilegeBroker{}
	remover, err := NewLinuxRuntimeRemover(LinuxRuntimeRemoverDependencies{
		Authority: staticAuthorityResolver{authority: authority}, Privilege: broker,
		Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
		Nonces: &incrementingNonces{}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	consent := runtimeinstall.Sum([]byte("separate-linux-removal-consent"))
	result, err := remover.removeAuthorizedLinuxRuntime(t.Context(), plan, ownership, scan, consent)
	if err != nil || result.PlanDigest != plan.Digest() || result.OwnershipDigest != ownership.Digest() ||
		result.ExecutionScan != scan.Digest() || result.BeforeDigest.IsZero() || result.EffectDigest.IsZero() ||
		!slices.Equal(broker.operations, []runtimeport.PrivilegeOperation{runtimeport.PrivilegeRemoveManagedPackages}) {
		t.Fatalf("result=%+v operations=%v error=%v", result, broker.operations, err)
	}
}

func TestPF001LinuxRuntimeRemoverFailsClosedOnIncompleteOrSubstitutedBoundaries(t *testing.T) {
	t.Parallel()
	plan, authority, ownership, scan := linuxRemovalComponentsFixture(t)
	clock := &fakeClock{now: time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)}
	consent := runtimeinstall.Sum([]byte("separate-linux-removal-consent"))
	for name, dependencies := range map[string]LinuxRuntimeRemoverDependencies{
		"authority": {
			Authority: staticAuthorityResolver{err: errors.New("substituted")}, Privilege: &fakePrivilegeBroker{},
			Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
			Nonces: &incrementingNonces{}, Clock: clock,
		},
		"receipt": {
			Authority: staticAuthorityResolver{authority: authority}, Privilege: &fakePrivilegeBroker{},
			Authenticator: rejectingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
			Nonces: &incrementingNonces{}, Clock: clock,
		},
		"replay": {
			Authority: staticAuthorityResolver{authority: authority}, Privilege: &fakePrivilegeBroker{},
			Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{err: errors.New("replayed")},
			Nonces: &incrementingNonces{}, Clock: clock,
		},
		"privilege": {
			Authority:     staticAuthorityResolver{authority: authority},
			Privilege:     &fakePrivilegeBroker{err: errors.New("helper unavailable")},
			Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
			Nonces: &incrementingNonces{}, Clock: clock,
		},
		"nonce": {
			Authority: staticAuthorityResolver{authority: authority}, Privilege: &fakePrivilegeBroker{},
			Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
			Nonces: desktopNonceFake{err: errors.New("entropy unavailable")}, Clock: clock,
		},
		"clock": {
			Authority: staticAuthorityResolver{authority: authority}, Privilege: &fakePrivilegeBroker{},
			Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
			Nonces: &incrementingNonces{}, Clock: &fakeClock{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			remover, err := NewLinuxRuntimeRemover(dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := remover.removeAuthorizedLinuxRuntime(t.Context(), plan, ownership, scan, consent); err == nil {
				t.Fatal("substituted Linux removal boundary was accepted")
			}
		})
	}
	if remover, err := NewLinuxRuntimeRemover(LinuxRuntimeRemoverDependencies{}); err == nil || remover != nil {
		t.Fatal("incomplete Linux runtime remover was accepted")
	}
	remover, err := NewLinuxRuntimeRemover(LinuxRuntimeRemoverDependencies{
		Authority: staticAuthorityResolver{authority: authority}, Privilege: &fakePrivilegeBroker{},
		Authenticator: acceptingAuthenticator{}, Replay: &fakeReplayLedger{consumed: map[runtimeport.Nonce]runtimeinstall.Hash{}},
		Nonces: &incrementingNonces{}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remover.RemoveManagedRuntime(t.Context(), runtimeremovalapp.RemovalAuthorization{}); err == nil {
		t.Fatal("zero Linux removal authorization was accepted")
	}
	if digest, err := linuxRemovalAuthorizationDigest(
		runtimeremoval.Plan{}, ownership, scan, consent,
	); err == nil || !digest.IsZero() {
		t.Fatalf("invalid authorization digest=%s error=%v", digest, err)
	}
}

func linuxRemovalComponentsFixture(
	t *testing.T,
) (runtimeremoval.Plan, runtimeport.LinuxAuthority, runtimeinstall.RuntimeOwnershipRecord, runtimeremoval.DependencyScan) {
	t.Helper()
	runtimePlan, authority := adapterAuthority(t)
	operation, err := runtimeinstall.NewOperation("019f60a0-2222-7abc-8123-0123456789ab", runtimePlan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = authority.ArtifactDigest()
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
		}
		evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), runtimePlan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), artifact, ownership,
		)
		if evidenceError != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceError)
		}
	}
	managed, err := runtimeport.ManagedRuntimePackages(authority)
	if err != nil {
		t.Fatal(err)
	}
	components := make([]string, 0, len(managed))
	for _, pkg := range managed {
		components = append(components, pkg.Name()+"@"+pkg.Version())
	}
	slices.Sort(components)
	ownershipAuthority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: runtimePlan.Product(), Version: runtimePlan.Version(), Channel: runtimePlan.Channel(),
		Endpoint: authority.Endpoint(), Context: "explicit-local-endpoint", Publisher: authority.Repository().URL(),
		PublisherDigest: authority.Repository().SigningKeyDigest(), ArtifactDigest: authority.ArtifactDigest(),
		Components: components, Settings: []string{"package_manager:apt", "repository:" + authority.Repository().ID()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := runtimeinstall.NewRuntimeOwnershipRecord(runtimePlan, operation.Snapshot(), ownershipAuthority, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofs := make([]runtimeremoval.DependencyProofInput, 0, len(runtimeremoval.OrderedDependencyKinds()))
	for _, kind := range runtimeremoval.OrderedDependencyKinds() {
		proofs = append(proofs, runtimeremoval.DependencyProofInput{
			Kind: kind, Complete: true, EvidenceDigest: runtimeinstall.Sum([]byte("empty-linux-" + kind.String())),
		})
	}
	scan, err := runtimeremoval.NewDependencyScan(runtimeremoval.DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(), Proofs: proofs,
	})
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := install.NewOperationID("019f60a0-0001-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeremoval.NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, scan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, authority, ownership, scan
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}
