package runtimeprovision

import (
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DesktopRuntimeRemoverBindsSecondConsentAndExhaustiveScanToSignedHelper(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			plan, authority, ownership, scan := desktopRemovalComponentsFixture(t, platform)
			clock := &fakeClock{now: time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)}
			mutation := &desktopMutationFake{clock: clock}
			remover, err := NewDesktopRuntimeRemover(DesktopRuntimeRemoverDependencies{
				Authority: desktopAuthorityResolverFake{authority: authority}, Mutation: mutation,
				MutationAuthenticator: desktopMutationAuthenticatorFake{}, MutationReplay: desktopMutationReplayFake{},
				Nonces: desktopNonceFake{nonce: runtimeport.Nonce{9, 8, 7}}, Clock: clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			consent := runtimeinstall.Sum([]byte("separate-removal-consent"))
			result, err := remover.removeAuthorizedDesktopRuntime(
				t.Context(), plan, ownership, scan, consent,
			)
			if err != nil || result.PlanDigest != plan.Digest() || result.OwnershipDigest != ownership.Digest() ||
				result.ExecutionScan != scan.Digest() || result.BeforeDigest.IsZero() || result.EffectDigest.IsZero() ||
				len(mutation.operations) != 1 || mutation.operations[0] != runtimeport.DesktopMutationRemoveRuntime ||
				mutation.installArtifactDigest != authority.ArtifactSHA256() {
				t.Fatalf("platform=%s result=%+v operations=%v artifact=%s error=%v", platform, result, mutation.operations, mutation.installArtifactDigest, err)
			}
		})
	}
}

func TestPF001DesktopRuntimeRemoverFailsClosedOnAuthorityReceiptAndDependencySubstitution(t *testing.T) {
	t.Parallel()
	plan, authority, ownership, scan := desktopRemovalComponentsFixture(t, runtimeinstall.PlatformDarwin)
	_, foreign := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	clock := &fakeClock{now: time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)}
	consent := runtimeinstall.Sum([]byte("separate-removal-consent"))
	for name, dependencies := range map[string]DesktopRuntimeRemoverDependencies{
		"authority": {
			Authority: desktopAuthorityResolverFake{authority: foreign}, Mutation: &desktopMutationFake{clock: clock},
			MutationAuthenticator: desktopMutationAuthenticatorFake{}, MutationReplay: desktopMutationReplayFake{},
			Nonces: desktopNonceFake{nonce: runtimeport.Nonce{1}}, Clock: clock,
		},
		"authenticator": {
			Authority: desktopAuthorityResolverFake{authority: authority}, Mutation: &desktopMutationFake{clock: clock},
			MutationAuthenticator: desktopMutationAuthenticatorFake{err: errors.New("forged receipt")},
			MutationReplay:        desktopMutationReplayFake{}, Nonces: desktopNonceFake{nonce: runtimeport.Nonce{1}}, Clock: clock,
		},
		"replay": {
			Authority: desktopAuthorityResolverFake{authority: authority}, Mutation: &desktopMutationFake{clock: clock},
			MutationAuthenticator: desktopMutationAuthenticatorFake{},
			MutationReplay:        desktopMutationReplayFake{err: errors.New("replayed receipt")},
			Nonces:                desktopNonceFake{nonce: runtimeport.Nonce{1}}, Clock: clock,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			remover, err := NewDesktopRuntimeRemover(dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := remover.removeAuthorizedDesktopRuntime(t.Context(), plan, ownership, scan, consent); err == nil {
				t.Fatal("substituted removal authority was accepted")
			}
		})
	}
	if remover, err := NewDesktopRuntimeRemover(DesktopRuntimeRemoverDependencies{}); err == nil || remover != nil {
		t.Fatal("incomplete desktop runtime remover was accepted")
	}
	remover, err := NewDesktopRuntimeRemover(DesktopRuntimeRemoverDependencies{
		Authority: desktopAuthorityResolverFake{authority: authority}, Mutation: &desktopMutationFake{clock: clock},
		MutationAuthenticator: desktopMutationAuthenticatorFake{}, MutationReplay: desktopMutationReplayFake{},
		Nonces: desktopNonceFake{nonce: runtimeport.Nonce{1}}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remover.RemoveManagedRuntime(t.Context(), runtimeremovalapp.RemovalAuthorization{}); err == nil {
		t.Fatal("zero application authorization was accepted")
	}
}
