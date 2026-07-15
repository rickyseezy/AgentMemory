package runtimeprovision

import (
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001DesktopRuntimeRemovalPresenceReprovesPublisherOrExactAbsence(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopRemovalPlanFixture(t, platform)
			for _, present := range []bool{true, false} {
				evidenceInput := runtimeport.DesktopInstalledApplicationEvidenceInput{
					AuthorityDigest: authority.Digest(), Present: present,
				}
				if present {
					publisher := authority.Publisher()
					evidenceInput.RuntimeVersion = authority.RuntimeVersion()
					evidenceInput.PublisherKind = publisher.Kind()
					evidenceInput.PublisherIdentity = publisher.Identity()
					evidenceInput.CertificateSHA256 = publisher.CertificateSHA256()
					evidenceInput.NativeVerified = true
				}
				evidence, err := runtimeport.NewDesktopInstalledApplicationEvidence(evidenceInput)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := NewDesktopRuntimeRemovalPresenceVerifier(
					desktopAuthorityResolverFake{authority: authority},
					desktopInstalledApplicationFake{evidence: evidence},
				)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := verifier.InspectManagedRuntime(t.Context(), plan)
				if err != nil || proof.Absent == present || proof.PlanDigest != plan.Digest() ||
					proof.OwnershipDigest != plan.OwnershipRecordDigest() || proof.EvidenceDigest.IsZero() {
					t.Fatalf("presence proof = %+v/%v", proof, err)
				}
			}
		})
	}
}

func TestPF001DesktopRuntimeRemovalPresenceFailsClosedOnSubstitutedAuthorityOrProbe(t *testing.T) {
	t.Parallel()
	plan, authority := desktopRemovalPlanFixture(t, runtimeinstall.PlatformDarwin)
	_, foreign := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	for name, test := range map[string]struct {
		resolver desktopAuthorityResolverFake
		probe    desktopInstalledApplicationFake
	}{
		"resolver": {resolver: desktopAuthorityResolverFake{authority: foreign}},
		"probe": {
			resolver: desktopAuthorityResolverFake{authority: authority},
			probe:    desktopInstalledApplicationFake{err: errors.New("native probe failed")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			verifier, err := NewDesktopRuntimeRemovalPresenceVerifier(test.resolver, test.probe)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.InspectManagedRuntime(t.Context(), plan); err == nil {
				t.Fatal("substituted presence evidence was accepted")
			}
		})
	}
	if verifier, err := NewDesktopRuntimeRemovalPresenceVerifier(nil, desktopInstalledApplicationFake{}); err == nil || verifier != nil {
		t.Fatal("incomplete desktop presence verifier was accepted")
	}
}

func desktopRemovalPlanFixture(
	t testing.TB,
	platform runtimeinstall.Platform,
) (runtimeremoval.Plan, runtimeport.DesktopAuthority) {
	t.Helper()
	plan, authority, _, _ := desktopRemovalComponentsFixture(t, platform)
	return plan, authority
}

func desktopRemovalComponentsFixture(
	t testing.TB,
	platform runtimeinstall.Platform,
) (
	runtimeremoval.Plan,
	runtimeport.DesktopAuthority,
	runtimeinstall.RuntimeOwnershipRecord,
	runtimeremoval.DependencyScan,
) {
	t.Helper()
	runtimePlan, authority := desktopAdapterAuthority(t, platform)
	operation, err := runtimeinstall.NewOperation("019f60a0-1111-7abc-8123-0123456789ab", runtimePlan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = authority.ArtifactSHA256()
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
	publisher := authority.Publisher()
	ownershipAuthority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: runtimePlan.Product(), Version: runtimePlan.Version(), Channel: runtimePlan.Channel(),
		Endpoint: authority.Endpoint(), Context: "explicit-local-endpoint", Publisher: publisher.Identity(),
		PublisherDigest: publisher.CertificateSHA256(), ArtifactDigest: authority.ArtifactSHA256(),
		Components: []string{"docker-desktop@" + authority.RuntimeVersion()},
		Settings:   []string{"application:" + publisher.PackageIdentity()},
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
			Kind: kind, Complete: true, EvidenceDigest: runtimeinstall.Sum([]byte("empty-" + kind.String())),
		})
	}
	scan, err := runtimeremoval.NewDependencyScan(runtimeremoval.DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(), Proofs: proofs,
	})
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	plan, err := runtimeremoval.NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, scan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, authority, ownership, scan
}
