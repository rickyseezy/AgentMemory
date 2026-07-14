package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestCatalogLinuxArtifactAcquirerReservesAndRetainsExactSignedSet(t *testing.T) {
	_, authority := adapterAuthority(t)
	plan := adapterLinuxArtifactPlan(t, authority)
	cas := successfulLinuxArtifactCAS(plan)
	acquirer, err := newCatalogLinuxArtifactAcquirer(&artifactPlanProjectorFake{plan: plan}, cas)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := acquirer.AcquireLinuxArtifacts(context.Background(), authority)
	if err != nil {
		t.Fatalf("AcquireLinuxArtifacts() error = %v", err)
	}
	if !evidence.AcquiredFor(authority) || evidence.VerifiedFor(authority) || evidence.Digest().IsZero() {
		t.Fatalf("unexpected acquisition evidence: acquired=%t verified=%t", evidence.AcquiredFor(authority), evidence.VerifiedFor(authority))
	}
	if cas.reserveCalls != 1 || cas.acquireCalls != 1 ||
		cas.reserveCommand.OperationID != linuxArtifactOperationID(authority) ||
		cas.acquireCommand.OperationID != cas.reserveCommand.OperationID ||
		!cas.acquireCommand.Plan.Digest().Equal(plan.Digest()) {
		t.Fatalf("unexpected CAS calls: reserve=%d acquire=%d", cas.reserveCalls, cas.acquireCalls)
	}
}

func TestCatalogLinuxArtifactAcquirerRejectsBoundarySubstitution(t *testing.T) {
	_, authority := adapterAuthority(t)
	validPlan := adapterLinuxArtifactPlan(t, authority)
	otherPlan := adapterLinuxArtifactPlanWithDigest(t, releaseinventory.DigestBytes([]byte("substituted-plan")))
	validCAS := func() *linuxArtifactCASFake { return successfulLinuxArtifactCAS(validPlan) }
	tests := []struct {
		name      string
		projector *artifactPlanProjectorFake
		cas       *linuxArtifactCASFake
		want      error
	}{
		{name: "projection failure", projector: &artifactPlanProjectorFake{err: errors.New("projection failed")}, cas: validCAS(), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "plan substitution", projector: &artifactPlanProjectorFake{plan: otherPlan}, cas: validCAS(), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "reservation unavailable", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: &linuxArtifactCASFake{reserveErr: &artifactapp.Error{Code: artifactapp.ErrorReservation}}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "source unavailable", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: &linuxArtifactCASFake{reserveErr: &artifactapp.Error{Code: artifactapp.ErrorSource}}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "repository unavailable", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: &linuxArtifactCASFake{reserveErr: &artifactapp.Error{Code: artifactapp.ErrorRepository}}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "store unavailable", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: &linuxArtifactCASFake{reserveErr: &artifactapp.Error{Code: artifactapp.ErrorStore}}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "reservation integrity error", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: &linuxArtifactCASFake{reserveErr: &artifactapp.Error{Code: artifactapp.ErrorIntegrity}}, want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong reserved bytes", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.reserveResult.ReservedBytes++ }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "missing reservation evidence", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.reserveResult.AggregateEvidence = releaseinventory.Digest{} }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "acquisition failure", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireErr = errors.New("failed") }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong completed count", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.CompletedArtifacts = 0 }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "missing verified object", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.VerifiedArtifacts = nil }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong object id", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.VerifiedArtifacts[0].ID = "other" }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong object digest", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) {
			cas.acquireResult.VerifiedArtifacts[0].Digest = releaseinventory.DigestBytes([]byte("other"))
		}), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong object size", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.VerifiedArtifacts[0].Size++ }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "wrong content key", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.VerifiedArtifacts[0].ContentKey = "sha256/00/other" }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "missing acquisition evidence", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.AggregateEvidence = releaseinventory.Digest{} }), want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "released reservation", projector: &artifactPlanProjectorFake{plan: validPlan}, cas: mutatedLinuxArtifactCAS(validPlan, func(cas *linuxArtifactCASFake) { cas.acquireResult.ReservationRetained = false }), want: runtimeport.ErrLinuxArtifactIntegrity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acquirer, err := newCatalogLinuxArtifactAcquirer(test.projector, test.cas)
			if err != nil {
				t.Fatal(err)
			}
			_, err = acquirer.AcquireLinuxArtifacts(context.Background(), authority)
			if !errors.Is(err, test.want) {
				t.Fatalf("AcquireLinuxArtifacts() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogLinuxArtifactAcquirerRejectsInvalidCallsAndDependencies(t *testing.T) {
	_, authority := adapterAuthority(t)
	plan := adapterLinuxArtifactPlan(t, authority)
	validProjector := &artifactPlanProjectorFake{plan: plan}
	validCAS := successfulLinuxArtifactCAS(plan)
	var nilProjector *artifactPlanProjectorFake
	var nilCAS *linuxArtifactCASFake
	for _, dependencies := range []struct {
		projector linuxArtifactPlanProjector
		cas       LinuxArtifactCAS
	}{{nil, validCAS}, {nilProjector, validCAS}, {validProjector, nil}, {validProjector, nilCAS}} {
		if _, err := newCatalogLinuxArtifactAcquirer(dependencies.projector, dependencies.cas); err == nil {
			t.Fatal("newCatalogLinuxArtifactAcquirer() accepted an absent dependency")
		}
	}
	if _, err := NewCatalogLinuxArtifactAcquirer(runtimecatalogapp.VerifiedCatalog{}, validCAS); err == nil {
		t.Fatal("NewCatalogLinuxArtifactAcquirer() accepted an unverified catalog")
	}
	acquirer, err := newCatalogLinuxArtifactAcquirer(validProjector, validCAS)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = acquirer.AcquireLinuxArtifacts(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if _, err = acquirer.AcquireLinuxArtifacts(hostileNilContext(), authority); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err = acquirer.AcquireLinuxArtifacts(context.Background(), runtimeport.LinuxAuthority{}); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("invalid authority error = %v", err)
	}
	var nilReceiver *CatalogLinuxArtifactAcquirer
	if _, err = nilReceiver.AcquireLinuxArtifacts(context.Background(), authority); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("nil receiver error = %v", err)
	}
}

// hostileNilContext models an invalid third-party boundary call without
// teaching static analysis that application code should pass nil contexts.
func hostileNilContext() context.Context { return nil }

func adapterLinuxArtifactPlan(t *testing.T, authority runtimeport.LinuxAuthority) artifactacquisition.Plan {
	t.Helper()
	return adapterLinuxArtifactPlanWithDigest(t, releaseinventory.Digest(authority.ArtifactDigest()))
}

func adapterLinuxArtifactPlanWithDigest(t *testing.T, planDigest releaseinventory.Digest) artifactacquisition.Plan {
	t.Helper()
	contents := []byte("exact-package")
	digest := releaseinventory.DigestBytes(contents)
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: planDigest,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "docker-ce", Digest: digest, Size: uint64(len(contents)),
			Sources: []string{"https://download.docker.com/linux/ubuntu/pool/stable/docker-ce.deb"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: uint64(len(contents)), Digest: digest}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: uint64(len(contents)), RollbackHeadroomBytes: 11,
			SafetyHeadroomBytes: 13, RequiredBytes: uint64(len(contents)) + 24,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type artifactPlanProjectorFake struct {
	plan artifactacquisition.Plan
	err  error
}

func (f *artifactPlanProjectorFake) ProjectLinuxArtifactPlan(runtimeport.LinuxAuthority) (artifactacquisition.Plan, error) {
	return f.plan, f.err
}

type linuxArtifactCASFake struct {
	reserveResult  artifactapp.ReserveResult
	reserveErr     error
	acquireResult  artifactapp.AcquireResult
	acquireErr     error
	reserveCommand artifactapp.Command
	acquireCommand artifactapp.Command
	reserveCalls   int
	acquireCalls   int
}

func (f *linuxArtifactCASFake) ReserveSpace(_ context.Context, command artifactapp.Command) (artifactapp.ReserveResult, error) {
	f.reserveCalls++
	f.reserveCommand = command
	return f.reserveResult, f.reserveErr
}

func (f *linuxArtifactCASFake) Acquire(_ context.Context, command artifactapp.Command) (artifactapp.AcquireResult, error) {
	f.acquireCalls++
	f.acquireCommand = command
	return f.acquireResult, f.acquireErr
}

func successfulLinuxArtifactCAS(plan artifactacquisition.Plan) *linuxArtifactCASFake {
	artifact := plan.Artifacts()[0]
	return &linuxArtifactCASFake{
		reserveResult: artifactapp.ReserveResult{
			ReservedBytes:     plan.Totals().RequiredBytes(),
			AggregateEvidence: releaseinventory.DigestBytes([]byte("reservation-evidence")),
		},
		acquireResult: artifactapp.AcquireResult{
			CompletedArtifacts: 1, AggregateEvidence: releaseinventory.DigestBytes([]byte("acquisition-evidence")),
			VerifiedArtifacts: []artifactapp.VerifiedArtifact{{
				ID: artifact.ID(), Digest: artifact.Digest(), Size: artifact.Size(), ContentKey: artifact.ContentKey(),
			}},
			ReservationRetained: true,
		},
	}
}

func mutatedLinuxArtifactCAS(
	plan artifactacquisition.Plan,
	mutate func(*linuxArtifactCASFake),
) *linuxArtifactCASFake {
	cas := successfulLinuxArtifactCAS(plan)
	mutate(cas)
	return cas
}
