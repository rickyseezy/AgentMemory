package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001LinuxRuntimeCompensationReleasesOnlyOwnedAcquisitionState(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	resolver := staticAuthorityResolver{authority: authority}
	ownership, err := NewLinuxOwnershipAuthorityResolver(resolver)
	if err != nil {
		t.Fatal(err)
	}
	request := captureRuntimeCompensationRequest(t, plan, ownership)
	evidence := absentLinuxRuntimeEvidence(t)
	inspector := &stableLinuxCompensationInspector{observations: []RuntimeEvidence{evidence, evidence}}
	artifactPlan := adapterLinuxArtifactPlan(t, authority)
	cas := &runtimeCompensationCASFake{result: successfulCompensationRelease()}
	compensator, err := newLinuxRuntimeCompensator(
		&artifactPlanProjectorFake{plan: artifactPlan}, resolver, inspector, cas,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := compensator.CompensateRuntime(context.Background(), request)
	if err != nil || !receipt.ValidFor(request) || cas.calls != 1 ||
		cas.reason != artifactacquisition.ReleaseReasonCancelled ||
		cas.command.OperationID != linuxArtifactOperationID(authority) ||
		cas.command.Plan.Digest() != artifactPlan.Digest() || len(receipt.RemovedArtifactDigests()) != 0 {
		t.Fatalf("receipt/error/cas = %+v/%v/%+v", receipt, err, cas)
	}
}

func TestPF001LinuxRuntimeCompensationRejectsRuntimeDriftAndForeignOwnership(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	resolver := staticAuthorityResolver{authority: authority}
	ownership, _ := NewLinuxOwnershipAuthorityResolver(resolver)
	request := captureRuntimeCompensationRequest(t, plan, ownership)
	absent := absentLinuxRuntimeEvidence(t)
	running := runningLinuxRuntimeEvidence(t, authority)
	cas := &runtimeCompensationCASFake{result: successfulCompensationRelease()}
	compensator, _ := newLinuxRuntimeCompensator(
		&artifactPlanProjectorFake{plan: adapterLinuxArtifactPlan(t, authority)}, resolver,
		&stableLinuxCompensationInspector{observations: []RuntimeEvidence{absent, running}}, cas,
	)
	if _, err := compensator.CompensateRuntime(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("runtime drift error = %v", err)
	}
	foreignPlan, foreignAuthority := adapterAuthority(t)
	foreignResolver := staticAuthorityResolver{authority: foreignAuthority}
	// Change the resolver result while retaining the original request authority.
	foreignAuthority = adapterLinuxAuthorityForIdentity(
		t, foreignPlan, 0, 1001, 1001, "/home/foreign", "/run/user/1001",
	)
	foreignResolver.authority = foreignAuthority
	foreign, _ := newLinuxRuntimeCompensator(
		&artifactPlanProjectorFake{plan: adapterLinuxArtifactPlan(t, foreignAuthority)}, foreignResolver,
		&stableLinuxCompensationInspector{observations: []RuntimeEvidence{absent, absent}}, cas,
	)
	if _, err := foreign.CompensateRuntime(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("foreign ownership error = %v", err)
	}
}

func TestPF001DesktopRuntimeCompensationPreservesDockerDesktop(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	resolver := desktopAuthorityResolverFake{authority: authority}
	ownership, err := NewDesktopOwnershipAuthorityResolver(resolver)
	if err != nil {
		t.Fatal(err)
	}
	request := captureRuntimeCompensationRequest(t, plan, ownership)
	evidence, err := runtimeport.NewDesktopRuntimeEvidence(runtimeport.DesktopRuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	inspector := &stableDesktopCompensationInspector{observations: []runtimeport.DesktopRuntimeEvidence{evidence, evidence}}
	artifactPlan := adapterDesktopArtifactPlan(t, authority)
	cas := &runtimeCompensationCASFake{result: successfulCompensationRelease()}
	compensator, err := newDesktopRuntimeCompensator(
		&desktopArtifactPlanProjectorFake{plan: artifactPlan}, resolver, inspector, cas,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := compensator.CompensateRuntime(context.Background(), request)
	if err != nil || !receipt.ValidFor(request) || cas.calls != 1 ||
		cas.command.OperationID != desktopArtifactOperationID(authority) ||
		len(receipt.RemovedSettings()) != 0 || len(receipt.RemovedArtifactDigests()) != 0 {
		t.Fatalf("desktop receipt/error/cas = %+v/%v/%+v", receipt, err, cas)
	}
}

type runtimeCompensationCapture struct {
	request runtimeinstallapp.RuntimeCompensationRequest
}

func (c *runtimeCompensationCapture) CompensateRuntime(
	_ context.Context,
	request runtimeinstallapp.RuntimeCompensationRequest,
) (runtimeinstallapp.RuntimeCompensationReceipt, error) {
	c.request = request
	return runtimeinstallapp.RuntimeCompensationReceipt{}, errors.New("captured compensation request")
}

func captureRuntimeCompensationRequest(
	t *testing.T,
	plan runtimeinstall.Plan,
	ownership runtimeinstallapp.RuntimeOwnershipAuthorityResolver,
) runtimeinstallapp.RuntimeCompensationRequest {
	t.Helper()
	operation, err := runtimeinstall.NewOperation("runtime-compensation-capture", plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases()[:5] {
		evidence, evidenceErr := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), runtimeinstall.Hash{}, runtimeinstall.OwnershipUnknown,
		)
		if evidenceErr != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceErr)
		}
	}
	if err := operation.Cancel(); err != nil {
		t.Fatal(err)
	}
	snapshot := operation.Snapshot()
	repository := &memoryRuntimeRepository{snapshot: &snapshot}
	records := &memoryRuntimeOwnershipRepository{}
	capture := &runtimeCompensationCapture{}
	unused := &requestCapturer{}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: repository, OwnershipAuthorities: ownership, OwnershipRecords: records,
		Compensation: capture, Host: unused, Detector: unused, Catalog: unused, Consent: unused,
		Fetcher: unused, Verifier: unused, Prerequisites: unused, Installer: unused,
		Terms: unused, Controller: unused, Capabilities: unused,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = application.Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: operation.ID(), CanonicalPlan: plan.CanonicalBytes(),
	})
	if capture.request.OperationID() != operation.ID() || capture.request.PlanDigest() != plan.Digest() {
		t.Fatal("application did not derive exact compensation authority")
	}
	return capture.request
}

type stableLinuxCompensationInspector struct {
	observations []RuntimeEvidence
	calls        int
}

func (i *stableLinuxCompensationInspector) Inspect(
	context.Context,
	runtimeinstall.Plan,
	runtimeport.LinuxAuthority,
) (RuntimeEvidence, error) {
	if i.calls >= len(i.observations) {
		return RuntimeEvidence{}, ErrProbeFailed
	}
	result := i.observations[i.calls]
	i.calls++
	return result, nil
}

type stableDesktopCompensationInspector struct {
	observations []runtimeport.DesktopRuntimeEvidence
	calls        int
}

func (i *stableDesktopCompensationInspector) InspectDesktopRuntime(
	context.Context,
	runtimeinstall.Plan,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopRuntimeEvidence, error) {
	if i.calls >= len(i.observations) {
		return runtimeport.DesktopRuntimeEvidence{}, runtimeport.ErrDesktopEvidenceIntegrity
	}
	result := i.observations[i.calls]
	i.calls++
	return result, nil
}

type runtimeCompensationCASFake struct {
	result  artifactapp.ReleaseResult
	err     error
	command artifactapp.Command
	reason  artifactacquisition.ReleaseReason
	calls   int
}

func (f *runtimeCompensationCASFake) ReleaseReservationIfPresent(
	_ context.Context,
	command artifactapp.Command,
	reason artifactacquisition.ReleaseReason,
) (artifactapp.ReleaseResult, error) {
	f.calls++
	f.command = command
	f.reason = reason
	return f.result, f.err
}

func successfulCompensationRelease() artifactapp.ReleaseResult {
	return artifactapp.ReleaseResult{
		Version: 4, Reason: artifactacquisition.ReleaseReasonCancelled, Released: true,
		AggregateEvidence: releaseinventory.DigestBytes([]byte("released-runtime-acquisition")),
	}
}

func absentLinuxRuntimeEvidence(t *testing.T) RuntimeEvidence {
	t.Helper()
	endpoint, err := NewEndpointEvidence(false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionAbsent, Endpoint: endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func runningLinuxRuntimeEvidence(t *testing.T, authority runtimeport.LinuxAuthority) RuntimeEvidence {
	t.Helper()
	endpoint, err := NewEndpointEvidence(true, 1, 0o660, true)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
		Workloads: authority.UnrelatedWorkloads(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}
