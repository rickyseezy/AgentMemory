package installphase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ArtifactPhasesBindReservationAndFinalCASIntoInstallEvidence(t *testing.T) {
	t.Parallel()
	fixture := newArtifactPhaseFixture(t)
	reserve, err := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := reserve.ReserveSpace(context.Background(), fixture.request)
	parentEvidence, _ := install.ParseDigest(fixture.request.PlanDigest().String())
	reservedAggregate, _ := install.ParseDigest(fixture.artifacts.reserve.AggregateEvidence.Hex())
	if err != nil || reserved.Outcome() != installapp.PhaseOutcomeCompleted ||
		!reserved.InputDigest().Equal(parentEvidence) || !reserved.OutputDigest().Equal(reservedAggregate) {
		t.Fatalf("ReserveSpace()=(%+v,%v)", reserved, err)
	}
	if fixture.artifacts.reserveCommand.OperationID != fixture.request.OperationID().String() ||
		!fixture.artifacts.reserveCommand.Plan.Digest().Equal(fixture.projection.AcquisitionPlan.Digest()) {
		t.Fatal("reservation lost parent operation/acquisition-plan binding")
	}
	if fixture.capacity.reserveCommand.OperationID != fixture.request.OperationID().String() {
		t.Fatal("per-pool capacity was not reserved before artifact reservation")
	}

	compose, err := NewComposeBundlePhase(fixture.plans, fixture.artifacts, fixture.capacity)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := compose.EnsureComposeBundle(context.Background(), fixture.request)
	composeArtifact, _ := fixture.projection.AcquisitionPlan.Artifact(fixture.projection.ComposeArtifactID)
	acquiredAggregate, _ := install.ParseDigest(fixture.artifacts.acquire.AggregateEvidence.Hex())
	composeDigest, _ := install.ParseDigest(composeArtifact.Digest().Hex())
	if err != nil || acquired.Outcome() != installapp.PhaseOutcomeCompleted ||
		!acquired.OutputDigest().Equal(acquiredAggregate) || !acquired.VerifiedArtifactDigest().Equal(composeDigest) {
		t.Fatalf("EnsureComposeBundle()=(%+v,%v)", acquired, err)
	}
	if fixture.artifacts.acquireCommand.OperationID != fixture.request.OperationID().String() ||
		!fixture.artifacts.acquireCommand.Plan.Digest().Equal(fixture.projection.AcquisitionPlan.Digest()) {
		t.Fatal("acquisition lost parent operation/acquisition-plan binding")
	}
	if fixture.capacity.consumedArtifact != "compose" || fixture.capacity.consumeCommand.OperationID != fixture.request.OperationID().String() {
		t.Fatal("expanded lease was not consumed through the explicit materializer boundary")
	}
}

func TestPF001ArtifactPhasesRejectCrossPlanAndManufacturedEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*artifactPhaseFixture)
		invoke func(*artifactPhaseFixture) error
	}{
		{name: "parent digest", mutate: func(value *artifactPhaseFixture) {
			value.projection.ParentPlanDigest, _ = install.BindPlan([]byte("other"))
		}, invoke: invokeReservation},
		{name: "acquisition digest", mutate: func(value *artifactPhaseFixture) {
			value.projection.AcquisitionPlanDigest = install.DigestBytes([]byte("other"))
		}, invoke: invokeReservation},
		{name: "ownership", mutate: func(value *artifactPhaseFixture) {
			value.projection.RuntimeOwnership = install.RuntimeOwnershipUndetermined
		}, invoke: invokeReservation},
		{name: "reservation bytes", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.reserve.ReservedBytes++
		}, invoke: invokeReservation},
		{name: "reservation evidence", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.reserve.AggregateEvidence = releaseinventory.Digest{}
		}, invoke: invokeReservation},
		{name: "compose id", mutate: func(value *artifactPhaseFixture) {
			value.projection.ComposeArtifactID = "missing"
		}, invoke: invokeCompose},
		{name: "aggregate incomplete", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.acquire.CompletedArtifacts = 0
		}, invoke: invokeCompose},
		{name: "reservation not retained", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.acquire.ReservationRetained = false
		}, invoke: invokeCompose},
		{name: "artifact missing", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.acquire.VerifiedArtifacts = nil
		}, invoke: invokeCompose},
		{name: "artifact digest", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.acquire.VerifiedArtifacts[0].Digest = releaseinventory.DigestBytes([]byte("wrong"))
		}, invoke: invokeCompose},
		{name: "aggregate evidence", mutate: func(value *artifactPhaseFixture) {
			value.artifacts.acquire.AggregateEvidence = releaseinventory.Digest{}
		}, invoke: invokeCompose},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newArtifactPhaseFixture(t)
			test.mutate(fixture)
			err := test.invoke(fixture)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != ErrorCodeInvalidBinding {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPF001ArtifactPhasesMapUnsupportedAndRecoverableFailuresWithoutRawDetails(t *testing.T) {
	t.Parallel()
	fixture := newArtifactPhaseFixture(t)
	fixture.artifacts.reserveErr = errors.Join(&artifactapp.Error{Code: artifactapp.ErrorReservation, Op: "reserve"}, artifactapp.ErrReservationUnsupported)
	phase, _ := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	output, err := phase.ReserveSpace(context.Background(), fixture.request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeUnsupportedHost {
		t.Fatalf("unsupported reservation=(%+v,%v)", output, err)
	}

	fixture = newArtifactPhaseFixture(t)
	fixture.artifacts.reserveErr = &artifactapp.Error{Code: artifactapp.ErrorReservation, Op: "/secret/path"}
	phase, _ = NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	output, err = phase.ReserveSpace(context.Background(), fixture.request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeFailedRecoverable || strings.Contains(output.NextSafeAction(), "secret") {
		t.Fatalf("recoverable reservation=(%+v,%v)", output, err)
	}

	fixture = newArtifactPhaseFixture(t)
	fixture.artifacts.acquireErr = &artifactapp.Error{Code: artifactapp.ErrorSource, Op: "https://secret.example"}
	compose, _ := NewComposeBundlePhase(fixture.plans, fixture.artifacts, fixture.capacity)
	output, err = compose.EnsureComposeBundle(context.Background(), fixture.request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeFailedRecoverable || strings.Contains(output.NextSafeAction(), "secret") {
		t.Fatalf("recoverable acquisition=(%+v,%v)", output, err)
	}

	fixture = newArtifactPhaseFixture(t)
	fixture.plans.err = errors.New("/secret/plan")
	phase, _ = NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	_, err = phase.ReserveSpace(context.Background(), fixture.request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != ErrorCodePlanUnavailable || strings.Contains(err.Error(), "secret") {
		t.Fatalf("plan error=%v", err)
	}
}

func TestPF001SpaceReservationPhaseSettlesParentCancellationAndRollback(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		from installapp.ReservationReleaseReason
		want artifactacquisition.ReleaseReason
	}{
		{name: "completed", from: installapp.ReservationReleaseCompleted, want: artifactacquisition.ReleaseReasonCompleted},
		{name: "cancelled", from: installapp.ReservationReleaseCancelled, want: artifactacquisition.ReleaseReasonCancelled},
		{name: "rollback", from: installapp.ReservationReleaseRollback, want: artifactacquisition.ReleaseReasonRollback},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newArtifactPhaseFixture(t)
			phase, _ := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
			if err := phase.ReleaseSpace(context.Background(), fixture.request, test.from); err != nil {
				t.Fatalf("ReleaseSpace() error=%v", err)
			}
			if fixture.artifacts.optionalReleaseReason != test.want ||
				fixture.artifacts.optionalReleaseCommand.OperationID != fixture.request.OperationID().String() ||
				!fixture.artifacts.optionalReleaseCommand.Plan.Digest().Equal(fixture.projection.AcquisitionPlan.Digest()) {
				t.Fatalf("optional release binding/reason=%+v/%v", fixture.artifacts.optionalReleaseCommand, fixture.artifacts.optionalReleaseReason)
			}
			if test.from == installapp.ReservationReleaseCompleted {
				if fixture.capacity.releaseCalls != 1 || fixture.capacity.compensateCalls != 0 {
					t.Fatalf("completed capacity cleanup release=%d compensate=%d", fixture.capacity.releaseCalls, fixture.capacity.compensateCalls)
				}
			} else if fixture.capacity.compensateCalls != 1 || fixture.capacity.releaseCalls != 0 {
				t.Fatalf("rollback capacity cleanup release=%d compensate=%d", fixture.capacity.releaseCalls, fixture.capacity.compensateCalls)
			}
		})
	}

	fixture := newArtifactPhaseFixture(t)
	phase, _ := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	if err := phase.ReleaseSpace(context.Background(), fixture.request, installapp.ReservationReleaseUnknown); err == nil {
		t.Fatal("ReleaseSpace() accepted unknown reason")
	}
	fixture.artifacts.optionalReleaseErr = errors.New("private cleanup detail")
	if err := phase.ReleaseSpace(context.Background(), fixture.request, installapp.ReservationReleaseCancelled); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("ReleaseSpace() error=%v", err)
	}
}

func TestPF001ArtifactPhasesRequireCompleteCapabilitiesAndRequests(t *testing.T) {
	t.Parallel()
	fixture := newArtifactPhaseFixture(t)
	if _, err := NewSpaceReservationPhase(nil, fixture.artifacts, fixture.capacity); err == nil {
		t.Fatal("nil reservation plan query accepted")
	}
	if _, err := NewSpaceReservationPhase(fixture.plans, nil, fixture.capacity); err == nil {
		t.Fatal("nil reservation application accepted")
	}
	if _, err := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, nil); err == nil {
		t.Fatal("nil capacity application accepted")
	}
	if _, err := NewComposeBundlePhase(nil, fixture.artifacts, fixture.capacity); err == nil {
		t.Fatal("nil compose plan query accepted")
	}
	if _, err := NewComposeBundlePhase(fixture.plans, nil, fixture.capacity); err == nil {
		t.Fatal("nil compose application accepted")
	}
	var typedNil *artifactPhaseApplication
	if _, err := NewComposeBundlePhase(fixture.plans, typedNil, fixture.capacity); err == nil {
		t.Fatal("typed-nil artifact application accepted")
	}
	reserve, _ := NewSpaceReservationPhase(fixture.plans, fixture.artifacts, fixture.capacity)
	if _, err := reserve.ReserveSpace(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("invalid reservation request accepted")
	}
	compose, _ := NewComposeBundlePhase(fixture.plans, fixture.artifacts, fixture.capacity)
	if _, err := compose.EnsureComposeBundle(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("invalid compose request accepted")
	}
}

func TestPF001ArtifactPhaseFailureMappingIsClosedAndPrivacySafe(t *testing.T) {
	t.Parallel()
	if _, err := reservationFailure(errors.New("/raw/path")); err == nil {
		t.Fatal("untyped reservation failure became an expected outcome")
	}

	tests := []struct {
		name    string
		err     error
		outcome installapp.PhaseOutcome
		code    ErrorCode
	}{
		{name: "raw", err: errors.New("https://secret.example"), code: ErrorCodeArtifactUnavailable},
		{name: "source", err: &artifactapp.Error{Code: artifactapp.ErrorSource, Op: "raw"}, outcome: installapp.PhaseOutcomeFailedRecoverable},
		{name: "store", err: &artifactapp.Error{Code: artifactapp.ErrorStore, Op: "raw"}, outcome: installapp.PhaseOutcomeFailedRecoverable},
		{name: "integrity", err: &artifactapp.Error{Code: artifactapp.ErrorIntegrity, Op: "raw"}, outcome: installapp.PhaseOutcomeFailedRecoverable},
		{name: "invalid", err: &artifactapp.Error{Code: artifactapp.ErrorInvalidCommand, Op: "raw"}, code: ErrorCodeArtifactUnavailable},
		{name: "reservation", err: &artifactapp.Error{Code: artifactapp.ErrorReservation, Op: "raw"}, code: ErrorCodeArtifactUnavailable},
		{name: "repository", err: &artifactapp.Error{Code: artifactapp.ErrorRepository, Op: "raw"}, code: ErrorCodeArtifactUnavailable},
		{name: "compensation", err: &artifactapp.Error{Code: artifactapp.ErrorCompensation, Op: "raw"}, code: ErrorCodeArtifactUnavailable},
		{name: "unknown", err: &artifactapp.Error{Code: artifactapp.ErrorCode("future"), Op: "raw"}, code: ErrorCodeArtifactUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := acquisitionFailure(test.err)
			if test.outcome != installapp.PhaseOutcomeUnknown {
				if err != nil || output.Outcome() != test.outcome {
					t.Fatalf("result=(%+v,%v)", output, err)
				}
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.code || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
}

func TestPF001ArtifactPhasesRejectEveryResultShapeAndComposePlanFailure(t *testing.T) {
	t.Parallel()
	reservationMutations := []func(*artifactapp.ReserveResult){
		func(value *artifactapp.ReserveResult) { value.Version = 0 },
		func(value *artifactapp.ReserveResult) { value.ReservationID = "r-" + strings.Repeat("f", 64) },
	}
	for _, mutate := range reservationMutations {
		fixture := newArtifactPhaseFixture(t)
		mutate(&fixture.artifacts.reserve)
		if err := invokeReservation(fixture); err == nil {
			t.Fatal("invalid reservation result accepted")
		}
	}

	acquisitionMutations := []func(*artifactapp.AcquireResult){
		func(value *artifactapp.AcquireResult) { value.Version = 0 },
		func(value *artifactapp.AcquireResult) { value.VerifiedArtifacts[0].ID = "unknown" },
		func(value *artifactapp.AcquireResult) { value.VerifiedArtifacts[0].Size++ },
		func(value *artifactapp.AcquireResult) { value.VerifiedArtifacts[0].ContentKey = "sha256/bad" },
	}
	for _, mutate := range acquisitionMutations {
		fixture := newArtifactPhaseFixture(t)
		mutate(&fixture.artifacts.acquire)
		if err := invokeCompose(fixture); err == nil {
			t.Fatal("invalid acquisition result accepted")
		}
	}

	fixture := newArtifactPhaseFixture(t)
	fixture.plans.err = errors.New("raw")
	phase, _ := NewComposeBundlePhase(fixture.plans, fixture.artifacts, fixture.capacity)
	_, err := phase.EnsureComposeBundle(context.Background(), fixture.request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != ErrorCodePlanUnavailable {
		t.Fatalf("compose plan error=%v", err)
	}
}

func TestPF001ArtifactPhaseEvidenceHelpersFailClosed(t *testing.T) {
	t.Parallel()
	output := install.DigestBytes([]byte("output"))
	ownership := install.RuntimeOwnershipReusedExternal
	if _, err := completedOutput(testBinding("bad"), output, ownership, "retain.valid", "installation.continue", "fact", "value"); err == nil {
		t.Fatal("invalid input binding accepted")
	}
	input := install.DigestBytes([]byte("input"))
	if _, err := completedOutput(input, output, ownership, "BAD", "installation.continue", "fact", "value"); err == nil {
		t.Fatal("invalid compensation accepted")
	}
	if _, err := completedOutput(input, output, ownership, "retain.valid", "BAD", "fact", "value"); err == nil {
		t.Fatal("invalid next action accepted")
	}
	if _, err := completedOutput(input, output, ownership, "retain.valid", "installation.continue", "bad fact", "value"); err == nil {
		t.Fatal("invalid fact accepted")
	}
	var nilMap map[string]string
	if !nilPort(nilMap) || nilPort(0) || nilPort(struct{}{}) {
		t.Fatal("phase nil-port classification changed")
	}
}

type testBinding string

func (b testBinding) String() string { return string(b) }

type artifactPhaseFixture struct {
	request    installapp.PhaseRequest
	projection ArtifactAcquisitionPlan
	plans      *artifactPlanQuery
	artifacts  *artifactPhaseApplication
	capacity   *artifactCapacityApplication
}

func newArtifactPhaseFixture(t *testing.T) *artifactPhaseFixture {
	t.Helper()
	canonical := []byte("canonical artifact plan")
	parent, _ := install.BindPlan(canonical)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012349")
	request, err := installapp.NewPhaseRequestForIntegration(operationID, parent, 1, canonical)
	if err != nil {
		t.Fatal(err)
	}
	plan := artifactPhasePlan(t)
	installationID := "019f5f20-1234-7abc-8123-0123456789ab"
	generationID := "019f5f21-5678-7def-9123-abcdef012345"
	identity, _ := composeplan.NewIdentity(installationID, generationID)
	projectionAuthority, _ := identity.SecretProjectionCapacities()
	secretProjections := make([]artifactapp.SecretProjectionCapacity, 0, len(projectionAuthority))
	for _, authority := range projectionAuthority {
		secretProjections = append(secretProjections, artifactapp.SecretProjectionCapacity{
			Name: authority.Name(), Purpose: authority.Purpose(), ReservedBytes: authority.ReservedBytes(),
		})
	}
	acquisitionDigest, _ := install.ParseDigest(plan.Digest().Hex())
	projection := ArtifactAcquisitionPlan{
		ParentPlanDigest: parent, InstallationID: installationID, ReleaseID: "agentmemory-1.0.0", GenerationID: generationID,
		AcquisitionPlanDigest: acquisitionDigest, AcquisitionPlan: plan, SecretProjections: secretProjections,
		ComposeArtifactID: "compose", RuntimeOwnership: install.RuntimeOwnershipReusedExternal,
		HostCASCapacity:      artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: "/cas"},
		HostReleaseCapacity:  artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: "/releases/release-1"},
		DockerEngineCapacity: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "engine"},
		DockerVolumeCapacity: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: "volume"},
	}
	aggregate, _ := artifactacquisition.NewAggregate(operationID.String(), plan)
	reservationID, _ := plan.ReservationID(operationID.String())
	proof, _ := artifactacquisition.NewReservationProof(reservationID, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	reservedEvidence := aggregate.EvidenceDigest()
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	consumptionAuthorization, _ := aggregate.AuthorizeConsumption(artifact)
	consumptionProof, _ := artifactacquisition.NewConsumptionProof(
		consumptionAuthorization.ReservationID(), consumptionAuthorization.PartialID(), consumptionAuthorization.Bytes(), consumptionAuthorization.FilesystemID(),
	)
	_, _ = aggregate.RecordConsumption(consumptionAuthorization, consumptionProof)
	for _, chunk := range artifact.Chunks() {
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	final, _ := artifactacquisition.NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
	_, _ = aggregate.CompleteArtifact(artifact, final)
	return &artifactPhaseFixture{
		request: request, projection: projection, plans: &artifactPlanQuery{plan: projection},
		capacity: &artifactCapacityApplication{}, artifacts: &artifactPhaseApplication{
			reserve: artifactapp.ReserveResult{Version: 1, ReservationID: reservationID, ReservedBytes: plan.Totals().DownloadBytes(), AggregateEvidence: reservedEvidence},
			acquire: artifactapp.AcquireResult{Version: aggregate.Version(), CompletedArtifacts: 1, AggregateEvidence: aggregate.EvidenceDigest(), ReservationRetained: true, VerifiedArtifacts: []artifactapp.VerifiedArtifact{{
				ID: artifact.ID(), Digest: artifact.Digest(), Size: artifact.Size(), ContentKey: artifact.ContentKey(),
			}}},
		},
	}
}

func artifactPhasePlan(t *testing.T) artifactacquisition.Plan {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("compose-bytes"))
	target, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, 13, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 13,
	})
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("signed acquisition plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "compose", Digest: digest, Size: 13, ExpandedBytes: 13, ExpandedDigest: digest,
			TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: []string{"bundle://release/compose.bin"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: 13, Digest: digest}},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 13, ExpandedBytes: 13, RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30, RequiredBytes: 76},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func invokeReservation(value *artifactPhaseFixture) error {
	value.plans.plan = value.projection
	phase, _ := NewSpaceReservationPhase(value.plans, value.artifacts, value.capacity)
	_, err := phase.ReserveSpace(context.Background(), value.request)
	return err
}

func invokeCompose(value *artifactPhaseFixture) error {
	value.plans.plan = value.projection
	phase, _ := NewComposeBundlePhase(value.plans, value.artifacts, value.capacity)
	_, err := phase.EnsureComposeBundle(context.Background(), value.request)
	return err
}

type artifactPlanQuery struct {
	plan ArtifactAcquisitionPlan
	err  error
}

func (q *artifactPlanQuery) ResolveArtifactAcquisitionPlan(context.Context, install.PlanDigest) (ArtifactAcquisitionPlan, error) {
	return q.plan, q.err
}

type artifactPhaseApplication struct {
	reserve                artifactapp.ReserveResult
	acquire                artifactapp.AcquireResult
	reserveCommand         artifactapp.Command
	acquireCommand         artifactapp.Command
	optionalReleaseCommand artifactapp.Command
	optionalReleaseReason  artifactacquisition.ReleaseReason
	reserveErr             error
	acquireErr             error
	optionalReleaseErr     error
}

type artifactCapacityApplication struct {
	reserveCommand       artifactapp.CapacityCommand
	consumeCommand       artifactapp.CapacityCommand
	transferCommand      artifactapp.CapacityCommand
	prepareCommand       artifactapp.CapacityCommand
	releaseCommand       artifactapp.CapacityCommand
	consumedArtifact     string
	transferGeneration   string
	prepareGeneration    string
	transferInstallation string
	releaseCalls         int
	compensateCalls      int
	transferResult       *artifactapp.CapacityResult
	err                  error
}

func capacityPhaseResult() artifactapp.CapacityResult {
	return artifactapp.CapacityResult{Version: 1, Leases: []artifactacquisition.CapacityLeaseSnapshot{{LeaseID: "l-test"}}}
}

func (a *artifactCapacityApplication) ReserveCapacity(_ context.Context, command artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	a.reserveCommand = command
	return capacityPhaseResult(), a.err
}

func (a *artifactCapacityApplication) ConsumeArtifactExpansion(_ context.Context, command artifactapp.CapacityCommand, artifactID string) (artifactapp.CapacityResult, error) {
	a.consumeCommand, a.consumedArtifact = command, artifactID
	return capacityPhaseResult(), a.err
}

func (a *artifactCapacityApplication) TransferActivationCapacity(_ context.Context, command artifactapp.CapacityCommand, generation, installation string) (artifactapp.CapacityResult, error) {
	a.transferCommand, a.transferGeneration, a.transferInstallation = command, generation, installation
	if a.transferResult != nil {
		return *a.transferResult, a.err
	}
	return activatedCapacityPhaseResult(command, generation, installation), a.err
}

func (a *artifactCapacityApplication) PrepareSecretProjectionCapacity(_ context.Context, command artifactapp.CapacityCommand, generation string) (artifactapp.CapacityResult, error) {
	a.prepareCommand, a.prepareGeneration = command, generation
	return preparedCapacityPhaseResult(command, generation), a.err
}

func preparedCapacityPhaseResult(command artifactapp.CapacityCommand, generation string) artifactapp.CapacityResult {
	host, _ := artifactacquisition.NewStoragePool("host-pool", artifactapp.CapacityHostCAS)
	release, _ := artifactacquisition.NewStoragePool("release-pool", artifactapp.CapacityHostRelease)
	target, _ := artifactacquisition.NewStoragePool("docker-pool", artifactapp.CapacityDockerEngine)
	parent, _ := releaseinventory.ParseDigest(command.ParentPlanDigest.String())
	projections := make([]artifactacquisition.SecretProjectionCapacityInput, 0, len(command.SecretProjections))
	for _, projection := range command.SecretProjections {
		projections = append(projections, artifactacquisition.SecretProjectionCapacityInput{
			Name: projection.Name, Purpose: projection.Purpose, ReservedBytes: projection.ReservedBytes,
		})
	}
	leases, err := command.Plan.CapacityLeasesForAuthority(
		command.OperationID, parent, host, release, target, command.HostRelease.Locator,
		artifactacquisition.SecretProjectionLeaseAuthority{
			InstallationID: command.InstallationID, ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
		}, projections,
	)
	if err != nil {
		return artifactapp.CapacityResult{}
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(command.OperationID, parent, leases)
	for _, lease := range leases {
		receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", true)
		_, _ = aggregate.RecordReserved(lease, receipt)
		if lease.Purpose() != artifactacquisition.LeaseSecretProjection {
			continue
		}
		_, _, _ = aggregate.BeginTransfer(lease.ID(), generation)
		missing, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", false)
		proof, _ := artifactacquisition.NewCapacityMutationProof(missing, releaseinventory.Digest{}, 0, generation)
		_, _ = aggregate.RecordTransferred(lease.ID(), proof)
	}
	snapshot := aggregate.Snapshot()
	return artifactapp.CapacityResult{Version: snapshot.Version, Leases: snapshot.Leases}
}

func activatedCapacityPhaseResult(command artifactapp.CapacityCommand, generation, installation string) artifactapp.CapacityResult {
	host, hostError := artifactacquisition.NewStoragePool("host-pool", artifactapp.CapacityHostCAS)
	release, releaseError := artifactacquisition.NewStoragePool("release-pool", artifactapp.CapacityHostRelease)
	target, targetError := artifactacquisition.NewStoragePool("docker-pool", artifactapp.CapacityDockerEngine)
	parent, parentError := releaseinventory.ParseDigest(command.ParentPlanDigest.String())
	projections := make([]artifactacquisition.SecretProjectionCapacityInput, 0, len(command.SecretProjections))
	for _, projection := range command.SecretProjections {
		projections = append(projections, artifactacquisition.SecretProjectionCapacityInput{
			Name: projection.Name, Purpose: projection.Purpose, ReservedBytes: projection.ReservedBytes,
		})
	}
	leases, leaseError := command.Plan.CapacityLeasesForAuthority(
		command.OperationID, parent, host, release, target, command.HostRelease.Locator,
		artifactacquisition.SecretProjectionLeaseAuthority{
			InstallationID: command.InstallationID, ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
		}, projections,
	)
	aggregate, aggregateError := artifactacquisition.NewCapacityAggregate(command.OperationID, parent, leases)
	if hostError != nil || releaseError != nil || targetError != nil || parentError != nil || leaseError != nil || aggregateError != nil {
		return artifactapp.CapacityResult{}
	}
	for _, lease := range leases {
		receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", true)
		_, _ = aggregate.RecordReserved(lease, receipt)
		if lease.Purpose() == artifactacquisition.LeaseExpanded {
			_, _, _ = aggregate.BeginConsume(lease.ID())
			missing, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", false)
			proof, _ := artifactacquisition.NewCapacityMutationProof(missing, lease.ExpectedTargetDigest(), lease.Bytes(), lease.Owner())
			_, _ = aggregate.RecordConsumed(lease.ID(), proof)
		}
		owner := generation
		if lease.Purpose() == artifactacquisition.LeaseSafety {
			owner = installation
		}
		_, _, _ = aggregate.BeginTransfer(lease.ID(), owner)
		missing, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", false)
		targetDigest, usage := releaseinventory.Digest{}, uint64(0)
		if lease.Purpose() == artifactacquisition.LeaseExpanded {
			targetDigest, usage = lease.ExpectedTargetDigest(), lease.Bytes()
		}
		proof, _ := artifactacquisition.NewCapacityMutationProof(missing, targetDigest, usage, owner)
		_, _ = aggregate.RecordTransferred(lease.ID(), proof)
	}
	snapshot := aggregate.Snapshot()
	return artifactapp.CapacityResult{Version: snapshot.Version, Leases: snapshot.Leases}
}

func (a *artifactCapacityApplication) ReleaseOperationCapacity(_ context.Context, command artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	a.releaseCommand = command
	a.releaseCalls++
	return capacityPhaseResult(), a.err
}

func (a *artifactCapacityApplication) CompensateOperationCapacity(_ context.Context, command artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	a.releaseCommand = command
	a.compensateCalls++
	return capacityPhaseResult(), a.err
}

func (a *artifactCapacityApplication) ReleaseActivatedCapacity(_ context.Context, command artifactapp.CapacityCommand, generation, installation string) (artifactapp.CapacityResult, error) {
	a.releaseCommand, a.transferGeneration, a.transferInstallation = command, generation, installation
	return capacityPhaseResult(), a.err
}

func (a *artifactPhaseApplication) ReleaseReservation(
	_ context.Context,
	_ artifactapp.Command,
	reason artifactacquisition.ReleaseReason,
) (artifactapp.ReleaseResult, error) {
	return artifactapp.ReleaseResult{Reason: reason, Released: true}, nil
}

func (a *artifactPhaseApplication) ReleaseReservationIfPresent(
	_ context.Context,
	command artifactapp.Command,
	reason artifactacquisition.ReleaseReason,
) (artifactapp.ReleaseResult, error) {
	a.optionalReleaseCommand = command
	a.optionalReleaseReason = reason
	return artifactapp.ReleaseResult{Reason: reason, Released: a.optionalReleaseErr == nil}, a.optionalReleaseErr
}

func (a *artifactPhaseApplication) ReserveSpace(_ context.Context, command artifactapp.Command) (artifactapp.ReserveResult, error) {
	a.reserveCommand = command
	return a.reserve, a.reserveErr
}

func (a *artifactPhaseApplication) Acquire(_ context.Context, command artifactapp.Command) (artifactapp.AcquireResult, error) {
	a.acquireCommand = command
	return a.acquire, a.acquireErr
}
