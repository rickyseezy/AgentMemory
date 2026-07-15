package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/agentconfigapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	agentConfigurationOperationID    = "019f5f23-5678-7def-9123-abcdef012347"
	agentConfigurationInstallationID = "019f5f20-1234-7abc-8123-0123456789ab"
	agentConfigurationEntryID        = "019f5f21-5678-7def-9123-abcdef012345"
)

func TestPF001AgentConfigurationPhaseAcceptsExactChangedReceipt(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	result := agentConfigurationMergeResult(t, projection.Target(), nil, false, projection.ExpectedManagedEntryDigest())
	query := &agentConfigurationPlanQuery{projection: projection}
	merger := &agentConfigurationMerger{result: result}
	phase, err := NewAgentConfigurationPhase(query, merger)
	if err != nil {
		t.Fatal(err)
	}

	output, err := phase.MergeAgentConfiguration(context.Background(), request)
	if err != nil {
		t.Fatalf("MergeAgentConfiguration() error = %v", err)
	}
	if output.Outcome() != installapp.PhaseOutcomeCompleted ||
		!output.InputDigest().Equal(projection.ParentBindingDigest()) ||
		!output.OutputDigest().Equal(install.DigestBytes(result.Plan().AfterContent())) ||
		output.RuntimeOwnership() != projection.RuntimeOwnership() ||
		output.NextSafeAction() != "installation.continue" {
		t.Fatalf("MergeAgentConfiguration() output = %+v", output)
	}
	if query.operationID != request.OperationID() || query.attempt != request.Attempt() ||
		!query.parent.Equal(request.PlanDigest()) || merger.calls != 1 ||
		merger.request.Location.String() != projection.Location().String() ||
		!sameAgentConfigurationTarget(merger.request.Target, projection.Target()) ||
		!merger.request.ExpectedManagedEntryDigest.Equal(projection.ExpectedManagedEntryDigest()) {
		t.Fatalf("phase lost an authenticated binding: query=%+v request=%+v", query, merger.request)
	}
}

func TestPF001AgentConfigurationPhaseAcceptsVerifiedIdempotentResult(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	initial := agentConfigurationMergeResult(t, projection.Target(), nil, false, agentconfigdomain.Digest{})
	result := agentConfigurationMergeResult(
		t,
		projection.Target(),
		initial.Plan().AfterContent(),
		true,
		initial.Plan().ManagedEntryDigest(),
	)
	query := &agentConfigurationPlanQuery{projection: projection}
	merger := &agentConfigurationMerger{result: result}
	phase, _ := NewAgentConfigurationPhase(query, merger)

	output, err := phase.MergeAgentConfiguration(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted || result.Changed() ||
		!output.OutputDigest().Equal(install.DigestBytes(result.Plan().AfterContent())) {
		t.Fatalf("MergeAgentConfiguration(idempotent) = %+v, %v", output, err)
	}
}

func TestPF001AgentConfigurationPhaseAcceptsPathNeutralCustomRegistration(t *testing.T) {
	t.Parallel()
	request, projection := agentConfigurationPhaseFixture(t)
	customTarget, err := agentconfigdomain.NewTargetForAgent(
		agentconfigdomain.AgentHostCustom,
		agentConfigurationInstallationID,
		agentConfigurationEntryID,
		"/opt/agentmemory/bin/agentmemory",
		agentconfigdomain.DigestBytes([]byte("signed launcher")),
	)
	if err != nil {
		t.Fatal(err)
	}
	projection.target = customTarget
	projection.expectedManagedEntryDigest = agentconfigdomain.Digest{}
	projection.parentBindingDigest = agentConfigurationParentBinding(projection)
	result := agentConfigurationMergeResult(t, customTarget, nil, false, agentconfigdomain.Digest{})
	phase, err := NewAgentConfigurationPhase(
		&agentConfigurationPlanQuery{projection: projection},
		&agentConfigurationMerger{result: result},
	)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.MergeAgentConfiguration(t.Context(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted || result.Changed() ||
		result.Plan().Action() != agentconfigdomain.MergeActionVerifyCustom ||
		!output.OutputDigest().Equal(install.DigestBytes(result.Plan().AfterContent())) {
		t.Fatalf("custom MergeAgentConfiguration()=%+v,%v plan=%+v", output, err, result.Plan())
	}
}

func TestPF001AgentConfigurationPhaseAcceptsExistingFileBackupReceipt(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	result := agentConfigurationMergeResult(
		t,
		projection.Target(),
		[]byte(`{"unrelated":{"preserved":true}}`),
		true,
		projection.ExpectedManagedEntryDigest(),
	)
	phase, _ := NewAgentConfigurationPhase(
		&agentConfigurationPlanQuery{projection: projection},
		&agentConfigurationMerger{result: result},
	)
	output, err := phase.MergeAgentConfiguration(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted || !result.Changed() {
		t.Fatalf("MergeAgentConfiguration(existing file) = %+v, %v", output, err)
	}
}

func TestPF001AgentConfigurationPhaseAcceptsProtectedManagedReplacement(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	current := agentConfigurationMergeResult(
		t,
		agentConfigurationTarget(t, "/opt/agentmemory/bin/previous"),
		nil,
		false,
		agentconfigdomain.Digest{},
	)
	projection.expectedManagedEntryDigest = current.Plan().ManagedEntryDigest()
	projection.parentBindingDigest = agentConfigurationParentBinding(projection)
	result := agentConfigurationMergeResult(
		t,
		projection.Target(),
		current.Plan().AfterContent(),
		true,
		projection.ExpectedManagedEntryDigest(),
	)
	phase, _ := NewAgentConfigurationPhase(
		&agentConfigurationPlanQuery{projection: projection},
		&agentConfigurationMerger{result: result},
	)

	output, err := phase.MergeAgentConfiguration(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted ||
		result.Plan().Action() != agentconfigdomain.MergeActionReplaceManaged {
		t.Fatalf("MergeAgentConfiguration(replacement) = %+v, %v", output, err)
	}
}

func TestPF001AgentConfigurationPhaseRejectsForeignOrContradictoryResults(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	foreignTarget := agentConfigurationTarget(t, "/opt/agentmemory/bin/foreign")
	foreignResult := agentConfigurationMergeResult(t, foreignTarget, nil, false, agentconfigdomain.Digest{})

	tests := []struct {
		name      string
		configure func(*AgentConfigurationPlan, *agentConfigurationPlanQuery, *agentConfigurationMerger)
		want      ErrorCode
	}{
		{name: "plan unavailable", configure: func(_ *AgentConfigurationPlan, query *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			query.err = errors.New("private parent-plan path")
		}, want: ErrorCodePlanUnavailable},
		{name: "parent mismatch", configure: func(plan *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			plan.parentPlanDigest, _ = install.BindPlan([]byte("foreign plan"))
		}, want: ErrorCodeInvalidBinding},
		{name: "operation mismatch", configure: func(plan *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			plan.operationID, _ = install.NewOperationID("019f5f23-5678-7def-a123-abcdef012348")
		}, want: ErrorCodeInvalidBinding},
		{name: "attempt mismatch", configure: func(plan *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			plan.attempt++
		}, want: ErrorCodeInvalidBinding},
		{name: "binding mismatch", configure: func(plan *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			plan.parentBindingDigest = install.DigestBytes([]byte("forged"))
		}, want: ErrorCodeInvalidBinding},
		{name: "runtime ownership unresolved", configure: func(plan *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, _ *agentConfigurationMerger) {
			plan.runtimeOwnership = install.RuntimeOwnershipUndetermined
		}, want: ErrorCodeInvalidBinding},
		{name: "empty result", configure: func(_ *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, merger *agentConfigurationMerger) {
			merger.result = agentconfigapp.MergeResult{}
		}, want: ErrorCodeInvalidBinding},
		{name: "foreign target result", configure: func(_ *AgentConfigurationPlan, _ *agentConfigurationPlanQuery, merger *agentConfigurationMerger) {
			merger.result = foreignResult
		}, want: ErrorCodeInvalidBinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			localProjection := projection
			query := &agentConfigurationPlanQuery{projection: localProjection}
			merger := &agentConfigurationMerger{
				result: agentConfigurationMergeResult(t, projection.Target(), nil, false, agentconfigdomain.Digest{}),
			}
			test.configure(&localProjection, query, merger)
			query.projection = localProjection
			phase, err := NewAgentConfigurationPhase(query, merger)
			if err != nil {
				t.Fatal(err)
			}
			_, phaseErr := phase.MergeAgentConfiguration(context.Background(), request)
			assertAgentConfigurationPhaseError(t, phaseErr, test.want)
		})
	}
}

func TestPF001AgentConfigurationPhaseMapsKnownFailuresWithoutRawCauses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		want   installapp.PhaseOutcome
		action string
	}{
		{name: "cancelled", err: context.Canceled, want: installapp.PhaseOutcomeCancelled, action: "installation.cancelled"},
		{name: "unsupported", err: agentconfigport.ErrUnsupportedPlatform, want: installapp.PhaseOutcomeUnsupportedHost, action: "installation.select_supported_host"},
		{name: "invalid document", err: agentconfigdomain.ErrInvalidDocument, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "ambiguous owner", err: agentconfigdomain.ErrAmbiguousOwnership, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "managed conflict", err: agentconfigdomain.ErrManagedEntryConflict, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "store conflict", err: agentconfigport.ErrConflict, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "integrity", err: agentconfigport.ErrIntegrity, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "compensation", err: errors.Join(agentconfigapp.ErrInvocationVerification, agentconfigapp.ErrCompensationFailed), want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "cancelled compensation", err: errors.Join(context.Canceled, agentconfigapp.ErrInvocationVerification, agentconfigapp.ErrCompensationFailed, agentconfigport.ErrIntegrity), want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.resolve_agent_configuration"},
		{name: "unsafe path", err: agentconfigport.ErrUnsafePath, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.repair_agent_configuration_permissions"},
		{name: "deadline", err: context.DeadlineExceeded, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_agent_configuration"},
		{name: "not found", err: agentconfigport.ErrNotFound, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_agent_configuration"},
		{name: "IO", err: agentconfigport.ErrIO, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_agent_configuration"},
		{name: "durability", err: agentconfigport.ErrDurabilityAmbiguous, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_agent_configuration"},
		{name: "invocation", err: agentconfigapp.ErrInvocationVerification, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_agent_configuration"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, projection := agentConfigurationPhaseFixture(t)
			phase, _ := NewAgentConfigurationPhase(
				&agentConfigurationPlanQuery{projection: projection},
				&agentConfigurationMerger{err: errors.Join(test.err, errors.New("secret host path"))},
			)
			output, err := phase.MergeAgentConfiguration(context.Background(), request)
			if err != nil || output.Outcome() != test.want || output.NextSafeAction() != test.action {
				t.Fatalf("MergeAgentConfiguration() = %+v, %v", output, err)
			}
		})
	}
}

func TestPF001AgentConfigurationPhaseFailsClosedForInvalidOrUnknownFailures(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	tests := []struct {
		err  error
		want ErrorCode
	}{
		{err: agentconfigapp.ErrInvalidReceipt, want: ErrorCodeInvalidBinding},
		{err: agentconfigport.ErrInvalidArgument, want: ErrorCodeInvalidBinding},
		{err: agentconfigdomain.ErrInvalidTarget, want: ErrorCodeInvalidBinding},
		{err: errors.New("secret unclassified platform failure"), want: ErrorCodeAgentConfigurationUnavailable},
	}
	for _, test := range tests {
		phase, _ := NewAgentConfigurationPhase(
			&agentConfigurationPlanQuery{projection: projection},
			&agentConfigurationMerger{err: test.err},
		)
		_, err := phase.MergeAgentConfiguration(context.Background(), request)
		assertAgentConfigurationPhaseError(t, err, test.want)
	}

	query := &agentConfigurationPlanQuery{projection: projection}
	merger := &agentConfigurationMerger{}
	if _, err := NewAgentConfigurationPhase(nil, merger); err == nil {
		t.Fatal("NewAgentConfigurationPhase() accepted nil query")
	}
	if _, err := NewAgentConfigurationPhase(query, nil); err == nil {
		t.Fatal("NewAgentConfigurationPhase() accepted nil merger")
	}
	var typedNil *agentConfigurationMerger
	if _, err := NewAgentConfigurationPhase(query, typedNil); err == nil {
		t.Fatal("NewAgentConfigurationPhase() accepted typed-nil merger")
	}
	phase, _ := NewAgentConfigurationPhase(query, merger)
	if _, err := phase.MergeAgentConfiguration(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("MergeAgentConfiguration() accepted invalid phase request")
	}
}

func TestPF001AgentConfigurationProjectionBindsEveryAuthorizedInput(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	if !projection.validFor(request) || projection.Location().String() == "" ||
		!projection.ParentPlanDigest().Equal(request.PlanDigest()) ||
		projection.OperationID() != request.OperationID() || projection.Attempt() != request.Attempt() ||
		projection.ExpectedManagedEntryDigest().IsZero() || !projection.RuntimeOwnership().Resolved() {
		t.Fatalf("projection getters or binding are incomplete: %+v", projection)
	}

	tests := []struct {
		name   string
		mutate func(*AgentConfigurationPlan)
	}{
		{name: "parent", mutate: func(plan *AgentConfigurationPlan) { plan.parentPlanDigest, _ = install.BindPlan([]byte("other")) }},
		{name: "operation", mutate: func(plan *AgentConfigurationPlan) {
			plan.operationID, _ = install.NewOperationID("019f5f23-5678-7def-a123-abcdef012348")
		}},
		{name: "attempt", mutate: func(plan *AgentConfigurationPlan) { plan.attempt++ }},
		{name: "location", mutate: func(plan *AgentConfigurationPlan) {
			plan.location, _ = agentconfigport.NewConfigLocation("/private/other-agent.json")
		}},
		{name: "target", mutate: func(plan *AgentConfigurationPlan) {
			plan.target = agentConfigurationTarget(t, "/opt/agentmemory/bin/other")
		}},
		{name: "expected entry", mutate: func(plan *AgentConfigurationPlan) {
			plan.expectedManagedEntryDigest = agentconfigdomain.DigestBytes([]byte("other-entry"))
		}},
		{name: "ownership", mutate: func(plan *AgentConfigurationPlan) {
			plan.runtimeOwnership = install.RuntimeOwnershipProvisionedByAgentMemory
		}},
	}
	for _, test := range tests {
		mutated := projection
		test.mutate(&mutated)
		if mutated.validFor(request) || mutated.ParentBindingDigest().Equal(agentConfigurationParentBinding(mutated)) {
			t.Fatalf("%s mutation retained authenticated binding", test.name)
		}
	}
}

func TestPF001AgentConfigurationProjectionRejectsIncompleteInputs(t *testing.T) {
	t.Parallel()

	request, projection := agentConfigurationPhaseFixture(t)
	tests := []struct {
		name      string
		parent    install.PlanDigest
		operation install.OperationID
		attempt   uint32
		location  agentconfigport.ConfigLocation
		target    agentconfigdomain.Target
		ownership install.RuntimeOwnership
	}{
		{name: "parent", operation: request.OperationID(), attempt: 1, location: projection.Location(), target: projection.Target(), ownership: projection.RuntimeOwnership()},
		{name: "operation", parent: request.PlanDigest(), attempt: 1, location: projection.Location(), target: projection.Target(), ownership: projection.RuntimeOwnership()},
		{name: "attempt", parent: request.PlanDigest(), operation: request.OperationID(), location: projection.Location(), target: projection.Target(), ownership: projection.RuntimeOwnership()},
		{name: "location", parent: request.PlanDigest(), operation: request.OperationID(), attempt: 1, target: projection.Target(), ownership: projection.RuntimeOwnership()},
		{name: "target", parent: request.PlanDigest(), operation: request.OperationID(), attempt: 1, location: projection.Location(), ownership: projection.RuntimeOwnership()},
		{name: "ownership", parent: request.PlanDigest(), operation: request.OperationID(), attempt: 1, location: projection.Location(), target: projection.Target(), ownership: install.RuntimeOwnershipUndetermined},
	}
	for _, test := range tests {
		if _, err := NewAgentConfigurationPlan(
			test.parent,
			test.operation,
			test.attempt,
			test.location,
			test.target,
			agentconfigdomain.Digest{},
			test.ownership,
		); err == nil {
			t.Fatalf("NewAgentConfigurationPlan() accepted missing %s", test.name)
		}
	}
}

func agentConfigurationPhaseFixture(t *testing.T) (installapp.PhaseRequest, AgentConfigurationPlan) {
	t.Helper()
	canonical := []byte("canonical agent-configuration plan")
	parent, _ := install.BindPlan(canonical)
	operation, _ := install.NewOperationID(agentConfigurationOperationID)
	request, err := installapp.NewPhaseRequestForIntegration(operation, parent, 3, canonical)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := agentconfigport.NewConfigLocation("/home/user/.config/codex/config.json")
	projection, err := NewAgentConfigurationPlan(
		parent,
		operation,
		request.Attempt(),
		location,
		agentConfigurationTarget(t, "/opt/agentmemory/bin/agentmemory"),
		agentconfigdomain.DigestBytes([]byte("last managed entry")),
		install.RuntimeOwnershipReusedExternal,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request, projection
}

func agentConfigurationTarget(t *testing.T, command string) agentconfigdomain.Target {
	t.Helper()
	target, err := agentconfigdomain.NewTarget(
		agentConfigurationInstallationID,
		agentConfigurationEntryID,
		command,
		agentconfigdomain.DigestBytes([]byte("signed launcher")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

type agentConfigurationPlanQuery struct {
	projection  AgentConfigurationPlan
	parent      install.PlanDigest
	operationID install.OperationID
	attempt     uint32
	err         error
}

func (q *agentConfigurationPlanQuery) ResolveAgentConfigurationPlan(
	_ context.Context,
	parent install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (AgentConfigurationPlan, error) {
	q.parent = parent
	q.operationID = operationID
	q.attempt = attempt
	return q.projection, q.err
}

type agentConfigurationMerger struct {
	result  agentconfigapp.MergeResult
	request agentconfigapp.MergeRequest
	err     error
	calls   int
}

func (m *agentConfigurationMerger) Merge(
	_ context.Context,
	request agentconfigapp.MergeRequest,
) (agentconfigapp.MergeResult, error) {
	m.calls++
	m.request = request
	return m.result, m.err
}

type agentConfigurationResultStore struct {
	snapshot agentconfigport.Snapshot
}

func (s *agentConfigurationResultStore) Detect(context.Context, agentconfigport.ConfigLocation) (agentconfigport.Detection, error) {
	return agentconfigport.NewDetection(s.snapshot.Exists()), nil
}

func (s *agentConfigurationResultStore) Read(context.Context, agentconfigport.ConfigLocation) (agentconfigport.Snapshot, error) {
	if !s.snapshot.Exists() {
		return agentconfigport.Snapshot{}, agentconfigport.ErrNotFound
	}
	return s.snapshot, nil
}

func (s *agentConfigurationResultStore) ApplyAtomic(
	_ context.Context,
	_ agentconfigport.ConfigLocation,
	plan agentconfigdomain.MergePlan,
) (agentconfigport.ApplyReceipt, error) {
	before := plan.BeforeDigest()
	backupLocation := ""
	backupDigest := agentconfigdomain.Digest{}
	if plan.OriginalExisted() {
		backupLocation = "/private/agentmemory/backups/" + before.String()
		backupDigest = before
	}
	receipt, err := agentconfigport.NewApplyReceipt(
		true,
		plan.OriginalExisted(),
		before,
		plan.AfterDigest(),
		plan.ManagedEntryDigest(),
		backupLocation,
		backupDigest,
	)
	if err != nil {
		return agentconfigport.ApplyReceipt{}, err
	}
	s.snapshot, err = agentconfigport.NewSnapshot(true, plan.AfterContent())
	return receipt, err
}

func (*agentConfigurationResultStore) RestoreBackup(
	context.Context,
	agentconfigport.ConfigLocation,
	agentconfigport.ApplyReceipt,
) (agentconfigport.RestoreReceipt, error) {
	return agentconfigport.RestoreReceipt{}, errors.New("unexpected restore")
}

type successfulAgentConfigurationVerifier struct{}

func (successfulAgentConfigurationVerifier) Verify(context.Context, agentconfigdomain.Target) error {
	return nil
}

func agentConfigurationMergeResult(
	t *testing.T,
	target agentconfigdomain.Target,
	original []byte,
	existed bool,
	expected agentconfigdomain.Digest,
) agentconfigapp.MergeResult {
	t.Helper()
	snapshot, err := agentconfigport.NewSnapshot(existed, original)
	if err != nil {
		t.Fatal(err)
	}
	application, err := agentconfigapp.New(
		&agentConfigurationResultStore{snapshot: snapshot},
		successfulAgentConfigurationVerifier{},
	)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := agentconfigport.NewConfigLocation("/home/user/.config/codex/config.json")
	result, err := application.Merge(context.Background(), agentconfigapp.MergeRequest{
		Location: location, Target: target, ExpectedManagedEntryDigest: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertAgentConfigurationPhaseError(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != want ||
		typed.Error() != string(typed.Code()) || containsSensitive(typed.Error()) {
		t.Fatalf("privacy-safe phase error = %#v", err)
	}
}
