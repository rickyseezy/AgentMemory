package install

import "testing"

func TestPF001CancellationIntentLifecycleIsPlanBoundAndAcknowledgedOnlyAfterCancelled(t *testing.T) {
	t.Parallel()

	operationID, _ := NewOperationID("domain-active-cancel")
	plan, _ := BindPlan([]byte("plan-a"))
	foreign, _ := BindPlan([]byte("plan-b"))
	operation, _ := NewOperation(operationID, plan)

	if err := operation.RequestCancellation(foreign); err == nil {
		t.Fatal("foreign-plan RequestCancellation() error=nil")
	}
	if err := operation.RequestCancellation(plan); err != nil {
		t.Fatalf("RequestCancellation() error=%v", err)
	}
	requested, ok := operation.CancellationIntent()
	if !ok || requested.Status() != CancellationRequested || requested.RequestedAtVersion() != 1 {
		t.Fatalf("requested intent=(%+v,%v)", requested, ok)
	}
	if err := operation.AcknowledgeCancellation(plan); err == nil {
		t.Fatal("AcknowledgeCancellation() before StateCancelled error=nil")
	}
	if err := operation.Cancel(plan); err != nil {
		t.Fatalf("Cancel() error=%v", err)
	}
	if err := operation.AcknowledgeCancellation(plan); err != nil {
		t.Fatalf("AcknowledgeCancellation() error=%v", err)
	}
	acknowledged, ok := operation.CancellationIntent()
	if !ok || acknowledged.Status() != CancellationAcknowledged ||
		acknowledged.AcknowledgedAtVersion() != operation.AggregateVersion() {
		t.Fatalf("acknowledged intent=(%+v,%v), aggregate=%d", acknowledged, ok, operation.AggregateVersion())
	}
	version := operation.AggregateVersion()
	if err := operation.AcknowledgeCancellation(plan); err != nil || operation.AggregateVersion() != version {
		t.Fatalf("ack replay error/version=%v/%d", err, operation.AggregateVersion())
	}
}

func TestPF001RestoreRejectsImpossibleCancellationSnapshots(t *testing.T) {
	t.Parallel()

	operationID, _ := NewOperationID("restore-active-cancel")
	plan, _ := BindPlan([]byte("plan-a"))
	operation, _ := NewOperation(operationID, plan)
	base := operation.Snapshot()

	for _, test := range []struct {
		name   string
		intent *CancellationRestoreInput
		state  State
		ver    uint64
	}{
		{name: "zero request", intent: &CancellationRestoreInput{}, state: StateRunning},
		{name: "request after aggregate", intent: &CancellationRestoreInput{RequestedAtVersion: 2}, state: StateRunning, ver: 1},
		{name: "ack before request", intent: &CancellationRestoreInput{RequestedAtVersion: 2, AcknowledgedAtVersion: 1}, state: StateCancelled, ver: 2},
		{name: "ack while running", intent: &CancellationRestoreInput{RequestedAtVersion: 1, AcknowledgedAtVersion: 2}, state: StateRunning, ver: 2},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := RestoreOperation(RestoreInput{
				OperationID: operationID, PlanDigest: plan, AggregateVersion: test.ver,
				State: test.state, CurrentPhase: base.CurrentPhase(), Attempt: 1,
				CancellationIntent: test.intent,
			})
			if err == nil {
				t.Fatal("RestoreOperation() error=nil")
			}
		})
	}
}
