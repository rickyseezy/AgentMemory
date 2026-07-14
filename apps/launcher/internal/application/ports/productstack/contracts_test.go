package productstack

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestAuthorizationIsImmutableOperationPlanAttemptAndSignedSourceBound(t *testing.T) {
	t.Parallel()
	authorization := testAuthorization(t, OperationMigrate, 2)
	if !authorization.Valid() || authorization.Operation() != OperationMigrate ||
		authorization.Attempt() != 2 || authorization.BindingDigest().IsZero() ||
		authorization.OperationID().IsZero() || authorization.ParentPlanDigest().IsZero() ||
		authorization.RuntimeOwnership() != install.RuntimeOwnershipProvisionedByAgentMemory ||
		authorization.Source().ConfigurationPath() != "/owner/agentmemory/releases/v1/compose/compose.yaml" {
		t.Fatal("authorization lost its complete signed-source binding")
	}

	other := testAuthorization(t, OperationMigrate, 3)
	if authorization.BindingDigest().Equal(other.BindingDigest()) {
		t.Fatal("authorization digest replayed across attempts")
	}
	start := testAuthorization(t, OperationStartCoreAndGraph, 2)
	if authorization.BindingDigest().Equal(start.BindingDigest()) {
		t.Fatal("authorization digest replayed across stack operations")
	}
}

func TestAuthorizationRejectsIncompleteOrUnresolvedAuthority(t *testing.T) {
	t.Parallel()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	source := testComposeSource(t)
	for _, input := range []struct {
		name      string
		operation Operation
		id        install.OperationID
		plan      install.PlanDigest
		attempt   uint32
		ownership install.RuntimeOwnership
		source    containerengine.ComposeReleaseSource
	}{
		{name: "unknown operation", operation: Operation("other"), id: operationID, plan: plan, attempt: 1, ownership: install.RuntimeOwnershipReusedExternal, source: source},
		{name: "zero operation id", operation: OperationMigrate, plan: plan, attempt: 1, ownership: install.RuntimeOwnershipReusedExternal, source: source},
		{name: "zero plan", operation: OperationMigrate, id: operationID, attempt: 1, ownership: install.RuntimeOwnershipReusedExternal, source: source},
		{name: "zero attempt", operation: OperationMigrate, id: operationID, plan: plan, ownership: install.RuntimeOwnershipReusedExternal, source: source},
		{name: "unresolved ownership", operation: OperationMigrate, id: operationID, plan: plan, attempt: 1, ownership: install.RuntimeOwnershipUndetermined, source: source},
		{name: "empty source", operation: OperationMigrate, id: operationID, plan: plan, attempt: 1, ownership: install.RuntimeOwnershipReusedExternal},
	} {
		input := input
		t.Run(input.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuthorization(input.operation, input.id, input.plan, input.attempt, input.ownership, input.source); err == nil {
				t.Fatal("NewAuthorization accepted incomplete authority")
			}
		})
	}
}

func TestReceiptRequiresExactAuthorizationAndRenderedConfiguration(t *testing.T) {
	t.Parallel()
	authorization := testAuthorization(t, OperationStartCoreAndGraph, 4)
	rendered := install.DigestBytes([]byte("normalized compose json"))
	receipt, err := NewReceiptForAdapter(authorization, rendered)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ValidFor(authorization) || !receipt.ConfigurationDigest().Equal(rendered) ||
		receipt.OutputDigest().IsZero() {
		t.Fatal("receipt did not preserve its exact execution binding")
	}
	if receipt.ValidFor(testAuthorization(t, OperationStartCoreAndGraph, 5)) {
		t.Fatal("receipt replayed across attempts")
	}
	if _, err := NewReceiptForAdapter(authorization, install.Digest{}); err == nil {
		t.Fatal("receipt accepted absent rendered-configuration evidence")
	}
}

func testAuthorization(t testing.TB, operation Operation, attempt uint32) Authorization {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	authorization, err := NewAuthorization(
		operation, operationID, plan, attempt,
		install.RuntimeOwnershipProvisionedByAgentMemory, testComposeSource(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func testComposeSource(t testing.TB) containerengine.ComposeReleaseSource {
	t.Helper()
	endpoint, err := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab",
		"019f5f21-5678-7def-9123-abcdef012345",
	)
	if err != nil {
		t.Fatal(err)
	}
	source, err := containerengine.NewComposeReleaseSource(
		endpoint, identity, "1.0.0", "/owner/agentmemory/releases/v1/compose",
		"/owner/agentmemory/releases/v1/compose/compose.yaml",
		"/owner/agentmemory/releases/v1/compose/empty.env",
		releaseinventory.DigestBytes([]byte("signed compose source")), 180,
	)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
