package brainbootstrap

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestAuthorizationAndReceiptBindExactFirstBrainIdentity(t *testing.T) {
	t.Parallel()
	authorization := bootstrapAuthorization(t, 2)
	if !authorization.Valid() || authorization.OperationID().String() == "" ||
		authorization.Attempt() != 2 || authorization.CoreEndpoint() != "http://127.0.0.1:9411" ||
		authorization.BrainName() != "local" || authorization.OwnerPrincipalID() == "" ||
		authorization.APICredentialPath() == "" || authorization.BindingDigest().IsZero() {
		t.Fatal("bootstrap authorization lost a required identity binding")
	}
	if authorization.ParentPlanDigest().IsZero() || !authorization.RuntimeOwnership().Resolved() ||
		authorization.InstallationID() == "" || authorization.OwnerGrantID() == "" ||
		authorization.OwnerSubjectDigest().IsZero() || authorization.BrainID() == "" ||
		authorization.ReleaseDigest().IsZero() || authorization.GenerationID() == "" {
		t.Fatal("bootstrap authorization getter lost a protected identity")
	}
	receipt, err := NewReceiptForAdapter(authorization, DispositionCreated)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ValidFor(authorization) || receipt.Disposition() != DispositionCreated ||
		receipt.OutputDigest().IsZero() {
		t.Fatal("bootstrap receipt lost its authorization binding")
	}
	if receipt.ValidFor(bootstrapAuthorization(t, 3)) {
		t.Fatal("bootstrap receipt replayed across attempts")
	}
}

func TestAuthorizationRejectsInvalidOwnerBrainEndpointOrCredentialAuthority(t *testing.T) {
	t.Parallel()
	valid := bootstrapInput(t)
	for _, test := range []struct {
		name   string
		mutate func(*AuthorizationInput)
	}{
		{name: "operation", mutate: func(value *AuthorizationInput) { value.OperationID = install.OperationID{} }},
		{name: "plan", mutate: func(value *AuthorizationInput) { value.ParentPlan = install.PlanDigest{} }},
		{name: "attempt", mutate: func(value *AuthorizationInput) { value.Attempt = 0 }},
		{name: "ownership", mutate: func(value *AuthorizationInput) { value.RuntimeOwnership = install.RuntimeOwnershipUndetermined }},
		{name: "remote endpoint", mutate: func(value *AuthorizationInput) { value.CoreEndpoint = "http://example.com:9411" }},
		{name: "credential", mutate: func(value *AuthorizationInput) { value.APICredentialPath = "" }},
		{name: "installation", mutate: func(value *AuthorizationInput) { value.InstallationID = "not-uuid" }},
		{name: "principal", mutate: func(value *AuthorizationInput) { value.OwnerPrincipalID = "not-uuid" }},
		{name: "grant", mutate: func(value *AuthorizationInput) { value.OwnerGrantID = "not-uuid" }},
		{name: "subject", mutate: func(value *AuthorizationInput) { value.OwnerSubjectDigest = install.Digest{} }},
		{name: "brain", mutate: func(value *AuthorizationInput) { value.BrainID = "not-uuid" }},
		{name: "brain name", mutate: func(value *AuthorizationInput) { value.BrainName = "Not Local" }},
		{name: "release", mutate: func(value *AuthorizationInput) { value.ReleaseDigest = install.Digest{} }},
		{name: "generation", mutate: func(value *AuthorizationInput) { value.GenerationID = "not-uuid" }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid

			test.mutate(&input)
			if _, err := NewAuthorization(input); err == nil {
				t.Fatal("NewAuthorization accepted incomplete identity authority")
			}
		})
	}
	if _, err := NewReceiptForAdapter(bootstrapAuthorization(t, 1), Disposition("other")); err == nil {
		t.Fatal("receipt accepted unknown bootstrap disposition")
	}
}

func bootstrapAuthorization(t testing.TB, attempt uint32) Authorization {
	t.Helper()
	input := bootstrapInput(t)
	input.Attempt = attempt
	authorization, err := NewAuthorization(input)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func bootstrapInput(t testing.TB) AuthorizationInput {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	return AuthorizationInput{ //nolint:gosec // G101: path names only; no credential value is present.
		OperationID: operationID, ParentPlan: plan, Attempt: 1,
		RuntimeOwnership: install.RuntimeOwnershipProvisionedByAgentMemory,
		CoreEndpoint:     "http://127.0.0.1:9411", APICredentialPath: "/owner/.agentmemory/secrets/api-credential",
		InstallationID:     "019f5f20-1234-7abc-8123-0123456789ab",
		OwnerPrincipalID:   "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID:       "019f5f25-5678-7def-9123-abcdef012349",
		OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
		BrainID:            "019f5f26-5678-7def-9123-abcdef012350", BrainName: "local",
		ReleaseDigest: install.DigestBytes([]byte("release manifest")),
		GenerationID:  "019f5f21-5678-7def-9123-abcdef012345",
	}
}
