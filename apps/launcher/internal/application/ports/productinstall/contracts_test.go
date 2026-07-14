package productinstall

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestDirectoryCommandIsCanonicalImmutableAndPlanBound(t *testing.T) {
	t.Parallel()
	operationID, planDigest := testBindings(t)
	specs := testDirectorySpecs(t)
	command, err := NewDirectoryCommand(
		operationID, planDigest, 2, install.RuntimeOwnershipReusedExternal, specs,
	)
	if err != nil {
		t.Fatal(err)
	}
	specs[0] = DirectorySpec{}
	resolved := command.Directories()
	if !command.Valid() || command.BindingDigest().IsZero() || len(resolved) != 6 ||
		resolved[0].Purpose() != DirectoryBackups || resolved[0].Path() == "" ||
		command.OperationID() != operationID || !command.ParentPlanDigest().Equal(planDigest) ||
		command.Attempt() != 2 || command.RuntimeOwnership() != install.RuntimeOwnershipReusedExternal {
		t.Fatal("directory command did not retain a canonical immutable binding")
	}
	resolved[0] = DirectorySpec{}
	if command.Directories()[0].Purpose() != DirectoryBackups {
		t.Fatal("Directories exposed mutable command storage")
	}

	state := install.DigestBytes([]byte("verified-directory-identities"))
	receipt, err := NewDirectoryReceiptForAdapter(command, state, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ValidFor(command) || receipt.OutputDigest().IsZero() ||
		receipt.Created() != 4 || receipt.Reused() != 2 {
		t.Fatal("directory receipt lost its exact authorization binding")
	}
	other, err := NewDirectoryCommand(
		operationID, planDigest, 3, install.RuntimeOwnershipReusedExternal, testDirectorySpecs(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ValidFor(other) {
		t.Fatal("directory receipt replayed across attempts")
	}
}

func TestDirectoryContractsRejectIncompleteOrContradictoryInput(t *testing.T) {
	t.Parallel()
	operationID, planDigest := testBindings(t)
	tests := []struct {
		name   string
		mutate func([]DirectorySpec) []DirectorySpec
	}{
		{name: "missing", mutate: func(specs []DirectorySpec) []DirectorySpec { return specs[1:] }},
		{name: "duplicate purpose", mutate: func(specs []DirectorySpec) []DirectorySpec {
			specs[1] = specs[0]
			return specs
		}},
		{name: "duplicate path", mutate: func(specs []DirectorySpec) []DirectorySpec {
			replacement, err := NewDirectorySpec(specs[1].Purpose(), specs[0].Path())
			if err != nil {
				t.Fatal(err)
			}
			specs[1] = replacement
			return specs
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewDirectoryCommand(
				operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory,
				test.mutate(testDirectorySpecs(t)),
			); err == nil {
				t.Fatal("NewDirectoryCommand accepted incomplete authority")
			}
		})
	}
	command, err := NewDirectoryCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory, testDirectorySpecs(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectoryReceiptForAdapter(command, install.Digest{}, 6, 0); err == nil {
		t.Fatal("directory receipt accepted absent state evidence")
	}
	if _, err := NewDirectoryReceiptForAdapter(command, install.DigestBytes([]byte("state")), 7, 0); err == nil {
		t.Fatal("directory receipt accepted a contradictory count")
	}
}

func TestSecretCommandAndReceiptRequireEveryPurposeSeparatedKey(t *testing.T) {
	t.Parallel()
	operationID, planDigest := testBindings(t)
	specs := testSecretSpecs(t)
	command, err := NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory,
		"/owner/agentmemory/secrets", specs,
	)
	if err != nil {
		t.Fatal(err)
	}
	specs[0] = SecretSpec{}
	resolved := command.Secrets()
	if !command.Valid() || command.BindingDigest().IsZero() || len(resolved) != 7 ||
		resolved[0].Purpose() != installplan.SecretAPICredential || resolved[0].Path() == "" ||
		command.OperationID() != operationID || !command.ParentPlanDigest().Equal(planDigest) ||
		command.Attempt() != 1 || command.RuntimeOwnership() != install.RuntimeOwnershipProvisionedByAgentMemory ||
		command.SecretDirectory() != "/owner/agentmemory/secrets" {
		t.Fatal("secret command did not canonicalize all required purposes")
	}
	resolved[0] = SecretSpec{}
	if command.Secrets()[0].Purpose() != installplan.SecretAPICredential {
		t.Fatal("Secrets exposed mutable command storage")
	}
	receipt, err := NewSecretReceiptForAdapter(
		command, install.DigestBytes([]byte("hmac-state-attestation")), 5, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ValidFor(command) || receipt.OutputDigest().IsZero() ||
		receipt.Created() != 5 || receipt.Reused() != 2 {
		t.Fatal("secret receipt lost its exact authorization binding")
	}
}

func TestSecretContractsRejectMissingDuplicateOrUnresolvedAuthority(t *testing.T) {
	t.Parallel()
	operationID, planDigest := testBindings(t)
	specs := testSecretSpecs(t)
	if _, err := NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipReusedExternal,
		"/owner/agentmemory/secrets", specs[1:],
	); err == nil {
		t.Fatal("secret command accepted a missing purpose")
	}
	specs = testSecretSpecs(t)
	specs[1] = specs[0]
	if _, err := NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipReusedExternal,
		"/owner/agentmemory/secrets", specs,
	); err == nil {
		t.Fatal("secret command accepted a duplicated purpose and path")
	}
	if _, err := NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipUndetermined,
		"/owner/agentmemory/secrets", testSecretSpecs(t),
	); err == nil {
		t.Fatal("secret command accepted unresolved runtime ownership")
	}
}

func testBindings(t testing.TB) (install.OperationID, install.PlanDigest) {
	t.Helper()
	operationID, err := install.NewOperationID("pf001-product-install")
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := install.BindPlan([]byte("canonical-pf001-plan"))
	if err != nil {
		t.Fatal(err)
	}
	return operationID, planDigest
}

func testDirectorySpecs(t testing.TB) []DirectorySpec {
	t.Helper()
	inputs := []struct {
		purpose DirectoryPurpose
		path    string
	}{
		{DirectoryRelease, "/owner/agentmemory/releases/v1"},
		{DirectoryConfiguration, "/owner/agentmemory/config"},
		{DirectoryRuntime, "/owner/agentmemory/runtime"},
		{DirectorySecrets, "/owner/agentmemory/secrets"},
		{DirectoryBackups, "/owner/agentmemory/backups"},
		{DirectoryComposeProject, "/owner/agentmemory/releases/v1/compose"},
	}
	result := make([]DirectorySpec, 0, len(inputs))
	for _, input := range inputs {
		spec, err := NewDirectorySpec(input.purpose, input.path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, spec)
	}
	return result
}

func testSecretSpecs(t testing.TB) []SecretSpec {
	t.Helper()
	purposes := []installplan.SecretPurpose{
		installplan.SecretInstallationRootKey,
		installplan.SecretAPICredential,
		installplan.SecretAttestationHMACKey,
		installplan.SecretNeo4jPassword,
		installplan.SecretEmbeddingCapability,
		installplan.SecretRerankerCapability,
		installplan.SecretExtractorCapability,
	}
	result := make([]SecretSpec, 0, len(purposes))
	for _, purpose := range purposes {
		spec, err := NewSecretSpec(purpose, "/owner/agentmemory/secrets/"+string(purpose))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, spec)
	}
	return result
}
