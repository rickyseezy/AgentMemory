package composefile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001RenderProducesDeterministicClosedComposeSourceWithoutSecretValues(t *testing.T) {
	t.Parallel()

	plan := releasePlanFixture(t)
	first, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(plan)
	if err != nil || !bytes.Equal(first, second) || !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("deterministic render = %v/%v", bytes.Equal(first, second), err)
	}
	if bytes.Contains(first, []byte("${")) || bytes.Contains(first, []byte(strings.Repeat("s", 32))) {
		t.Fatal("render contains interpolation or secret value material")
	}
	var source document
	if err := json.Unmarshal(first, &source); err != nil {
		t.Fatal(err)
	}
	core := source.Services[string(composeplan.ServiceCore)]
	neo4j := source.Services[string(composeplan.ServiceNeo4j)]
	projector := source.Services[string(composeplan.ServiceSecretProjector)]
	if len(source.Services) != 7 || len(source.Secrets) != 8 || len(source.Volumes) != 12 ||
		len(core.Secrets) != 0 || len(projector.Secrets) != 8 || projector.NetworkMode != "none" ||
		len(projector.CapAdd) != 2 || len(projector.Volumes) != 6 ||
		core.DependsOn[string(composeplan.ServiceMigrate)].Condition != "service_completed_successfully" ||
		neo4j.User != "7474:7474" || neo4j.Environment["NEO4J_client_allow__telemetry"] != "false" ||
		!source.Networks[string(composeplan.NetworkInternal)].Internal {
		t.Fatalf("rendered closed topology = %#v", source)
	}
	for _, mounted := range projector.Secrets {
		if mounted.Mode != "" {
			t.Fatalf("secret mode = %q", mounted.Mode)
		}
	}
}

func TestPF001RenderRejectsAnythingExceptAValidatedProductionPlan(t *testing.T) {
	t.Parallel()

	if rendered, err := Render(composeplan.PolicyPlan{}); err == nil || rendered != nil {
		t.Fatalf("zero plan rendered %q/%v", rendered, err)
	}
}

func releasePlanFixture(t *testing.T) composeplan.PolicyPlan {
	t.Helper()
	identity, err := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab", "019f5f21-5678-7def-9123-abcdef012345",
	)
	if err != nil {
		t.Fatal(err)
	}
	images := make(map[composeplan.ServiceName]string)
	limits := make(map[composeplan.ServiceName]composeplan.Limits)
	for _, name := range composeplan.RequiredDefaultServices() {
		images[name] = "ghcr.io/agentmemory/" + string(name) + "@sha256:" + strings.Repeat("a", 64)
		limits[name] = composeplan.Limits{CPUsMilli: 1000, MemoryBytes: 1024 * 1024 * 1024, PIDs: 128}
	}
	secretFiles := map[string]string{
		composeplan.SecretInstallationRootKey:  "/managed/agentmemory_installation_root_key",
		composeplan.SecretAPICredential:        "/managed/agentmemory_api_credential",
		composeplan.SecretAttestationHMACKey:   "/managed/agentmemory_attestation_hmac_key",
		composeplan.SecretNeo4jPassword:        "/managed/agentmemory_neo4j_password",
		composeplan.SecretEmbeddingCapability:  "/managed/agentmemory_embedding_capability",
		composeplan.SecretRerankingCapability:  "/managed/agentmemory_reranking_capability",
		composeplan.SecretExtractionCapability: "/managed/agentmemory_extraction_capability",
		composeplan.SecretEgressAttestation:    "/managed/agentmemory_egress_attestation",
	}
	plan, err := composeplan.NewDefaultReleasePlan(composeplan.DefaultReleaseInput{
		Identity: identity, Release: "0.1.0", HostPort: 9411, Images: images, Limits: limits,
		Models: map[composeplan.ServiceName]composeplan.ModelArtifact{
			composeplan.ServiceLocalEmbedding: {Revision: strings.Repeat("1", 40), SHA256: strings.Repeat("b", 64), Bytes: 1_000_000},
			composeplan.ServiceLocalReranker:  {Revision: strings.Repeat("2", 40), SHA256: strings.Repeat("c", 64), Bytes: 2_000_000},
			composeplan.ServiceLocalExtractor: {Revision: strings.Repeat("3", 40), SHA256: strings.Repeat("d", 64), Bytes: 3_000_000},
		},
		SecretFiles: secretFiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
