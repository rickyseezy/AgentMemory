package composeplan

import (
	"strings"
	"testing"
)

func TestPF001DefaultReleaseConstructorClosesEveryProductionTopologyChoice(t *testing.T) {
	t.Parallel()

	input := validDefaultReleaseInput()
	plan, err := NewDefaultReleasePlan(input)
	if err != nil || !plan.Valid() {
		t.Fatalf("NewDefaultReleasePlan() = %#v/%v", plan, err)
	}
	model, ok := plan.CanonicalModel()
	if !ok || len(NewPolicy().Validate(model)) != 0 || model.Services[ServiceNeo4j].User != "7474:7474" ||
		model.Services[ServiceNeo4j].Environment["NEO4J_client_allow__telemetry"] != "false" ||
		model.Services[ServiceCore].Environment["AM_EMBEDDING_MODEL_REVISION"] != strings.Repeat("1", 40) ||
		len(model.Services[ServiceCore].Mounts) != 5 || len(model.Services[ServiceCore].Mounts) == 0 ||
		len(model.Secrets) != 8 || len(model.Volumes) != 12 ||
		model.Services[ServiceSecretProjector].User != "0:0" ||
		!model.Services[ServiceSecretProjector].NetworkDisabled {
		t.Fatalf("default release model = %#v", model)
	}
	projections, projected := plan.SecretProjectionVolumes()
	if !projected || len(projections) != 6 || projections[0].Purpose() != projectionPurposeCore ||
		projections[0].ReservedBytes() != SecretProjectionVolumeReservationBytes ||
		len(projections[0].Files()) != 8 || projections[2].Files()[0].UserID() != 7474 {
		t.Fatalf("projection authority = %#v/%v", projections, projected)
	}
	projectedSecret := projections[0].Files()[0]
	if projectedSecret.Name() == "" || projectedSecret.SourceFile() == "" ||
		projectedSecret.GroupID() != 10_001 || projectedSecret.Mode() != 0o400 ||
		projectedSecret.MaximumBytes() != 32 {
		t.Fatalf("projected secret authority = %#v", projectedSecret)
	}
	filesCopy := projections[0].Files()
	filesCopy[0] = ProjectedSecret{}
	if projections[0].Files()[0].Name() == "" {
		t.Fatal("projection exposed mutable file authority")
	}
	capacities, capacityOK := input.Identity.SecretProjectionCapacities()
	if !capacityOK || len(capacities) != 6 || capacities[0].Name() != projections[0].Name() ||
		capacities[0].Purpose() != projections[0].Purpose() || capacities[0].ReservedBytes() != projections[0].ReservedBytes() {
		t.Fatalf("projection capacities = %#v/%v", capacities, capacityOK)
	}
	if capacities, ok := (Identity{}).SecretProjectionCapacities(); ok || capacities != nil {
		t.Fatalf("zero identity capacities = %#v/%v", capacities, ok)
	}
	if model, ok := (PolicyPlan{}).CanonicalModel(); ok || len(model.Services) != 0 {
		t.Fatalf("zero canonical model = %#v/%v", model, ok)
	}
	if files, ok := (PolicyPlan{}).SecretFiles(); ok || files != nil {
		t.Fatalf("zero secret files = %#v/%v", files, ok)
	}
	if volumes, ok := (PolicyPlan{}).SecretProjectionVolumes(); ok || volumes != nil {
		t.Fatalf("zero secret projections = %#v/%v", volumes, ok)
	}
	model.Services[ServiceCore].Environment["AM_NEO4J_USERNAME"] = "attacker"
	if !plan.Valid() {
		t.Fatal("caller-owned model snapshot mutated the release plan")
	}
}

func TestPF001DefaultReleaseConstructorRejectsEveryOpenInputSet(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*DefaultReleaseInput)
	}{
		{name: "extra image", mutate: func(input *DefaultReleaseInput) { input.Images[ServiceName("debug")] = input.Images[ServiceCore] }},
		{name: "missing secret", mutate: func(input *DefaultReleaseInput) { delete(input.SecretFiles, SecretAPICredential) }},
		{name: "mutable image", mutate: func(input *DefaultReleaseInput) { input.Images[ServiceCore] = "core:latest" }},
		{name: "unknown model", mutate: func(input *DefaultReleaseInput) { input.Models[ServiceCore] = input.Models[ServiceLocalEmbedding] }},
		{name: "unbound model", mutate: func(input *DefaultReleaseInput) {
			model := input.Models[ServiceLocalEmbedding]
			model.SHA256 = "not-a-digest"
			input.Models[ServiceLocalEmbedding] = model
		}},
		{name: "zero limit", mutate: func(input *DefaultReleaseInput) { input.Limits[ServiceNeo4j] = Limits{} }},
		{name: "missing projector", mutate: func(input *DefaultReleaseInput) { delete(input.Images, ServiceSecretProjector) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validDefaultReleaseInput()
			test.mutate(&input)
			if plan, err := NewDefaultReleasePlan(input); err == nil || plan.Valid() {
				t.Fatalf("unsafe release input produced %#v/%v", plan, err)
			}
		})
	}
}

func validDefaultReleaseInput() DefaultReleaseInput {
	identity, _ := NewIdentity(testInstallationID, testGenerationID)
	images := make(map[ServiceName]string)
	limits := make(map[ServiceName]Limits)
	for _, service := range RequiredDefaultServices() {
		images[service] = "ghcr.io/agentmemory/" + string(service) + "@sha256:" + strings.Repeat("a", 64)
		limits[service] = Limits{CPUsMilli: 1000, MemoryBytes: 1024 * 1024 * 1024, PIDs: 128}
	}
	return DefaultReleaseInput{
		Identity: identity, Release: "0.1.0", HostPort: 9411, Images: images, Limits: limits,
		Models: map[ServiceName]ModelArtifact{
			ServiceLocalEmbedding: {Revision: strings.Repeat("1", 40), SHA256: strings.Repeat("b", 64), Bytes: 1_000_000},
			ServiceLocalReranker:  {Revision: strings.Repeat("2", 40), SHA256: strings.Repeat("c", 64), Bytes: 2_000_000},
			ServiceLocalExtractor: {Revision: strings.Repeat("3", 40), SHA256: strings.Repeat("d", 64), Bytes: 3_000_000},
		},
		SecretFiles: map[string]string{
			SecretInstallationRootKey:  "/managed/agentmemory_installation_root_key",
			SecretAPICredential:        "/managed/agentmemory_api_credential",
			SecretAttestationHMACKey:   "/managed/agentmemory_attestation_hmac_key",
			SecretNeo4jPassword:        "/managed/agentmemory_neo4j_password",
			SecretEmbeddingCapability:  "/managed/agentmemory_embedding_capability",
			SecretRerankingCapability:  "/managed/agentmemory_reranking_capability",
			SecretExtractionCapability: "/managed/agentmemory_extraction_capability",
			SecretEgressAttestation:    "/managed/agentmemory_egress_attestation",
		},
	}
}
