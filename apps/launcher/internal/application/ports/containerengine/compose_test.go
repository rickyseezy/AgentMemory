package containerengine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ComposeProjectAcceptsOnlyExplicitReleaseBoundAddressing(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	digest := releaseinventory.DigestBytes([]byte("rendered"))
	plan := composeProjectTestPlan(t)
	project, err := NewComposeProject(
		endpoint,
		"agentmemory_019f5f2012347abc81230123456789ab",
		"/managed/release",
		"/managed/release/compose.yaml",
		"/managed/release/empty.env",
		digest,
		plan,
		300,
	)
	if err != nil {
		t.Fatal(err)
	}
	if project.Endpoint() != endpoint || project.Name() != "agentmemory_019f5f2012347abc81230123456789ab" ||
		project.ProjectDirectory() != "/managed/release" ||
		project.ConfigurationPath() != "/managed/release/compose.yaml" ||
		project.EmptyEnvironmentPath() != "/managed/release/empty.env" ||
		!project.ExpectedConfigurationDigest().Equal(digest) || !project.ExpectedPolicyPlan().Valid() ||
		project.WaitTimeSeconds() != 300 {
		t.Fatalf("project accessors lost addressing: %+v", project)
	}
}

func TestPF001ComposeReleaseSourceIsClosedAndImmutable(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab", "019f5f21-5678-7def-9123-abcdef012345",
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := releaseinventory.DigestBytes([]byte("signed compose source"))
	source, err := NewComposeReleaseSource(
		endpoint, identity, "0.1.0", "/managed/release", "/managed/release/compose.json",
		"/managed/release/empty.env", digest, 300,
	)
	if err != nil {
		t.Fatal(err)
	}
	if source.Endpoint() != endpoint || source.Identity().InstallationID() != identity.InstallationID() ||
		source.Identity().Generation() != identity.Generation() || source.Release() != "0.1.0" ||
		source.ProjectDirectory() != "/managed/release" || source.ConfigurationPath() != "/managed/release/compose.json" ||
		source.EmptyEnvironmentPath() != "/managed/release/empty.env" || !source.SourceDigest().Equal(digest) ||
		source.WaitTimeSeconds() != 300 {
		t.Fatalf("release source accessors lost authority: %+v", source)
	}

	tests := []struct {
		name        string
		endpoint    Endpoint
		identity    composeplan.Identity
		release     string
		directory   string
		config      string
		environment string
		digest      releaseinventory.Digest
		wait        uint16
	}{
		{name: "zero endpoint", identity: identity, release: "0.1.0", directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "zero identity", endpoint: endpoint, release: "0.1.0", directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "invalid release", endpoint: endpoint, identity: identity, release: "../next", directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "empty release", endpoint: endpoint, identity: identity, directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "long release", endpoint: endpoint, identity: identity, release: strings.Repeat("a", 129), directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "unsafe path", endpoint: endpoint, identity: identity, release: "v1_rc-1", directory: "/release\n", config: "/release/c", environment: "/release/e", digest: digest, wait: 1},
		{name: "same source files", endpoint: endpoint, identity: identity, release: "v1", directory: "/release", config: "/release/c", environment: "/release/c", digest: digest, wait: 1},
		{name: "zero digest", endpoint: endpoint, identity: identity, release: "v1", directory: "/release", config: "/release/c", environment: "/release/e", wait: 1},
		{name: "zero wait", endpoint: endpoint, identity: identity, release: "v1", directory: "/release", config: "/release/c", environment: "/release/e", digest: digest},
		{name: "excessive wait", endpoint: endpoint, identity: identity, release: "v1", directory: "/release", config: "/release/c", environment: "/release/e", digest: digest, wait: 301},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewComposeReleaseSource(
				test.endpoint, test.identity, test.release, test.directory, test.config,
				test.environment, test.digest, test.wait,
			)
			if !errors.Is(err, ErrInvalidComposeProject) {
				t.Fatalf("NewComposeReleaseSource() error = %v", err)
			}
		})
	}
}

func TestPF001ComposeProjectRejectsUnsafeOrAmbientInputs(t *testing.T) {
	t.Parallel()

	endpoint, _ := NewEndpoint("unix:///var/run/docker.sock")
	digest := releaseinventory.DigestBytes([]byte("rendered"))
	plan := composeProjectTestPlan(t)
	valid := func() (Endpoint, string, string, string, string, releaseinventory.Digest, composeplan.PolicyPlan, uint16) {
		return endpoint,
			"agentmemory_019f5f2012347abc81230123456789ab",
			"/managed/release",
			"/managed/release/compose.yaml",
			"/managed/release/empty.env",
			digest,
			plan,
			300
	}
	tests := []struct {
		name   string
		mutate func(*Endpoint, *string, *string, *string, *string, *releaseinventory.Digest, *composeplan.PolicyPlan, *uint16)
	}{
		{name: "zero endpoint", mutate: func(endpoint *Endpoint, _ *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*endpoint = Endpoint{}
		}},
		{name: "user project", mutate: func(_ *Endpoint, name *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*name = "agentmemory_project-name"
		}},
		{name: "upper project", mutate: func(_ *Endpoint, name *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*name = "agentmemory_019F5f2012347abc81230123456789ab"
		}},
		{name: "path newline", mutate: func(_ *Endpoint, _ *string, directory *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*directory += "\n--project-name=other"
		}},
		{name: "same files", mutate: func(_ *Endpoint, _ *string, _ *string, config *string, environment *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*environment = *config
		}},
		{name: "zero digest", mutate: func(_ *Endpoint, _ *string, _ *string, _ *string, _ *string, digest *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*digest = releaseinventory.Digest{}
		}},
		{name: "zero plan", mutate: func(_ *Endpoint, _ *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, plan *composeplan.PolicyPlan, _ *uint16) {
			*plan = composeplan.PolicyPlan{}
		}},
		{name: "zero timeout", mutate: func(_ *Endpoint, _ *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, timeout *uint16) {
			*timeout = 0
		}},
		{name: "long timeout", mutate: func(_ *Endpoint, _ *string, _ *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, timeout *uint16) {
			*timeout = 301
		}},
		{name: "long path", mutate: func(_ *Endpoint, _ *string, directory *string, _ *string, _ *string, _ *releaseinventory.Digest, _ *composeplan.PolicyPlan, _ *uint16) {
			*directory = "/" + strings.Repeat("a", maximumComposePath)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actualEndpoint, name, directory, config, environment, actualDigest, actualPlan, timeout := valid()
			test.mutate(&actualEndpoint, &name, &directory, &config, &environment, &actualDigest, &actualPlan, &timeout)
			_, err := NewComposeProject(actualEndpoint, name, directory, config, environment, actualDigest, actualPlan, timeout)
			if !errors.Is(err, ErrInvalidComposeProject) {
				t.Fatalf("NewComposeProject() error = %v, want ErrInvalidComposeProject", err)
			}
		})
	}
}

func composeProjectTestPlan(t *testing.T) composeplan.PolicyPlan {
	t.Helper()
	identity, err := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab", "019f5f21-5678-7def-9123-abcdef012345",
	)
	if err != nil {
		t.Fatal(err)
	}
	labels := func(purpose string, generation string) map[string]string {
		return map[string]string{
			composeplan.LabelInstallation: identity.InstallationID(), composeplan.LabelRelease: "0.1.0",
			composeplan.LabelGeneration: generation, composeplan.LabelPurpose: purpose, composeplan.LabelManaged: "true",
		}
	}
	services := make(map[composeplan.ServiceName]composeplan.Service)
	for _, name := range composeplan.RequiredDefaultServices() {
		services[name] = composeplan.Service{
			Name: name, Image: "ghcr.io/agentmemory/" + string(name) + "@sha256:" + strings.Repeat("a", 64),
			User: "10001:10001", ReadOnly: true, CapDropAll: true, NoNewPrivileges: true,
			Restart: "unless-stopped", Networks: []composeplan.NetworkName{composeplan.NetworkInternal},
			Healthcheck: composeProjectHealthcheck(name),
			HealthTiming: composeplan.HealthcheckTiming{
				Interval: 10 * time.Second, Timeout: 3 * time.Second, Retries: 5,
				StartPeriod: 30 * time.Second, StartInterval: 2 * time.Second,
			},
			StopGracePeriod: 30 * time.Second,
			Limits:          composeplan.Limits{CPUsMilli: 1000, MemoryBytes: 1024 * 1024 * 1024, PIDs: 128},
			Tmpfs:           []composeplan.Tmpfs{{Target: "/tmp", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777}},
			Labels:          labels(string(name), identity.Generation()),
			Environment:     composeProjectEnvironment(name),
		}
		if name == composeplan.ServiceNeo4j {
			service := services[name]
			service.User = "7474:7474"
			service.Tmpfs[0].Executable = true
			service.Tmpfs = append(service.Tmpfs,
				composeplan.Tmpfs{Target: "/logs", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777},
				composeplan.Tmpfs{Target: "/var/lib/neo4j/run", SizeBytes: 16 * 1024 * 1024, Mode: 0o1777},
			)
			services[name] = service
		}
	}
	projectionPurpose := map[composeplan.ServiceName]string{
		composeplan.ServiceCore: "protected-core", composeplan.ServiceMigrate: "protected-migrate",
		composeplan.ServiceNeo4j: "protected-neo4j", composeplan.ServiceLocalEmbedding: "protected-embedding",
		composeplan.ServiceLocalReranker: "protected-reranking", composeplan.ServiceLocalExtractor: "protected-extraction",
	}
	projector := services[composeplan.ServiceSecretProjector]
	projector.User = "0:0"
	projector.CapAdd = []string{"CHOWN", "DAC_READ_SEARCH"}
	projector.Networks = nil
	projector.NetworkDisabled = true
	projector.Healthcheck = nil
	projector.HealthTiming = composeplan.HealthcheckTiming{}
	projector.Restart = "no"
	projector.Environment = map[string]string{}
	for _, purpose := range []string{
		"protected-core", "protected-migrate", "protected-neo4j",
		"protected-embedding", "protected-reranking", "protected-extraction",
	} {
		projector.Mounts = append(projector.Mounts, composeplan.Mount{
			Kind: composeplan.MountVolume, Source: identity.VolumeName(purpose), Target: "/run/outputs/" + purpose,
		})
	}
	for name := range composeProjectSecrets(identity) {
		projector.Mounts = append(projector.Mounts, composeplan.Mount{
			Kind: composeplan.MountSecret, Source: name, Target: "/run/inputs/" + name, ReadOnly: true,
		})
	}
	services[composeplan.ServiceSecretProjector] = projector
	core := services[composeplan.ServiceCore]
	core.DependsOn = []composeplan.Dependency{
		{Service: composeplan.ServiceNeo4j, Condition: "service_healthy", Required: true},
		{Service: composeplan.ServiceLocalEmbedding, Condition: "service_healthy", Required: true},
		{Service: composeplan.ServiceLocalReranker, Condition: "service_healthy", Required: true},
		{Service: composeplan.ServiceLocalExtractor, Condition: "service_healthy", Required: true},
		{Service: composeplan.ServiceMigrate, Condition: "service_completed_successfully", Required: true},
	}
	core.Ports = []composeplan.Port{{HostIP: "127.0.0.1", HostPort: 9411, ContainerPort: 9411}}
	core.Mounts = []composeplan.Mount{
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("artifacts"), Target: "/var/lib/agentmemory/artifacts"},
		{Kind: composeplan.MountVolume, Source: identity.StableVolumeName("journal"), Target: "/var/lib/agentmemory/journal"},
		{Kind: composeplan.MountVolume, Source: identity.StableVolumeName("telemetry"), Target: "/var/lib/agentmemory/telemetry"},
	}
	core.Mounts = append(core.Mounts, composeProjectProjectionMount(identity, projectionPurpose[composeplan.ServiceCore]))
	services[composeplan.ServiceCore] = core
	neo4j := services[composeplan.ServiceNeo4j]
	neo4j.Mounts = []composeplan.Mount{{Kind: composeplan.MountVolume, Source: identity.VolumeName("neo4j"), Target: "/data"}}
	neo4j.Mounts = append(neo4j.Mounts, composeProjectProjectionMount(identity, projectionPurpose[composeplan.ServiceNeo4j]))
	services[composeplan.ServiceNeo4j] = neo4j
	for _, name := range []composeplan.ServiceName{composeplan.ServiceLocalEmbedding, composeplan.ServiceLocalReranker, composeplan.ServiceLocalExtractor} {
		service := services[name]
		service.Mounts = []composeplan.Mount{{Kind: composeplan.MountVolume, Source: identity.StableVolumeName("models"), Target: "/models", ReadOnly: true}}
		service.Mounts = append(service.Mounts, composeProjectProjectionMount(identity, projectionPurpose[name]))
		services[name] = service
	}
	migrate := services[composeplan.ServiceMigrate]
	migrate.Healthcheck = nil
	migrate.HealthTiming = composeplan.HealthcheckTiming{}
	migrate.Restart = "no"
	migrate.DependsOn = []composeplan.Dependency{{Service: composeplan.ServiceNeo4j, Condition: "service_healthy", Required: true}}
	migrate.Mounts = []composeplan.Mount{
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
	}
	migrate.Mounts = append(migrate.Mounts, composeProjectProjectionMount(identity, projectionPurpose[composeplan.ServiceMigrate]))
	services[composeplan.ServiceMigrate] = migrate
	volumes := make(map[string]composeplan.Volume)
	for _, purpose := range []string{"state", "artifacts", "neo4j"} {
		name := identity.VolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: labels(purpose, identity.Generation())}
	}
	for _, purpose := range []string{"journal", "models", "telemetry"} {
		name := identity.StableVolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: labels(purpose, "stable")}
	}
	for _, purpose := range []string{
		"protected-core", "protected-migrate", "protected-neo4j",
		"protected-embedding", "protected-reranking", "protected-extraction",
	} {
		name := identity.VolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: labels(purpose, identity.Generation())}
	}
	plan, err := composeplan.NewPolicyPlan(composeplan.Model{
		Identity: identity, Release: "0.1.0", Services: services,
		Networks: map[composeplan.NetworkName]composeplan.Network{
			composeplan.NetworkInternal: {Name: identity.NetworkName("internal"), Internal: true, Labels: labels("internal", identity.Generation())},
		},
		Volumes: volumes,
		Secrets: composeProjectSecrets(identity),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func composeProjectHealthcheck(name composeplan.ServiceName) []string {
	return map[composeplan.ServiceName][]string{
		composeplan.ServiceCore:           {"CMD", "/usr/local/bin/agentmemory-healthcheck"},
		composeplan.ServiceNeo4j:          {"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"},
		composeplan.ServiceLocalEmbedding: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		composeplan.ServiceLocalReranker:  {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		composeplan.ServiceLocalExtractor: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
	}[name]
}

func composeProjectEnvironment(name composeplan.ServiceName) map[string]string {
	revisions := map[string]string{
		"AM_EMBEDDING_MODEL_REVISION":  strings.Repeat("1", 40),
		"AM_RERANKING_MODEL_REVISION":  strings.Repeat("2", 40),
		"AM_EXTRACTION_MODEL_REVISION": strings.Repeat("3", 40),
		"AM_NEO4J_USERNAME":            "neo4j",
	}
	if name == composeplan.ServiceCore || name == composeplan.ServiceMigrate {
		return revisions
	}
	if name == composeplan.ServiceNeo4j {
		return map[string]string{
			"NEO4J_client_allow__telemetry":       "false",
			"NEO4J_server_bolt_telemetry_enabled": "false",
		}
	}
	role := map[composeplan.ServiceName]string{
		composeplan.ServiceLocalEmbedding: "embedding",
		composeplan.ServiceLocalReranker:  "reranking",
		composeplan.ServiceLocalExtractor: "extraction",
	}[name]
	revisionKey := map[composeplan.ServiceName]string{
		composeplan.ServiceLocalEmbedding: "AM_EMBEDDING_MODEL_REVISION",
		composeplan.ServiceLocalReranker:  "AM_RERANKING_MODEL_REVISION",
		composeplan.ServiceLocalExtractor: "AM_EXTRACTION_MODEL_REVISION",
	}[name]
	return map[string]string{
		"AM_PROVIDER_ROLE": role, "AM_PROVIDER_MODEL_REVISION": revisions[revisionKey],
		"AM_PROVIDER_MODEL_SHA256": strings.Repeat("a", 64), "AM_PROVIDER_MODEL_SIZE": "1048576",
	}
}

func composeProjectProjectionMount(identity composeplan.Identity, purpose string) composeplan.Mount {
	return composeplan.Mount{
		Kind: composeplan.MountVolume, Source: identity.VolumeName(purpose), Target: "/run/secrets", ReadOnly: true,
	}
}

func composeProjectSecrets(identity composeplan.Identity) map[string]composeplan.Secret {
	names := []string{
		composeplan.SecretInstallationRootKey, composeplan.SecretAPICredential,
		composeplan.SecretAttestationHMACKey, composeplan.SecretNeo4jPassword,
		composeplan.SecretEmbeddingCapability, composeplan.SecretRerankingCapability,
		composeplan.SecretExtractionCapability, composeplan.SecretEgressAttestation,
	}
	secrets := make(map[string]composeplan.Secret, len(names))
	for _, name := range names {
		secrets[name] = composeplan.Secret{Name: identity.StableVolumeName(name), File: "/managed/release/" + name}
	}
	return secrets
}

func TestPF001RenderedConfigurationIsImmutableAndContentBound(t *testing.T) {
	t.Parallel()

	input := []byte(`{"services":{}}`)
	rendered, err := NewRenderedConfiguration(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'x'
	returned := rendered.CanonicalBytes()
	returned[0] = 'y'
	want := []byte(`{"services":{}}`)
	if string(rendered.CanonicalBytes()) != string(want) ||
		!rendered.Digest().Equal(releaseinventory.DigestBytes(want)) {
		t.Fatal("rendered configuration exposed mutable storage or lost its digest")
	}
	if _, err := NewRenderedConfiguration(nil); !errors.Is(err, ErrComposeConfigurationMismatch) {
		t.Fatalf("empty render error = %v", err)
	}
}
