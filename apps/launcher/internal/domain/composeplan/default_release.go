package composeplan

import (
	"strconv"
	"time"
)

// ModelArtifact is one signed local-model binding used by exactly one role.
type ModelArtifact struct {
	Revision string
	SHA256   string
	Bytes    uint64
}

// DefaultReleaseInput contains only the installation- and release-bound
// variables permitted to influence the production offline topology.
type DefaultReleaseInput struct {
	Identity    Identity
	Release     string
	HostPort    uint16
	Images      map[ServiceName]string
	Limits      map[ServiceName]Limits
	Models      map[ServiceName]ModelArtifact
	SecretFiles map[string]string
}

// NewDefaultReleasePlan constructs the entire production topology from the
// closed signed inputs. Callers cannot add services, mounts, networks,
// commands, environment keys, health probes, or resource names.
func NewDefaultReleasePlan(input DefaultReleaseInput) (PolicyPlan, error) {
	if input.HostPort == 0 || len(input.Images) != len(RequiredDefaultServices()) ||
		len(input.Limits) != len(RequiredDefaultServices()) || len(input.Models) != 3 ||
		len(input.SecretFiles) != len(requiredDefaultSecrets) {
		return PolicyPlan{}, errInvalidPolicyPlan
	}
	for _, service := range RequiredDefaultServices() {
		if input.Images[service] == "" || input.Limits[service] == (Limits{}) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for service := range input.Images {
		if !requiredService(service) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for service := range input.Limits {
		if !requiredService(service) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	providers := []ServiceName{ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor}
	for _, service := range providers {
		model, exists := input.Models[service]
		if !exists || !validRevision(model.Revision) || !validSHA256(model.SHA256) ||
			model.Bytes == 0 || model.Bytes > 16*1024*1024*1024 {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for service := range input.Models {
		if service != ServiceLocalEmbedding && service != ServiceLocalReranker && service != ServiceLocalExtractor {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for _, name := range requiredDefaultSecrets {
		if !validSecretFile(input.SecretFiles[name]) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for name := range input.SecretFiles {
		if !requiredDefaultSecret(name) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}

	release := input.Release
	generation := input.Identity.Generation()
	labels := func(purpose string, labelGeneration string) map[string]string {
		return map[string]string{
			LabelInstallation: input.Identity.InstallationID(), LabelRelease: release,
			LabelGeneration: labelGeneration, LabelPurpose: purpose, LabelManaged: "true",
		}
	}
	revisions := map[string]string{
		"AM_EMBEDDING_MODEL_REVISION":  input.Models[ServiceLocalEmbedding].Revision,
		"AM_RERANKING_MODEL_REVISION":  input.Models[ServiceLocalReranker].Revision,
		"AM_EXTRACTION_MODEL_REVISION": input.Models[ServiceLocalExtractor].Revision,
		"AM_NEO4J_USERNAME":            "neo4j",
	}
	services := make(map[ServiceName]Service, len(RequiredDefaultServices()))
	for _, name := range RequiredDefaultServices() {
		services[name] = Service{
			Name: name, Image: input.Images[name], User: "10001:10001", ReadOnly: true,
			CapDropAll: true, NoNewPrivileges: true, Restart: "unless-stopped",
			Networks: []NetworkName{NetworkInternal}, Healthcheck: defaultHealthcheck(name),
			HealthTiming: HealthcheckTiming{
				Interval: 10 * time.Second, Timeout: 8 * time.Second, Retries: 12,
				StartPeriod: 120 * time.Second, StartInterval: 2 * time.Second,
			},
			StopGracePeriod: 30 * time.Second, Limits: input.Limits[name],
			Tmpfs:  []Tmpfs{{Target: "/tmp", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777}},
			Labels: labels(string(name), generation),
		}
	}
	projector := services[ServiceSecretProjector]
	projector.User = "0:0"
	projector.CapAdd = []string{"CHOWN", "DAC_READ_SEARCH"}
	projector.Networks = nil
	projector.NetworkDisabled = true
	projector.Healthcheck = nil
	projector.HealthTiming = HealthcheckTiming{}
	projector.Restart = "no"
	projector.Environment = map[string]string{}
	projector.Mounts = defaultProjectionOutputMounts(input.Identity)
	projector.Mounts = append(projector.Mounts, defaultSecretMounts(ServiceSecretProjector)...)
	services[ServiceSecretProjector] = projector

	core := services[ServiceCore]
	core.Environment = cloneLabels(revisions)
	core.DependsOn = []Dependency{
		{Service: ServiceNeo4j, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalEmbedding, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalReranker, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalExtractor, Condition: "service_healthy", Required: true},
		{Service: ServiceMigrate, Condition: "service_completed_successfully", Required: true},
	}
	core.Ports = []Port{{HostIP: "127.0.0.1", HostPort: input.HostPort, ContainerPort: 9411}}
	core.Mounts = []Mount{
		{Kind: MountVolume, Source: input.Identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
		{Kind: MountVolume, Source: input.Identity.VolumeName("artifacts"), Target: "/var/lib/agentmemory/artifacts"},
		{Kind: MountVolume, Source: input.Identity.StableVolumeName("journal"), Target: "/var/lib/agentmemory/journal"},
		{Kind: MountVolume, Source: input.Identity.StableVolumeName("telemetry"), Target: "/var/lib/agentmemory/telemetry"},
	}
	core.Mounts = append(core.Mounts, defaultProjectionConsumerMount(input.Identity, ServiceCore))
	services[ServiceCore] = core

	neo4j := services[ServiceNeo4j]
	neo4j.User = "7474:7474"
	neo4j.Tmpfs[0].Executable = true
	neo4j.Environment = map[string]string{
		"NEO4J_client_allow__telemetry":       "false",
		"NEO4J_server_bolt_telemetry_enabled": "false",
	}
	neo4j.Tmpfs = append(neo4j.Tmpfs,
		Tmpfs{Target: "/logs", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777},
		Tmpfs{Target: "/var/lib/neo4j/run", SizeBytes: 16 * 1024 * 1024, Mode: 0o1777},
	)
	neo4j.Mounts = []Mount{{Kind: MountVolume, Source: input.Identity.VolumeName("neo4j"), Target: "/data"}}
	neo4j.Mounts = append(neo4j.Mounts, defaultProjectionConsumerMount(input.Identity, ServiceNeo4j))
	services[ServiceNeo4j] = neo4j

	roles := map[ServiceName]string{
		ServiceLocalEmbedding: "embedding", ServiceLocalReranker: "reranking", ServiceLocalExtractor: "extraction",
	}
	for _, name := range providers {
		provider := services[name]
		artifact := input.Models[name]
		provider.Environment = map[string]string{
			"AM_PROVIDER_ROLE": roles[name], "AM_PROVIDER_MODEL_REVISION": artifact.Revision,
			"AM_PROVIDER_MODEL_SHA256": artifact.SHA256,
			"AM_PROVIDER_MODEL_SIZE":   strconv.FormatUint(artifact.Bytes, 10),
		}
		provider.Mounts = []Mount{{
			Kind: MountVolume, Source: input.Identity.StableVolumeName("models"), Target: "/models", ReadOnly: true,
		}}
		provider.Mounts = append(provider.Mounts, defaultProjectionConsumerMount(input.Identity, name))
		services[name] = provider
	}

	migrate := services[ServiceMigrate]
	migrate.Healthcheck = nil
	migrate.HealthTiming = HealthcheckTiming{}
	migrate.Restart = "no"
	migrate.Environment = cloneLabels(revisions)
	migrate.DependsOn = []Dependency{{Service: ServiceNeo4j, Condition: "service_healthy", Required: true}}
	migrate.Mounts = []Mount{{
		Kind: MountVolume, Source: input.Identity.VolumeName("state"), Target: "/var/lib/agentmemory/state",
	}}
	migrate.Mounts = append(migrate.Mounts, defaultProjectionConsumerMount(input.Identity, ServiceMigrate))
	services[ServiceMigrate] = migrate

	volumes := make(map[string]Volume, 12)
	for _, purpose := range []string{"state", "artifacts", "neo4j"} {
		name := input.Identity.VolumeName(purpose)
		volumes[name] = Volume{Name: name, Labels: labels(purpose, generation)}
	}
	for _, purpose := range []string{"journal", "models", "telemetry"} {
		name := input.Identity.StableVolumeName(purpose)
		volumes[name] = Volume{Name: name, Labels: labels(purpose, "stable")}
	}
	for _, purpose := range requiredProjectionPurposes() {
		name := input.Identity.VolumeName(purpose)
		volumes[name] = Volume{Name: name, Labels: labels(purpose, generation)}
	}
	secrets := make(map[string]Secret, len(requiredDefaultSecrets))
	for _, name := range requiredDefaultSecrets {
		secrets[name] = Secret{Name: input.Identity.StableVolumeName(name), File: input.SecretFiles[name]}
	}
	return NewPolicyPlan(Model{
		Identity: input.Identity, Release: release, Services: services,
		Networks: map[NetworkName]Network{
			NetworkInternal: {
				Name: input.Identity.NetworkName("internal"), Internal: true,
				Labels: labels("internal", generation),
			},
		},
		Volumes: volumes, Secrets: secrets,
	})
}

func defaultHealthcheck(name ServiceName) []string {
	return map[ServiceName][]string{
		ServiceCore:           {"CMD", "/usr/local/bin/agentmemory-healthcheck"},
		ServiceNeo4j:          {"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"},
		ServiceLocalEmbedding: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalReranker:  {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalExtractor: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
	}[name]
}

func defaultSecretMounts(service ServiceName) []Mount {
	required := requiredSecretMounts(service)
	mounts := make([]Mount, 0, len(required))
	for _, name := range requiredDefaultSecrets {
		if target, exists := required[name]; exists {
			mounts = append(mounts, Mount{Kind: MountSecret, Source: name, Target: target, ReadOnly: true})
		}
	}
	return mounts
}

func defaultProjectionConsumerMount(identity Identity, service ServiceName) Mount {
	return Mount{
		Kind: MountVolume, Source: identity.VolumeName(projectionPurposeForService(service)),
		Target: "/run/secrets", ReadOnly: true,
	}
}

func defaultProjectionOutputMounts(identity Identity) []Mount {
	mounts := make([]Mount, 0, len(requiredProjectionPurposes()))
	for _, purpose := range requiredProjectionPurposes() {
		mounts = append(mounts, Mount{
			Kind: MountVolume, Source: identity.VolumeName(purpose), Target: "/run/outputs/" + purpose,
		})
	}
	return mounts
}
