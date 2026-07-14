package composeplan

import (
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	testInstallationID = "019f5f20-1234-7abc-8123-0123456789ab"
	testGenerationID   = "019f5f21-5678-7def-9123-abcdef012345"
)

func TestPF001DefaultComposePolicyAcceptsOnlyHardenedOfflineTopology(t *testing.T) {
	t.Parallel()

	model := validDefaultModel()
	if violations := NewPolicy().Validate(model); len(violations) != 0 {
		t.Fatalf("valid model violations = %+v", violations)
	}
}

func TestPF001MigrationUsesOnlyTheSignedImageEntrypoint(t *testing.T) {
	t.Parallel()

	model := validDefaultModel()
	if containsViolation(NewPolicy().Validate(model), ViolationClosedInventory) {
		t.Fatal("empty migration command was rejected")
	}
	for _, test := range []struct {
		name    string
		command []string
	}{
		{name: "missing subcommand", command: []string{"/app/agentmemory"}},
		{name: "wrong subcommand", command: []string{"/app/agentmemory", "other"}},
		{name: "wrong executable", command: []string{"/other/agentmemory", "migrate"}},
		{name: "additional argument", command: []string{"/app/agentmemory", "migrate", "--force"}},
		{name: "shell", command: []string{"sh", "-c", "/app/agentmemory migrate"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			model := validDefaultModel()
			migrate := model.Services[ServiceMigrate]
			migrate.Command = append([]string(nil), test.command...)
			model.Services[ServiceMigrate] = migrate
			if !containsViolation(NewPolicy().Validate(model), ViolationClosedInventory) {
				t.Fatalf("migration command %q was accepted", test.command)
			}
		})
	}
}

func TestPF001DefaultComposePolicyRejectsEveryIsolationRegression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Model)
		code   ViolationCode
	}{
		{name: "missing service", mutate: func(model *Model) { delete(model.Services, ServiceLocalExtractor) }, code: ViolationRequiredService},
		{name: "unknown service", mutate: func(model *Model) {
			model.Services[ServiceName("debug-shell")] = hardenedService(ServiceName("debug-shell"), model.Identity.Generation())
		}, code: ViolationClosedInventory},
		{name: "mutable image", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Image = "ghcr.io/agentmemory/core:latest"
			model.Services[ServiceCore] = service
		}, code: ViolationImageDigest},
		{name: "root user", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.User = "0:0"
			model.Services[ServiceCore] = service
		}, code: ViolationNonRoot},
		{name: "named user", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.User = "root"
			model.Services[ServiceCore] = service
		}, code: ViolationNonRoot},
		{name: "writable root", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.ReadOnly = false
			model.Services[ServiceCore] = service
		}, code: ViolationReadOnly},
		{name: "capability added", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.CapDropAll = false
			model.Services[ServiceCore] = service
		}, code: ViolationCapabilities},
		{name: "privileged", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Privileged = true
			model.Services[ServiceCore] = service
		}, code: ViolationPrivileged},
		{name: "host namespace", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.HostNetwork = true
			model.Services[ServiceCore] = service
		}, code: ViolationHostNamespace},
		{name: "missing no-new-privileges", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.NoNewPrivileges = false
			model.Services[ServiceCore] = service
		}, code: ViolationNoNewPrivileges},
		{name: "missing limits", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Limits.MemoryBytes = 0
			model.Services[ServiceCore] = service
		}, code: ViolationResourceLimits},
		{name: "world-accessible tmpfs", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Tmpfs[0].Mode = 0o777
			model.Services[ServiceCore] = service
		}, code: ViolationResourceLimits},
		{name: "missing health", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Healthcheck = nil
			model.Services[ServiceCore] = service
		}, code: ViolationHealthcheck},
		{name: "missing health timing", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.HealthTiming.Timeout = 0
			model.Services[ServiceCore] = service
		}, code: ViolationHealthcheck},
		{name: "missing stop grace", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.StopGracePeriod = 0
			model.Services[ServiceCore] = service
		}, code: ViolationRestartPolicy},
		{name: "missing dependency", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.DependsOn = service.DependsOn[1:]
			model.Services[ServiceCore] = service
		}, code: ViolationDependencies},
		{name: "shell migration command", mutate: func(model *Model) {
			service := model.Services[ServiceMigrate]
			service.Command = []string{"sh", "-c", "migrate"}
			model.Services[ServiceMigrate] = service
		}, code: ViolationClosedInventory},
		{name: "weak dependency", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.DependsOn[0].Condition = "service_started"
			model.Services[ServiceCore] = service
		}, code: ViolationDependencies},
		{name: "shell health", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Healthcheck = []string{"CMD-SHELL", "curl localhost"}
			model.Services[ServiceCore] = service
		}, code: ViolationHealthcheck},
		{name: "wrong restart", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Restart = "always"
			model.Services[ServiceCore] = service
		}, code: ViolationRestartPolicy},
		{name: "LAN port", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Ports[0].HostIP = "0.0.0.0"
			model.Services[ServiceCore] = service
		}, code: ViolationPortExposure},
		{name: "Neo4j port", mutate: func(model *Model) {
			service := model.Services[ServiceNeo4j]
			service.Ports = []Port{{HostIP: "127.0.0.1", HostPort: 7687, ContainerPort: 7687}}
			model.Services[ServiceNeo4j] = service
		}, code: ViolationPortExposure},
		{name: "duplicate loopback port family", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Ports = append(service.Ports, service.Ports[0])
			model.Services[ServiceCore] = service
		}, code: ViolationPortExposure},
		{name: "split loopback ports", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Ports = append(service.Ports, Port{HostIP: "::1", HostPort: 19411, ContainerPort: 9411})
			model.Services[ServiceCore] = service
		}, code: ViolationPortExposure},
		{name: "external route", mutate: func(model *Model) {
			model.Networks[NetworkInternal] = Network{Name: model.Networks[NetworkInternal].Name, Internal: false, Labels: model.Networks[NetworkInternal].Labels}
		}, code: ViolationNetworkIsolation},
		{name: "default egress", mutate: func(model *Model) {
			model.Networks[NetworkEgress] = Network{Name: "agentmemory_iid_egress", Internal: false, Labels: validLabelMap("egress", testGenerationID)}
		}, code: ViolationNetworkIsolation},
		{name: "unknown network", mutate: func(model *Model) {
			model.Networks[NetworkName("default")] = Network{Name: "default", Internal: false, Labels: validLabelMap("default", testGenerationID)}
		}, code: ViolationClosedInventory},
		{name: "Docker socket", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts = append(service.Mounts, Mount{Kind: MountBind, Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"})
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "unowned named volume", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts[0].Source = "unrelated_user_volume"
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "missing required volume", mutate: func(model *Model) {
			delete(model.Volumes, model.Identity.StableVolumeName("journal"))
		}, code: ViolationClosedInventory},
		{name: "missing required mount", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts = service.Mounts[1:]
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "duplicate mount target", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts[1].Target = service.Mounts[0].Target
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "writable provider model cache", mutate: func(model *Model) {
			service := model.Services[ServiceLocalEmbedding]
			service.Mounts[0].ReadOnly = false
			model.Services[ServiceLocalEmbedding] = service
		}, code: ViolationMountPolicy},
		{name: "missing installation key", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts = service.Mounts[:len(service.Mounts)-1]
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "writable secret", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts = append(service.Mounts, Mount{Kind: MountSecret, Source: "key", Target: "/run/secrets/key", ReadOnly: false})
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "unbound config resource", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts = append(service.Mounts, Mount{Kind: MountConfig, Source: "core-config", Target: "/etc/agentmemory/config", ReadOnly: true})
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "secret outside secret directory", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Mounts[len(service.Mounts)-1].Target = "/tmp/key"
			model.Services[ServiceCore] = service
		}, code: ViolationMountPolicy},
		{name: "empty release", mutate: func(model *Model) {
			model.Release = ""
			for name, service := range model.Services {
				service.Labels[LabelRelease] = ""
				model.Services[name] = service
			}
			for name, network := range model.Networks {
				network.Labels[LabelRelease] = ""
				model.Networks[name] = network
			}
			for name, volume := range model.Volumes {
				volume.Labels[LabelRelease] = ""
				model.Volumes[name] = volume
			}
		}, code: ViolationLabels},
		{name: "wrong labels", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Labels[LabelManaged] = "false"
			model.Services[ServiceCore] = service
		}, code: ViolationLabels},
	}

	policy := NewPolicy()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			model := validDefaultModel()
			test.mutate(&model)
			violations := policy.Validate(model)
			if !containsViolation(violations, test.code) {
				t.Fatalf("violations = %+v, want %s", violations, test.code)
			}
		})
	}
}

func TestPF001ComposeResourceNamesRejectUserControlledText(t *testing.T) {
	t.Parallel()

	identity, err := NewIdentity(testInstallationID, testGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(identity.ProjectName(), "-") ||
		identity.ProjectName() != "agentmemory_019f5f2012347abc81230123456789ab" ||
		strings.Contains(identity.VolumeName("state"), "-") {
		t.Fatalf("resource names are not canonical: project=%q volume=%q", identity.ProjectName(), identity.VolumeName("state"))
	}
	for _, value := range []string{
		"../brain",
		"Project Name",
		"$(id)",
		"",
		strings.Repeat("a", 65),
		"019f5f21-5678-4def-9123-abcdef012345",
		"019f5f21-5678-7def-7123-abcdef012345",
	} {
		if _, err := NewIdentity(testInstallationID, value); err == nil {
			t.Fatalf("unsafe generation %q accepted", value)
		}
	}
}

func containsViolation(violations []Violation, code ViolationCode) bool {
	for _, violation := range violations {
		if violation.Code == code {
			return true
		}
	}
	return false
}

func validDefaultModel() Model {
	identity, _ := NewIdentity(testInstallationID, testGenerationID)
	services := make(map[ServiceName]Service)
	for _, name := range RequiredDefaultServices() {
		service := hardenedService(name, identity.Generation())
		services[name] = service
	}
	core := services[ServiceCore]
	core.DependsOn = []Dependency{
		{Service: ServiceNeo4j, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalEmbedding, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalReranker, Condition: "service_healthy", Required: true},
		{Service: ServiceLocalExtractor, Condition: "service_healthy", Required: true},
		{Service: ServiceMigrate, Condition: "service_completed_successfully", Required: true},
	}
	core.Ports = []Port{{HostIP: "127.0.0.1", HostPort: 9411, ContainerPort: 9411}}
	core.Mounts = []Mount{
		{Kind: MountVolume, Source: identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
		{Kind: MountVolume, Source: identity.VolumeName("artifacts"), Target: "/var/lib/agentmemory/artifacts"},
		{Kind: MountVolume, Source: identity.StableVolumeName("journal"), Target: "/var/lib/agentmemory/journal"},
		{Kind: MountVolume, Source: identity.StableVolumeName("telemetry"), Target: "/var/lib/agentmemory/telemetry"},
		{Kind: MountVolume, Source: identity.VolumeName(projectionPurposeCore), Target: "/run/secrets", ReadOnly: true},
	}
	services[ServiceCore] = core
	neo4j := withMount(services[ServiceNeo4j], Mount{
		Kind: MountVolume, Source: identity.VolumeName("neo4j"), Target: "/data",
	})
	neo4j.Mounts = append(neo4j.Mounts, Mount{
		Kind: MountVolume, Source: identity.VolumeName(projectionPurposeNeo4j), Target: "/run/secrets", ReadOnly: true,
	})
	services[ServiceNeo4j] = neo4j
	for _, provider := range []ServiceName{ServiceLocalEmbedding, ServiceLocalReranker, ServiceLocalExtractor} {
		service := withMount(services[provider], Mount{
			Kind: MountVolume, Source: identity.StableVolumeName("models"), Target: "/models", ReadOnly: true,
		})
		service.Mounts = append(service.Mounts, Mount{
			Kind: MountVolume, Source: identity.VolumeName(projectionPurposeForService(provider)),
			Target: "/run/secrets", ReadOnly: true,
		})
		services[provider] = service
	}
	migrate := services[ServiceMigrate]
	migrate.Healthcheck = nil
	migrate.HealthTiming = HealthcheckTiming{}
	migrate.Restart = "no"
	migrate.DependsOn = []Dependency{{Service: ServiceNeo4j, Condition: "service_healthy", Required: true}}
	migrate.Mounts = []Mount{
		{Kind: MountVolume, Source: identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
		{Kind: MountVolume, Source: identity.VolumeName(projectionPurposeMigrate), Target: "/run/secrets", ReadOnly: true},
	}
	services[ServiceMigrate] = migrate
	projector := services[ServiceSecretProjector]
	projector.User = "0:0"
	projector.CapAdd = []string{"CHOWN", "DAC_READ_SEARCH"}
	projector.Networks = nil
	projector.NetworkDisabled = true
	projector.Healthcheck = nil
	projector.HealthTiming = HealthcheckTiming{}
	projector.Restart = "no"
	projector.Environment = map[string]string{}
	for _, purpose := range requiredProjectionPurposes() {
		projector.Mounts = append(projector.Mounts, Mount{
			Kind: MountVolume, Source: identity.VolumeName(purpose), Target: "/run/outputs/" + purpose,
		})
	}
	projector.Mounts = append(projector.Mounts, testSecretMounts(ServiceSecretProjector)...)
	services[ServiceSecretProjector] = projector

	volumes := map[string]Volume{}
	for _, purpose := range []string{"state", "artifacts", "neo4j"} {
		name := identity.VolumeName(purpose)
		volumes[name] = Volume{Name: name, Labels: validLabelMap(purpose, identity.Generation())}
	}
	models := identity.StableVolumeName("models")
	volumes[models] = Volume{Name: models, Labels: validLabelMap("models", "stable")}
	journal := identity.StableVolumeName("journal")
	volumes[journal] = Volume{Name: journal, Labels: validLabelMap("journal", "stable")}
	telemetry := identity.StableVolumeName("telemetry")
	volumes[telemetry] = Volume{Name: telemetry, Labels: validLabelMap("telemetry", "stable")}
	for _, purpose := range requiredProjectionPurposes() {
		name := identity.VolumeName(purpose)
		volumes[name] = Volume{Name: name, Labels: validLabelMap(purpose, identity.Generation())}
	}
	return Model{
		Identity: identity,
		Release:  "0.1.0",
		Services: services,
		Networks: map[NetworkName]Network{
			NetworkInternal: {
				Name: identity.NetworkName("internal"), Internal: true,
				Labels: validLabelMap("internal", identity.Generation()),
			},
		},
		Volumes: volumes,
		Secrets: testSecrets(identity, "/managed/release"),
	}
}

func TestPF001PolicyPlanIsImmutableCanonicalAndContentEqual(t *testing.T) {
	t.Parallel()

	model := validDefaultModel()
	plan, err := NewPolicyPlan(model)
	if err != nil {
		t.Fatal(err)
	}
	core := model.Services[ServiceCore]
	core.Image = "ghcr.io/agentmemory/core@sha256:" + strings.Repeat("b", 64)
	model.Services[ServiceCore] = core
	if !plan.Valid() || plan.Matches(model) {
		t.Fatal("policy plan accepted caller mutation or semantic substitution")
	}
	if source, ok := plan.InstallationKeyFile(); !ok || source != "/managed/release/"+SecretInstallationRootKey {
		t.Fatalf("authenticated installation-key source = %q/%v", source, ok)
	}
	files, ok := plan.SecretFiles()
	if !ok || len(files) != len(requiredDefaultSecrets) || files[SecretAPICredential] != "/managed/release/"+SecretAPICredential {
		t.Fatalf("authenticated secret file inventory = %#v/%v", files, ok)
	}
	if source, ok := (PolicyPlan{}).InstallationKeyFile(); ok || source != "" {
		t.Fatalf("zero-plan installation-key source = %q/%v", source, ok)
	}

	expected := validDefaultModel()
	core = expected.Services[ServiceCore]
	core.DependsOn[0], core.DependsOn[3] = core.DependsOn[3], core.DependsOn[0]
	core.Networks = append([]NetworkName(nil), core.Networks...)
	expected.Services[ServiceCore] = core
	if !plan.Matches(expected) {
		t.Fatal("policy plan did not canonicalize unordered rendered collections")
	}

	invalid := validDefaultModel()
	delete(invalid.Services, ServiceNeo4j)
	if _, err := NewPolicyPlan(invalid); err == nil {
		t.Fatal("NewPolicyPlan() accepted a policy-invalid signed projection")
	}
	if (PolicyPlan{}).Valid() || (PolicyPlan{}).Matches(validDefaultModel()) {
		t.Fatal("zero policy plan became execution authority")
	}
}

func hardenedService(name ServiceName, generation string) Service {
	service := Service{
		Name:            name,
		Image:           "ghcr.io/agentmemory/" + string(name) + "@sha256:" + strings.Repeat("a", 64),
		User:            "10001:10001",
		ReadOnly:        true,
		CapDropAll:      true,
		NoNewPrivileges: true,
		Restart:         "unless-stopped",
		Networks:        []NetworkName{NetworkInternal},
		Healthcheck:     testHealthcheck(name),
		HealthTiming: HealthcheckTiming{
			Interval: 10 * time.Second, Timeout: 3 * time.Second, Retries: 5,
			StartPeriod: 30 * time.Second, StartInterval: 2 * time.Second,
		},
		StopGracePeriod: 30 * time.Second,
		Limits:          Limits{CPUsMilli: 1000, MemoryBytes: 1024 * 1024 * 1024, PIDs: 128},
		Tmpfs:           []Tmpfs{{Target: "/tmp", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777}},
		Labels:          validLabelMap(string(name), generation),
	}
	if name == ServiceNeo4j {
		service.User = "7474:7474"
		service.Tmpfs[0].Executable = true
	}
	if name == ServiceSecretProjector {
		service.User = "0:0"
		service.CapAdd = []string{"CHOWN", "DAC_READ_SEARCH"}
		service.Networks = nil
		service.NetworkDisabled = true
		service.Healthcheck = nil
		service.HealthTiming = HealthcheckTiming{}
		service.Restart = "no"
	}
	service.Environment = testEnvironment(name)
	return service
}

func testEnvironment(name ServiceName) map[string]string {
	revisions := map[string]string{
		"AM_EMBEDDING_MODEL_REVISION":  strings.Repeat("1", 40),
		"AM_RERANKING_MODEL_REVISION":  strings.Repeat("2", 40),
		"AM_EXTRACTION_MODEL_REVISION": strings.Repeat("3", 40),
		"AM_NEO4J_USERNAME":            "neo4j",
	}
	if name == ServiceCore || name == ServiceMigrate {
		return revisions
	}
	if name == ServiceNeo4j {
		return map[string]string{
			"NEO4J_client_allow__telemetry":       "false",
			"NEO4J_server_bolt_telemetry_enabled": "false",
		}
	}
	if name == ServiceSecretProjector {
		return map[string]string{}
	}
	role := map[ServiceName]string{
		ServiceLocalEmbedding: "embedding", ServiceLocalReranker: "reranking", ServiceLocalExtractor: "extraction",
	}[name]
	revision := map[ServiceName]string{
		ServiceLocalEmbedding: revisions["AM_EMBEDDING_MODEL_REVISION"],
		ServiceLocalReranker:  revisions["AM_RERANKING_MODEL_REVISION"],
		ServiceLocalExtractor: revisions["AM_EXTRACTION_MODEL_REVISION"],
	}[name]
	return map[string]string{
		"AM_PROVIDER_ROLE": role, "AM_PROVIDER_MODEL_REVISION": revision,
		"AM_PROVIDER_MODEL_SHA256": strings.Repeat("a", 64), "AM_PROVIDER_MODEL_SIZE": "1048576",
	}
}

func testHealthcheck(name ServiceName) []string {
	return map[ServiceName][]string{
		ServiceCore:           {"CMD", "/usr/local/bin/agentmemory-healthcheck"},
		ServiceNeo4j:          {"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"},
		ServiceLocalEmbedding: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalReranker:  {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		ServiceLocalExtractor: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
	}[name]
}

func testSecretMounts(service ServiceName) []Mount {
	required := requiredSecretMounts(service)
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	mounts := make([]Mount, 0, len(names))
	for _, name := range names {
		mounts = append(mounts, Mount{Kind: MountSecret, Source: name, Target: required[name], ReadOnly: true})
	}
	return mounts
}

func testSecrets(identity Identity, directory string) map[string]Secret {
	secrets := make(map[string]Secret, len(requiredDefaultSecrets))
	for _, name := range requiredDefaultSecrets {
		secrets[name] = Secret{Name: identity.StableVolumeName(name), File: directory + "/" + name}
	}
	return secrets
}

func withMount(service Service, mount Mount) Service {
	service.Mounts = append(service.Mounts, mount)
	return service
}

func validLabelMap(purpose string, generation string) map[string]string {
	return map[string]string{
		LabelInstallation: testInstallationID,
		LabelRelease:      "0.1.0",
		LabelGeneration:   generation,
		LabelPurpose:      purpose,
		LabelManaged:      "true",
	}
}
