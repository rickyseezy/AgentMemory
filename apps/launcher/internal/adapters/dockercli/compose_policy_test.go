package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	composePolicyInstallation = "019f5f20-1234-7abc-8123-0123456789ab"
	composePolicyGeneration   = "019f5f21-5678-7def-9123-abcdef012345"
	composePolicyProject      = "agentmemory_019f5f2012347abc81230123456789ab"
)

func TestPF001RenderedComposeDecoderRejectsEveryPolicyBypass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "host network", mutate: mutateCoreService("network_mode", "host")},
		{name: "host pid", mutate: mutateCoreService("pid", "host")},
		{name: "host ipc", mutate: mutateCoreService("ipc", "host")},
		{name: "privileged", mutate: mutateCoreService("privileged", true)},
		{name: "added capability", mutate: mutateCoreService("cap_add", []any{"SYS_ADMIN"})},
		{name: "missing cap drop", mutate: mutateCoreService("cap_drop", []any{})},
		{name: "writable root", mutate: mutateCoreService("read_only", false)},
		{name: "bind mount", mutate: func(document map[string]any) {
			coreService(document)["volumes"] = append(coreService(document)["volumes"].([]any), map[string]any{
				"type": "bind", "source": "/private", "target": "/host", "read_only": true,
			})
		}},
		{name: "Docker socket", mutate: func(document map[string]any) {
			coreService(document)["volumes"] = append(coreService(document)["volumes"].([]any), map[string]any{
				"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock",
			})
		}},
		{name: "public port", mutate: func(document map[string]any) {
			coreService(document)["ports"].([]any)[0].(map[string]any)["host_ip"] = "0.0.0.0"
		}},
		{name: "external network", mutate: func(document map[string]any) {
			document["networks"].(map[string]any)["am_internal"].(map[string]any)["internal"] = false
		}},
		{name: "mutable image", mutate: mutateCoreService("image", "ghcr.io/agentmemory/core:latest")},
		{name: "missing service", mutate: func(document map[string]any) {
			delete(document["services"].(map[string]any), "local-extractor")
		}},
		{name: "missing health", mutate: func(document map[string]any) {
			delete(coreService(document), "healthcheck")
		}},
		{name: "missing dependency", mutate: func(document map[string]any) {
			delete(coreService(document)["depends_on"].(map[string]any), "neo4j")
		}},
		{name: "unknown engine field", mutate: mutateCoreService("use_api_socket", true)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory, _, plan, document := validComposePolicyFixture(t)
			test.mutate(document)
			rendered := marshalRenderedFixture(t, document)
			project := policyComposeProject(t, directory, rendered, plan)
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, err := NewCompose(testExecutorsForCompose(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			_, err = compose.VerifyConfiguration(context.Background(), project)
			if !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
				t.Fatalf("VerifyConfiguration() error = %v, want policy mismatch", err)
			}
			if len(runner.invocations) != 1 {
				t.Fatalf("policy rejection used %d Docker invocations", len(runner.invocations))
			}
		})
	}
}

func TestPF001CanonicalRenderedFixtureMatchesAuthenticatedPlan(t *testing.T) {
	t.Parallel()

	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(directory, composeplan.SecretInstallationRootKey)
	expected := validComposePolicyModel(secretFile)
	golden := marshalRenderedFixture(t, validRenderedDocument(expected))
	var wire renderedComposeDocument
	if err := decodeStrictJSON(golden, &wire); err != nil {
		t.Fatalf("strict wire decode: %v", err)
	}
	model, err := decodeRenderedPolicy(golden, composePolicyProject)
	if err != nil {
		t.Fatalf("decode canonical render: %v", err)
	}
	plan, err := composeplan.NewPolicyPlan(expected)
	if err != nil {
		t.Fatal(err)
	}
	if violations := composeplan.NewPolicy().Validate(model); len(violations) != 0 || !plan.Matches(model) {
		t.Fatalf("golden render violations=%+v matches=%v", violations, plan.Matches(model))
	}
}

func TestPF001RenderedComposeDecoderRejectsUnknownDuplicateAndUnboundedJSON(t *testing.T) {
	t.Parallel()

	directory, rendered, plan, _ := validComposePolicyFixture(t)
	duplicate := []byte(strings.Replace(string(rendered), `"name":`, `"name":"duplicate","name":`, 1))
	unknown := []byte(strings.Replace(string(rendered), `"services":`, `"x-unknown":true,"services":`, 1))
	deep := []byte(strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40))
	for _, value := range [][]byte{duplicate, unknown, deep} {
		project := policyComposeProject(t, directory, value, plan)
		runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: value}}}
		compose, _ := NewCompose(testExecutorsForCompose(t, runner))
		if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
			t.Fatalf("unsafe JSON error = %v", err)
		}
	}
}

func TestPF001ComposeRequiresSemanticEqualityWithAuthenticatedPlan(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "image digest", mutate: func(document map[string]any) {
			coreService(document)["image"] = "ghcr.io/agentmemory/core@sha256:" + strings.Repeat("b", 64)
		}},
		{name: "migration command", mutate: func(document map[string]any) {
			document["services"].(map[string]any)["migrate"].(map[string]any)["command"] = []any{"/app/agentmemory", "other"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory, _, plan, document := validComposePolicyFixture(t)
			test.mutate(document)
			substituted := marshalRenderedFixture(t, document)
			project := policyComposeProject(t, directory, substituted, plan)
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: substituted}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
				t.Fatalf("policy-valid signed-plan substitution error = %v", err)
			}
		})
	}
}

func TestPF001ComposeRechecksPolicyImmediatelyBeforeEverySideEffect(t *testing.T) {
	t.Parallel()

	for _, invoke := range []struct {
		name string
		run  func(*Compose, containerengine.ComposeProject) error
	}{
		{name: "migrations", run: func(compose *Compose, project containerengine.ComposeProject) error {
			return compose.RunMigrations(context.Background(), project)
		}},
		{name: "start", run: func(compose *Compose, project containerengine.ComposeProject) error {
			return compose.StartAndWait(context.Background(), project)
		}},
	} {
		t.Run(invoke.name, func(t *testing.T) {
			t.Parallel()
			directory, rendered, plan, document := validComposePolicyFixture(t)
			project := policyComposeProject(t, directory, rendered, plan)
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if _, err := compose.VerifyConfiguration(context.Background(), project); err != nil {
				t.Fatalf("initial verification: %v", err)
			}

			coreService(document)["privileged"] = true
			runner.outputs = append(runner.outputs, argvprocess.Result{StandardOutput: marshalRenderedFixture(t, document)})
			if err := invoke.run(compose, project); !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
				t.Fatalf("recheck error = %v", err)
			}
			if len(runner.invocations) != 2 {
				t.Fatalf("substituted render reached side effect: %d invocations", len(runner.invocations))
			}
		})
	}
}

func TestPF001ComposeRejectsConfigurationSubstitutionDuringRender(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "render-substitution")
	runner := &composeRunner{
		outputs: []argvprocess.Result{{StandardOutput: rendered}},
		afterRun: func() {
			if err := os.WriteFile(project.ConfigurationPath(), []byte("services:\n  attacker: {}\n"), 0o600); err != nil {
				t.Errorf("substitute Compose input: %v", err)
			}
		},
	}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("configuration substitution error = %v", err)
	}
}

func TestPF001ComposeRejectsSecretContentOrIdentitySubstitutionDuringRender(t *testing.T) {
	t.Parallel()

	for _, identitySwap := range []bool{false, true} {
		identitySwap := identitySwap
		t.Run(map[bool]string{false: "content", true: "identity"}[identitySwap], func(t *testing.T) {
			t.Parallel()
			project, rendered := composeFixture(t, "secret-render-substitution")
			secret := filepath.Join(project.ProjectDirectory(), executionSecretName)
			runner := &composeRunner{
				outputs: []argvprocess.Result{{StandardOutput: rendered}},
				afterRun: func() {
					if identitySwap {
						if err := os.Remove(secret); err != nil {
							t.Errorf("remove installation key: %v", err)
							return
						}
						writePrivateTestFile(t, secret, validExecutionSecretValues()[composeplan.SecretInstallationRootKey])
						return
					}
					if err := os.WriteFile(secret, []byte("substituted-key"), 0o600); err != nil {
						t.Errorf("substitute installation key: %v", err)
					}
				},
			}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
				t.Fatalf("secret substitution error = %v", err)
			}
			if len(runner.invocations) != 1 {
				t.Fatalf("secret substitution used %d Docker invocations", len(runner.invocations))
			}
		})
	}
}

func TestPF001ComposeSideEffectConsumesBoundTopologyAndSecretSnapshot(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "side-effect-binding")
	secretPath := filepath.Join(project.ProjectDirectory(), executionSecretName)
	runner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {},
	}}
	runner.beforeRun = func(_ argvprocess.Invocation) {
		if len(runner.invocations) != 2 {
			return
		}
		for path, contents := range map[string][]byte{
			project.ConfigurationPath():    []byte("services:\n  attacker: {}\n"),
			project.EmptyEnvironmentPath(): []byte("ATTACKER=value\n"),
			secretPath:                     []byte("substituted-key"),
		} {
			if err := os.Remove(path); err != nil {
				t.Errorf("remove source before substitution: %v", err)
				return
			}
			writePrivateTestFile(t, path, contents)
		}
	}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	if len(runner.invocations) != 4 {
		t.Fatalf("invocations = %d", len(runner.invocations))
	}
	sideEffect := runner.invocations[3]
	for _, forbidden := range []string{project.ConfigurationPath(), project.EmptyEnvironmentPath(), secretPath, strings.Repeat("r", 32)} {
		if strings.Contains(strings.Join(sideEffect.Arguments(), "\x00"), forbidden) ||
			bytes.Contains(sideEffect.StandardInput(), []byte(forbidden)) {
			t.Fatalf("mutable source or secret escaped into side-effect authority: %q", forbidden)
		}
	}
	boundModel, err := decodeRenderedPolicy(sideEffect.StandardInput(), project.Name())
	if err != nil || len(composeplan.NewPolicy().Validate(boundModel)) != 0 {
		t.Fatalf("bound input decode/policy = %v/%+v", err, composeplan.NewPolicy().Validate(boundModel))
	}
	boundSecret := boundModel.Secrets[composeplan.SecretInstallationKey].File
	// #nosec G304 -- the strict decoder derived this path from the adapter's bounded execution document.
	contents, err := os.ReadFile(boundSecret)
	if err != nil || !bytes.Equal(contents, validExecutionSecretValues()[composeplan.SecretInstallationRootKey]) {
		t.Fatalf("durable bound secret length/error = %d/%v", len(contents), err)
	}
}

func TestPF001PostVerificationSourceSwapCannotChangeBoundExecution(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "post-verify-source-swap")
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	verified, err := compose.verifyConfiguration(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateSnapshots(verified.secrets)
	for path, contents := range map[string][]byte{
		project.ConfigurationPath():                                    []byte("services:\n  attacker: {}\n"),
		project.EmptyEnvironmentPath():                                 []byte("ATTACKER=value\n"),
		filepath.Join(project.ProjectDirectory(), executionSecretName): []byte("substituted-key"),
	} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		writePrivateTestFile(t, path, contents)
	}
	execution, err := prepareBoundComposeExecution(
		context.Background(), project, verified.rendered.CanonicalBytes(), snapshotContents(verified.secrets),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer execution.authority.close()
	model, err := decodeRenderedPolicy(execution.configuration, project.Name())
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- strict bound model selects the adapter-owned protected materialization.
	contents, err := os.ReadFile(model.Secrets[composeplan.SecretInstallationKey].File)
	if err != nil || !bytes.Equal(contents, validExecutionSecretValues()[composeplan.SecretInstallationRootKey]) {
		t.Fatalf("post-verification binding length/error = %d/%v", len(contents), err)
	}
}

func TestPF001BoundMaterializationSwapFailsBeforeComposeSideEffect(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "bound-materialization-swap")
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	verified, err := compose.verifyConfiguration(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateSnapshots(verified.secrets)
	execution, err := prepareBoundComposeExecution(
		context.Background(), project, verified.rendered.CanonicalBytes(), snapshotContents(verified.secrets),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(execution.directory, 0o700); err != nil { //nolint:gosec // G302: owner-only directory enables the forced substitution fixture.
		execution.authority.close()
		t.Fatal(err)
	}
	secretPath := filepath.Join(execution.directory, executionSecretName)
	if err := os.Remove(secretPath); err != nil {
		execution.authority.close()
		t.Skipf("platform read lease blocked the forced substitution: %v", err)
	}
	writePrivateTestFile(t, secretPath, []byte("attacker-materialization"))
	before := len(runner.invocations)
	if err := compose.runBound(context.Background(), project, execution, []string{"run"}); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("materialization substitution error = %v", err)
	}
	if len(runner.invocations) != before {
		t.Fatalf("materialization substitution reached Docker: %d -> %d", before, len(runner.invocations))
	}
}

func TestPF001ComposeExecutionMaterializationIsNoReplaceAndContentBound(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "no-replace-binding")
	firstRunner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {},
	}}
	compose, _ := NewCompose(testExecutorsForCompose(t, firstRunner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(project.ProjectDirectory(), executionSecretName)
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, secretPath, []byte("rotated-without-new-generation"))

	secondRunner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, _ = NewCompose(testExecutorsForCompose(t, secondRunner))
	if err := compose.RunMigrations(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("content substitution error = %v", err)
	}
	if len(secondRunner.invocations) != 0 {
		t.Fatalf("content mismatch reached side effect: %d invocations", len(secondRunner.invocations))
	}
}

func TestPF001DockerComposeV514AcceptsBoundCanonicalJSONFromStdin(t *testing.T) {
	composeExecutable := os.Getenv("AGENTMEMORY_TEST_COMPOSE_EXECUTABLE")
	if composeExecutable == "" {
		for _, candidate := range []string{
			"/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
			"/usr/libexec/docker/cli-plugins/docker-compose",
			"/usr/lib/docker/cli-plugins/docker-compose",
		} {
			if info, statError := os.Stat(candidate); statError == nil && info.Mode().IsRegular() {
				composeExecutable = candidate
				break
			}
		}
	}
	if composeExecutable == "" {
		if resolved, lookError := exec.LookPath("docker-compose"); lookError == nil {
			composeExecutable = resolved
		}
	}
	if composeExecutable == "" {
		t.Skip("direct Docker Compose executable is not installed")
	}
	versionContext, cancelVersion := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelVersion()
	//nolint:gosec // G702: discovered direct Compose executable with fixed version-only argv in an opt-in compatibility test.
	versionCommand := exec.CommandContext( // #nosec G204 -- test-only explicit direct Compose executable; exact argv.
		versionContext, composeExecutable, "version", "--short",
	)
	version, err := versionCommand.Output()
	if err != nil || strings.TrimPrefix(strings.TrimSpace(string(version)), "v") != "5.1.4" {
		t.Skipf("Docker Compose v5.1.4 is required for the compatibility proof; version=%q error=%v", version, err)
	}
	project, rendered := composeFixture(t, "real-$-stdin-roundtrip")
	runner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {},
	}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	sideEffect := runner.invocations[len(runner.invocations)-1]
	arguments := sideEffect.Arguments()
	operation := -1
	for index, argument := range arguments {
		if argument == "run" {
			operation = index
			break
		}
	}
	if operation == -1 {
		t.Fatal("bound Compose operation is absent")
	}
	arguments = append(arguments[:operation], "config", "--format", "json", "--no-env-resolution")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	//nolint:gosec // G702: exact adapter-produced argv and verified direct Compose executable; no shell.
	command := exec.CommandContext(ctx, composeExecutable, arguments...) // #nosec G204 -- exact adapter-produced argv; no shell.
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(sideEffect.StandardInput())
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			t.Fatalf("real Docker Compose stdin round-trip: %v: %s", err, exitError.Stderr)
		}
		t.Fatalf("real Docker Compose stdin round-trip: %v", err)
	}
	model, err := decodeRenderedPolicy(bytes.TrimSpace(output), project.Name())
	if err != nil || len(composeplan.NewPolicy().Validate(model)) != 0 {
		t.Fatalf("round-trip decode/policy = %v/%+v", err, composeplan.NewPolicy().Validate(model))
	}
}

func validComposePolicyFixture(t *testing.T) (string, []byte, composeplan.PolicyPlan, map[string]any) {
	t.Helper()
	root := secureComposeTestRoot(t)
	directory := filepath.Join(root, "managed-compose")
	ensurePrivateTestDirectory(t, directory)
	registerExecutionMaterializationCleanup(t, directory)
	secretFile := writeValidComposePolicySecrets(t, directory)
	model := validComposePolicyModel(secretFile)
	plan, err := composeplan.NewPolicyPlan(model)
	if err != nil {
		t.Fatal(err)
	}
	document := validRenderedDocument(model)
	return directory, marshalRenderedFixture(t, document), plan, document
}

func policyComposeProject(
	t *testing.T,
	directory string,
	rendered []byte,
	plan composeplan.PolicyPlan,
) containerengine.ComposeProject {
	t.Helper()
	configuration := filepath.Join(directory, "compose.yaml")
	environment := filepath.Join(directory, "empty.env")
	writePrivateTestFile(t, configuration, []byte("services: {}\n"))
	writePrivateTestFile(t, environment, nil)
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	project, err := containerengine.NewComposeProject(
		endpoint, composePolicyProject, directory, configuration, environment,
		releaseinventory.DigestBytes(rendered), plan, 300,
	)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func validComposePolicyModel(secretFile string) composeplan.Model {
	identity, _ := composeplan.NewIdentity(composePolicyInstallation, composePolicyGeneration)
	services := make(map[composeplan.ServiceName]composeplan.Service)
	for _, name := range composeplan.RequiredDefaultServices() {
		services[name] = composeplan.Service{
			Name: name, Image: "ghcr.io/agentmemory/" + string(name) + "@sha256:" + strings.Repeat("a", 64),
			User: "10001:10001", ReadOnly: true, CapDropAll: true, NoNewPrivileges: true,
			Restart: "unless-stopped", Networks: []composeplan.NetworkName{composeplan.NetworkInternal},
			Healthcheck: composePolicyHealthcheck(name),
			HealthTiming: composeplan.HealthcheckTiming{
				Interval: 10 * time.Second, Timeout: 3 * time.Second, Retries: 5,
				StartPeriod: 30 * time.Second, StartInterval: 2 * time.Second,
			},
			StopGracePeriod: 30 * time.Second,
			Limits:          composeplan.Limits{CPUsMilli: 1000, MemoryBytes: 1024 * 1024 * 1024, PIDs: 128},
			Tmpfs:           []composeplan.Tmpfs{{Target: "/tmp", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777}},
			Environment:     composePolicyEnvironment(name),
			Labels:          composePolicyLabels(string(name), composePolicyGeneration),
		}
		if name == composeplan.ServiceNeo4j {
			service := services[name]
			service.User = "7474:7474"
			service.Tmpfs[0].Executable = true
			services[name] = service
		}
	}
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
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("protected-core"), Target: "/run/secrets", ReadOnly: true},
	}
	services[composeplan.ServiceCore] = core
	neo4j := services[composeplan.ServiceNeo4j]
	neo4j.Mounts = []composeplan.Mount{{Kind: composeplan.MountVolume, Source: identity.VolumeName("neo4j"), Target: "/data"}}
	neo4j.Mounts = append(neo4j.Mounts, composeplan.Mount{
		Kind: composeplan.MountVolume, Source: identity.VolumeName("protected-neo4j"), Target: "/run/secrets", ReadOnly: true,
	})
	services[composeplan.ServiceNeo4j] = neo4j
	for _, name := range []composeplan.ServiceName{
		composeplan.ServiceLocalEmbedding, composeplan.ServiceLocalReranker, composeplan.ServiceLocalExtractor,
	} {
		provider := services[name]
		provider.Mounts = []composeplan.Mount{{
			Kind: composeplan.MountVolume, Source: identity.StableVolumeName("models"), Target: "/models", ReadOnly: true,
		}}
		provider.Mounts = append(provider.Mounts, composeplan.Mount{
			Kind: composeplan.MountVolume, Source: identity.VolumeName(composeProjectionPurpose(name)),
			Target: "/run/secrets", ReadOnly: true,
		})
		services[name] = provider
	}
	migrate := services[composeplan.ServiceMigrate]
	migrate.Healthcheck = nil
	migrate.HealthTiming = composeplan.HealthcheckTiming{}
	migrate.Restart = "no"
	migrate.DependsOn = []composeplan.Dependency{{Service: composeplan.ServiceNeo4j, Condition: "service_healthy", Required: true}}
	migrate.Mounts = []composeplan.Mount{
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("state"), Target: "/var/lib/agentmemory/state"},
		{Kind: composeplan.MountVolume, Source: identity.VolumeName("protected-migrate"), Target: "/run/secrets", ReadOnly: true},
	}
	services[composeplan.ServiceMigrate] = migrate
	projector := services[composeplan.ServiceSecretProjector]
	projector.User = "0:0"
	projector.CapAdd = []string{"CHOWN", "DAC_READ_SEARCH"}
	projector.Networks = nil
	projector.NetworkDisabled = true
	projector.Healthcheck = nil
	projector.HealthTiming = composeplan.HealthcheckTiming{}
	projector.Restart = "no"
	projector.Environment = map[string]string{}
	for _, purpose := range composeProjectionPurposes() {
		projector.Mounts = append(projector.Mounts, composeplan.Mount{
			Kind: composeplan.MountVolume, Source: identity.VolumeName(purpose), Target: "/run/outputs/" + purpose,
		})
	}
	projector.Mounts = append(projector.Mounts, composePolicySecretMounts(composeplan.ServiceSecretProjector)...)
	services[composeplan.ServiceSecretProjector] = projector
	volumes := make(map[string]composeplan.Volume)
	for _, purpose := range []string{"state", "artifacts", "neo4j"} {
		name := identity.VolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: composePolicyLabels(purpose, composePolicyGeneration)}
	}
	for _, purpose := range []string{"journal", "models", "telemetry"} {
		name := identity.StableVolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: composePolicyLabels(purpose, "stable")}
	}
	for _, purpose := range composeProjectionPurposes() {
		name := identity.VolumeName(purpose)
		volumes[name] = composeplan.Volume{Name: name, Labels: composePolicyLabels(purpose, composePolicyGeneration)}
	}
	return composeplan.Model{
		Identity: identity, Release: "0.1.0", Services: services,
		Networks: map[composeplan.NetworkName]composeplan.Network{
			composeplan.NetworkInternal: {
				Name: identity.NetworkName("internal"), Internal: true,
				Labels: composePolicyLabels("internal", composePolicyGeneration),
			},
		},
		Volumes: volumes,
		Secrets: composePolicySecrets(identity, filepath.Dir(secretFile)),
	}
}

func composePolicyHealthcheck(name composeplan.ServiceName) []string {
	return map[composeplan.ServiceName][]string{
		composeplan.ServiceCore:           {"CMD", "/usr/local/bin/agentmemory-healthcheck"},
		composeplan.ServiceNeo4j:          {"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"},
		composeplan.ServiceLocalEmbedding: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		composeplan.ServiceLocalReranker:  {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
		composeplan.ServiceLocalExtractor: {"CMD", "/usr/local/bin/agentmemory-provider", "healthcheck"},
	}[name]
}

func composePolicyEnvironment(name composeplan.ServiceName) map[string]string {
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
	if name == composeplan.ServiceSecretProjector {
		return map[string]string{}
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

func composePolicySecretMounts(service composeplan.ServiceName) []composeplan.Mount {
	names := map[composeplan.ServiceName][]string{
		composeplan.ServiceSecretProjector: {
			composeplan.SecretInstallationRootKey, composeplan.SecretAPICredential,
			composeplan.SecretAttestationHMACKey, composeplan.SecretNeo4jPassword,
			composeplan.SecretEmbeddingCapability, composeplan.SecretRerankingCapability,
			composeplan.SecretExtractionCapability, composeplan.SecretEgressAttestation,
		},
	}[service]
	mounts := make([]composeplan.Mount, 0, len(names))
	for _, name := range names {
		target := "/run/inputs/" + name
		mounts = append(mounts, composeplan.Mount{Kind: composeplan.MountSecret, Source: name, Target: target, ReadOnly: true})
	}
	return mounts
}

func composeProjectionPurposes() []string {
	return []string{
		"protected-core", "protected-migrate", "protected-neo4j",
		"protected-embedding", "protected-reranking", "protected-extraction",
	}
}

func composeProjectionPurpose(service composeplan.ServiceName) string {
	return map[composeplan.ServiceName]string{
		composeplan.ServiceCore: "protected-core", composeplan.ServiceMigrate: "protected-migrate",
		composeplan.ServiceNeo4j: "protected-neo4j", composeplan.ServiceLocalEmbedding: "protected-embedding",
		composeplan.ServiceLocalReranker: "protected-reranking", composeplan.ServiceLocalExtractor: "protected-extraction",
	}[service]
}

func composePolicySecrets(identity composeplan.Identity, directory string) map[string]composeplan.Secret {
	secrets := make(map[string]composeplan.Secret)
	for name := range validExecutionSecretValues() {
		secrets[name] = composeplan.Secret{Name: identity.StableVolumeName(name), File: filepath.Join(directory, name)}
	}
	return secrets
}

func validRenderedDocument(model composeplan.Model) map[string]any {
	services := make(map[string]any, len(model.Services))
	logicalVolumes := map[string]string{
		model.Identity.VolumeName("state"):           "state",
		model.Identity.VolumeName("artifacts"):       "artifacts",
		model.Identity.VolumeName("neo4j"):           "neo4j",
		model.Identity.StableVolumeName("journal"):   "journal",
		model.Identity.StableVolumeName("models"):    "models",
		model.Identity.StableVolumeName("telemetry"): "telemetry",
	}
	for _, purpose := range composeProjectionPurposes() {
		logicalVolumes[model.Identity.VolumeName(purpose)] = purpose
	}
	for name, expected := range model.Services {
		mounts := make([]any, 0)
		secrets := make([]any, 0)
		for _, mount := range expected.Mounts {
			if mount.Kind == composeplan.MountSecret {
				secrets = append(secrets, map[string]any{
					"source": mount.Source, "target": mount.Target,
					"uid": "", "gid": "",
				})
				continue
			}
			mounts = append(mounts, map[string]any{
				"type": "volume", "source": logicalVolumes[mount.Source], "target": mount.Target,
				"read_only": mount.ReadOnly,
			})
		}
		dependencies := make(map[string]any)
		for _, dependency := range expected.DependsOn {
			dependencies[string(dependency.Service)] = map[string]any{
				"condition": dependency.Condition, "restart": dependency.Restart, "required": dependency.Required,
			}
		}
		ports := make([]any, 0, len(expected.Ports))
		for _, port := range expected.Ports {
			ports = append(ports, map[string]any{
				"host_ip": port.HostIP, "target": port.ContainerPort, "published": "9411",
				"protocol": "tcp", "mode": "ingress",
			})
		}
		tmpfs := []any{"/tmp:mode=1023,size=67108864"}
		if expected.Tmpfs[0].Executable {
			tmpfs[0] = "/tmp:mode=1023,size=67108864,exec"
		}
		renderedService := map[string]any{
			"command": expected.Command, "entrypoint": nil, "image": expected.Image, "user": expected.User,
			"read_only": expected.ReadOnly, "cap_drop": []any{"ALL"}, "cap_add": expected.CapAdd,
			"security_opt": []any{"no-new-privileges:true"}, "restart": expected.Restart,
			"stop_grace_period": "30s",
			"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
				"cpus": 1, "memory": "1073741824", "pids": 128,
			}}, "placement": map[string]any{}},
			"tmpfs": tmpfs, "ports": ports, "volumes": mounts,
			"secrets": secrets, "environment": expected.Environment,
			"labels": expected.Labels, "depends_on": dependencies,
		}
		if expected.NetworkDisabled {
			renderedService["network_mode"] = "none"
			renderedService["networks"] = map[string]any{}
		} else {
			renderedService["networks"] = map[string]any{"am_internal": nil}
		}
		if len(expected.Healthcheck) != 0 {
			renderedService["healthcheck"] = map[string]any{
				"test": expected.Healthcheck, "interval": "10s", "timeout": "3s", "retries": 5,
				"start_period": "30s", "start_interval": "2s",
			}
		}
		services[string(name)] = renderedService
	}
	volumes := make(map[string]any, len(model.Volumes))
	for physical, volume := range model.Volumes {
		volumes[logicalVolumes[physical]] = map[string]any{"name": volume.Name, "labels": volume.Labels}
	}
	renderedSecrets := make(map[string]any, len(model.Secrets))
	for name, secret := range model.Secrets {
		renderedSecrets[name] = map[string]any{"name": secret.Name, "file": secret.File}
	}
	return map[string]any{
		"name": composePolicyProject, "services": services,
		"networks": map[string]any{
			"am_internal": map[string]any{
				"name":     model.Networks[composeplan.NetworkInternal].Name,
				"internal": true, "labels": model.Networks[composeplan.NetworkInternal].Labels,
			},
		},
		"volumes": volumes,
		"secrets": renderedSecrets,
	}
}

func composePolicyLabels(purpose string, generation string) map[string]string {
	return map[string]string{
		composeplan.LabelInstallation: composePolicyInstallation,
		composeplan.LabelRelease:      "0.1.0",
		composeplan.LabelGeneration:   generation,
		composeplan.LabelPurpose:      purpose,
		composeplan.LabelManaged:      "true",
	}
}

func mutateCoreService(key string, value any) func(map[string]any) {
	return func(document map[string]any) { coreService(document)[key] = value }
}

func coreService(document map[string]any) map[string]any {
	return document["services"].(map[string]any)["core"].(map[string]any)
}

func marshalRenderedFixture(t *testing.T, document map[string]any) []byte {
	t.Helper()
	rendered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func validExecutionSecretValues() map[string][]byte {
	return map[string][]byte{
		composeplan.SecretInstallationRootKey:  bytes.Repeat([]byte("r"), 32),
		composeplan.SecretAPICredential:        bytes.Repeat([]byte("a"), 32),
		composeplan.SecretAttestationHMACKey:   bytes.Repeat([]byte("h"), 32),
		composeplan.SecretNeo4jPassword:        bytes.Repeat([]byte("n"), 32),
		composeplan.SecretEmbeddingCapability:  bytes.Repeat([]byte("e"), 32),
		composeplan.SecretRerankingCapability:  bytes.Repeat([]byte("k"), 32),
		composeplan.SecretExtractionCapability: bytes.Repeat([]byte("x"), 32),
		composeplan.SecretEgressAttestation:    []byte(`{"version":1,"egress_enabled":false}`),
	}
}

func writeValidComposePolicySecrets(t *testing.T, directory string) string {
	t.Helper()
	for name, value := range validExecutionSecretValues() {
		writePrivateTestFile(t, filepath.Join(directory, name), value)
	}
	return filepath.Join(directory, composeplan.SecretInstallationRootKey)
}
