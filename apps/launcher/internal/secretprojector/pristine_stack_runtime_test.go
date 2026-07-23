//go:build darwin || linux

package secretprojector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

// TestPF001PristineStackStartsNeo4jBeforeCommunityMigrations is an opt-in live
// proof over empty named volumes. It deliberately uses the production
// projector, Neo4j, and migrate images and the same command ordering as the
// release-bound Compose adapter. Image build/signature verification belongs to
// the release pipeline; this test refuses to pull or build anything.
func TestPF001PristineStackStartsNeo4jBeforeCommunityMigrations(t *testing.T) {
	endpoint := os.Getenv("AGENTMEMORY_TEST_DOCKER_ENDPOINT")
	projectorImage := os.Getenv("AGENTMEMORY_SECRET_PROJECTOR_IMAGE")
	neo4jImage := os.Getenv("AGENTMEMORY_TEST_NEO4J_IMAGE")
	migrateImage := os.Getenv("AGENTMEMORY_TEST_MIGRATE_IMAGE")
	if endpoint == "" || projectorImage == "" || neo4jImage == "" || migrateImage == "" {
		t.Skip("set the Docker endpoint and projector, Neo4j, and migrate image variables for the pristine-stack proof")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker CLI is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	for _, image := range []string{projectorImage, neo4jImage, migrateImage} {
		command := exec.CommandContext(ctx, docker, "--host", endpoint, "image", "inspect", "--", image) // #nosec G204,G702 -- explicit opt-in local Docker integration.
		command.Env = projectionTestEnvironment()
		if err := command.Run(); err != nil {
			t.Skipf("required local production image is not installed: %s", image)
		}
	}

	directory := t.TempDir()
	values := pristineProtectedValues(t)
	for name, value := range values {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, value, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	emptyEnvironment := filepath.Join(directory, "empty.env")
	if err := os.WriteFile(emptyEnvironment, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	suffixBytes := make([]byte, 4)
	if _, err := rand.Read(suffixBytes); err != nil {
		t.Fatal(err)
	}
	projectName := "agentmemory_pristine_test_" + strconv.Itoa(os.Getpid()) + "_" + hex.EncodeToString(suffixBytes)
	physicalVolumes := make(map[string]string, 8)
	for _, volume := range defaultContract() {
		physicalVolumes[volume.purpose] = projectName + "_" + strings.ReplaceAll(volume.purpose, "-", "_")
	}
	physicalVolumes["neo4j-data"] = projectName + "_neo4j_data"
	physicalVolumes["state"] = projectName + "_state"

	document := pristineMigrationComposeDocument(
		projectorImage, neo4jImage, migrateImage, directory, projectName, physicalVolumes,
	)
	configuration, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = runPristineCompose(
			cleanupContext, docker, endpoint, projectName, directory, emptyEnvironment, configuration,
			"down", "--volumes", "--remove-orphans", "--timeout", "30",
		)
		for _, name := range physicalVolumes {
			command := exec.CommandContext(cleanupContext, docker, "--host", endpoint, "volume", "rm", "--force", "--", name) // #nosec G204,G702 -- generated closed test volume identity.
			command.Env = projectionTestEnvironment()
			_ = command.Run()
		}
	})

	output, err := runPristineCompose(
		ctx, docker, endpoint, projectName, directory, emptyEnvironment, configuration,
		"run", "--rm", "--no-deps", "--pull", "never", "--no-TTY", "--interactive=false",
		string(composeplan.ServiceSecretProjector),
	)
	if err != nil || string(output) != "ok\n" {
		t.Fatalf("pristine projection failed: output=%q error=%v", output, safePristineError(err))
	}
	if _, err := runPristineCompose(
		ctx, docker, endpoint, projectName, directory, emptyEnvironment, configuration,
		"up", "--detach", "--wait", "--wait-timeout", "180", "--pull", "never", "--no-build", "neo4j",
	); err != nil {
		t.Fatalf("pristine Neo4j startup failed: %v", safePristineError(err))
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := runPristineCompose(
			ctx, docker, endpoint, projectName, directory, emptyEnvironment, configuration,
			"run", "--rm", "--no-deps", "--pull", "never", "--no-TTY", "--interactive=false", "migrate",
		); err != nil {
			t.Fatalf("pristine migration attempt %d failed: %v", attempt, safePristineError(err))
		}
	}

	verify := exec.CommandContext( // #nosec G204,G702 -- fixed Python verifier, explicit local image, and generated test volume.
		ctx, docker, "--host", endpoint, "run", "--rm", "--pull", "never", "--network", "none",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", "10001:10001", "--mount",
		"type=volume,source="+physicalVolumes["state"]+",target=/var/lib/agentmemory/state,readonly",
		"--entrypoint", "python", migrateImage, "-c",
		"import sqlite3; c=sqlite3.connect('file:/var/lib/agentmemory/state/agentmemory.sqlite3?mode=ro&immutable=1',uri=True); print(c.execute('select version_num from alembic_version').fetchone()[0])",
	)
	verify.Env = projectionTestEnvironment()
	head, err := verify.Output()
	if err != nil || string(head) != "0038_pro005_provider_routing\n" {
		t.Fatalf("pristine relational migration head = %q/%v", head, safePristineError(err))
	}
}

func pristineProtectedValues(t *testing.T) map[string][]byte {
	t.Helper()
	values := make(map[string][]byte, 8)
	for name := range valuesForProjectionDocument() {
		if name == composeplan.SecretEgressAttestation {
			values[name] = []byte(`{"version":1,"egress_enabled":false}`)
			continue
		}
		value := make([]byte, exactCryptographicSecretBytes)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		values[name] = value
	}
	return values
}

func pristineMigrationComposeDocument(
	projectorImage string,
	neo4jImage string,
	migrateImage string,
	directory string,
	projectName string,
	physical map[string]string,
) map[string]any {
	document := projectionComposeDocument(projectorImage, directory, physical)
	volumes := document["volumes"].(map[string]any)
	volumes["neo4j-data"] = map[string]any{"name": physical["neo4j-data"]}
	volumes["state"] = map[string]any{"name": physical["state"]}
	services := document["services"].(map[string]any)
	services["neo4j"] = map[string]any{
		"image": neo4jImage, "user": "7474:7474", "read_only": true,
		"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"restart": "no", "pull_policy": "never", "networks": []string{"am_internal"},
		"environment": map[string]string{
			"NEO4J_client_allow__telemetry": "false", "NEO4J_server_bolt_telemetry_enabled": "false",
		},
		"tmpfs": []string{
			"/tmp:size=67108864,mode=01777,exec", "/logs:size=67108864,mode=01777",
			"/var/lib/neo4j/run:size=16777216,mode=01777",
		},
		"volumes": []map[string]any{
			{"type": "volume", "source": "neo4j-data", "target": "/data"},
			{"type": "volume", "source": purposeNeo4j, "target": "/run/secrets", "read_only": true},
		},
		"healthcheck": map[string]any{
			"test": []string{"CMD", "/opt/agentmemory/bin/neo4j-healthcheck"}, "interval": "3s",
			"timeout": "5s", "retries": 50, "start_period": "10s", "start_interval": "1s",
		},
	}
	revision := strings.Repeat("a", 40)
	services["migrate"] = map[string]any{
		"image": migrateImage, "user": "10001:10001", "read_only": true,
		"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"restart": "no", "pull_policy": "never", "networks": []string{"am_internal"},
		"environment": map[string]string{
			"AM_NEO4J_USERNAME": "neo4j", "AM_EMBEDDING_MODEL_REVISION": revision,
			"AM_RERANKING_MODEL_REVISION": revision, "AM_EXTRACTION_MODEL_REVISION": revision,
		},
		"tmpfs": []string{"/tmp:size=67108864,mode=01777"},
		"volumes": []map[string]any{
			{"type": "volume", "source": "state", "target": "/var/lib/agentmemory/state"},
			{"type": "volume", "source": purposeMigrate, "target": "/run/secrets", "read_only": true},
		},
		"depends_on": map[string]any{
			"neo4j": map[string]any{"condition": "service_healthy", "required": true, "restart": false},
		},
	}
	document["networks"] = map[string]any{
		"am_internal": map[string]any{"name": projectName + "_internal", "internal": true},
	}
	return document
}

func runPristineCompose(
	ctx context.Context,
	docker string,
	endpoint string,
	projectName string,
	directory string,
	emptyEnvironment string,
	configuration []byte,
	operation ...string,
) ([]byte, error) {
	arguments := make([]string, 0, 15+len(operation))
	arguments = append(arguments,
		"--host", endpoint, "compose", "--ansi", "never", "--progress", "quiet",
		"--project-name", projectName, "--project-directory", directory,
		"--env-file", emptyEnvironment, "--file", "-",
	)
	arguments = append(arguments, operation...)
	command := exec.CommandContext(ctx, docker, arguments...) // #nosec G204,G702 -- closed test operation and explicit opt-in local Docker authority.
	command.Env = projectionTestEnvironment()
	command.Stdin = bytes.NewReader(configuration)
	return command.Output()
}

func safePristineError(err error) error {
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return err
	}
	stderr := exitError.Stderr
	if len(stderr) > 2048 {
		stderr = stderr[:2048]
	}
	return errors.New("docker operation failed with bounded diagnostics: " + strconv.Quote(string(stderr)))
}
