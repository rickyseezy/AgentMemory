//go:build darwin || linux

package secretprojector

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

const projectionVerifierImage = "alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"

func TestPF001CertifiedComposeProjectsProtectedVolumesForExactConsumerIdentity(t *testing.T) {
	endpoint := os.Getenv("AGENTMEMORY_TEST_DOCKER_ENDPOINT")
	image := os.Getenv("AGENTMEMORY_SECRET_PROJECTOR_IMAGE")
	if endpoint == "" || image == "" {
		t.Skip("set AGENTMEMORY_TEST_DOCKER_ENDPOINT and AGENTMEMORY_SECRET_PROJECTOR_IMAGE for the active projection proof")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker CLI is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, requiredImage := range []string{image, projectionVerifierImage} {
		command := exec.CommandContext(ctx, docker, "--host", endpoint, "image", "inspect", "--", requiredImage) // #nosec G204,G702 -- explicit opt-in local Docker integration.
		command.Env = projectionTestEnvironment()
		if err := command.Run(); err != nil {
			t.Skipf("required pinned/local test image is not installed: %s", requiredImage)
		}
	}

	directory := t.TempDir()
	values := make(map[string][]byte, 8)
	for _, name := range []string{
		composeplan.SecretInstallationRootKey, composeplan.SecretAPICredential,
		composeplan.SecretAttestationHMACKey, composeplan.SecretNeo4jPassword,
		composeplan.SecretEmbeddingCapability, composeplan.SecretRerankingCapability,
		composeplan.SecretExtractionCapability,
	} {
		value := make([]byte, exactCryptographicSecretBytes)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		values[name] = value
	}
	values[composeplan.SecretEgressAttestation] = []byte(`{"version":1,"egress_enabled":false}`)
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
	suffix := strconv.Itoa(os.Getpid()) + "_" + hex.EncodeToString(suffixBytes)
	projectName := "agentmemory_projection_test_" + suffix
	physicalVolumes := make(map[string]string, 6)
	for _, volume := range defaultContract() {
		physicalVolumes[volume.purpose] = projectName + "_" + strings.ReplaceAll(volume.purpose, "-", "_")
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		for _, name := range physicalVolumes {
			command := exec.CommandContext(cleanupContext, docker, "--host", endpoint, "volume", "rm", "--force", "--", name) // #nosec G204,G702 -- generated closed test volume identity.
			command.Env = projectionTestEnvironment()
			_ = command.Run()
		}
	})

	document := projectionComposeDocument(image, directory, physicalVolumes)
	configuration, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext( // #nosec G204,G702 -- exact opt-in local Compose invocation with generated owner-only paths.
		ctx, docker, "--host", endpoint, "compose", "--ansi", "never", "--progress", "quiet",
		"--project-name", projectName, "--project-directory", directory, "--env-file", emptyEnvironment,
		"--file", "-", "run", "--rm", "--no-deps", "--pull", "never", "--no-TTY",
		"--interactive=false", string(composeplan.ServiceSecretProjector),
	)
	command.Env = projectionTestEnvironment()
	command.Stdin = bytes.NewReader(configuration)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			diagnostic := string(exitError.Stderr)
			for source, replacement := range map[string]string{
				directory: "<directory>", image: "<image>", endpoint: "<endpoint>", projectName: "<project>",
			} {
				diagnostic = strings.ReplaceAll(diagnostic, source, replacement)
			}
			if len(diagnostic) > 2048 {
				diagnostic = diagnostic[:2048]
			}
			t.Fatalf("secret projector failed: %q", diagnostic)
		}
		t.Fatal(err)
	}
	if string(output) != "ok\n" {
		t.Fatalf("projector receipt = %q", output)
	}

	coreSecret := composeplan.SecretInstallationRootKey
	coreDigest := sha256.Sum256(values[coreSecret])
	verifyProjectedConsumer(
		ctx, t, docker, endpoint, physicalVolumes[purposeCore], "10001:10001",
		coreSecret, hex.EncodeToString(coreDigest[:]),
	)
	neoDigest := sha256.Sum256(values[composeplan.SecretNeo4jPassword])
	verifyProjectedConsumer(
		ctx, t, docker, endpoint, physicalVolumes[purposeNeo4j], "7474:7474",
		composeplan.SecretNeo4jPassword, hex.EncodeToString(neoDigest[:]),
	)
}

func projectionComposeDocument(image string, directory string, physical map[string]string) map[string]any {
	volumes := make(map[string]any, len(physical))
	serviceVolumes := make([]any, 0, len(physical))
	for _, contract := range defaultContract() {
		volumes[contract.purpose] = map[string]any{"name": physical[contract.purpose]}
		serviceVolumes = append(serviceVolumes, map[string]any{
			"type": "volume", "source": contract.purpose,
			"target": outputPath(contract.purpose), "read_only": false,
		})
	}
	secrets := make(map[string]any, 8)
	serviceSecrets := make([]any, 0, 8)
	for name := range valuesForProjectionDocument() {
		secrets[name] = map[string]any{"file": filepath.Join(directory, name)}
		serviceSecrets = append(serviceSecrets, map[string]any{
			"source": name, "target": inputPath(name),
		})
	}
	return map[string]any{
		"services": map[string]any{
			string(composeplan.ServiceSecretProjector): map[string]any{
				"image": image, "user": "0:0", "read_only": true,
				"cap_drop": []string{"ALL"}, "cap_add": []string{"CHOWN", "DAC_READ_SEARCH"},
				"security_opt": []string{"no-new-privileges:true"}, "network_mode": "none",
				"restart": "no", "pull_policy": "never", "environment": map[string]string{},
				"tmpfs":   []string{"/tmp:size=16777216,mode=01777"},
				"volumes": serviceVolumes, "secrets": serviceSecrets,
			},
		},
		"volumes": volumes, "secrets": secrets,
	}
}

func valuesForProjectionDocument() map[string]struct{} {
	values := make(map[string]struct{}, 8)
	for _, volume := range defaultContract() {
		for _, file := range volume.files {
			values[file.name] = struct{}{}
		}
	}
	return values
}

func verifyProjectedConsumer(
	ctx context.Context,
	t *testing.T,
	docker string,
	endpoint string,
	volume string,
	user string,
	fileName string,
	expectedDigest string,
) {
	t.Helper()
	script := `set -eu; file="/run/secrets/$1"; ` +
		`test "$(stat -c '%u:%g:%a:%h:%s' "$file")" = "$2:400:1:32"; ` +
		`test "$(sha256sum "$file" | cut -d ' ' -f 1)" = "$3"; ` +
		`! (printf x >> "$file") 2>/dev/null; printf 'ok\n'`
	command := exec.CommandContext( // #nosec G204,G702 -- exact pinned test image, local endpoint, generated test volume, and closed argv.
		ctx, docker, "--host", endpoint, "run", "--rm", "--pull", "never", "--network", "none",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", user,
		"--mount", "type=volume,source="+volume+",target=/run/secrets,readonly",
		projectionVerifierImage, "/bin/sh", "-c", script, "projection-verifier", fileName, user, expectedDigest,
	)
	command.Env = projectionTestEnvironment()
	output, err := command.Output()
	if err != nil || string(output) != "ok\n" {
		t.Fatalf("projected consumer verification failed: output=%q error=%v", output, err)
	}
}

func projectionTestEnvironment() []string {
	return []string{"LANG=C", "LC_ALL=C", "PATH=" + os.Getenv("PATH")}
}
