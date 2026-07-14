//go:build darwin || linux

package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

const secretReaderImage = "alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"

func TestPF001ExecutionSecretIsHostIsolatedAndReadableByContainerUID10001(t *testing.T) {
	endpointValue := os.Getenv("AGENTMEMORY_TEST_DOCKER_ENDPOINT")
	if endpointValue == "" {
		t.Skip("set AGENTMEMORY_TEST_DOCKER_ENDPOINT to run the explicit local-Docker secret integration")
	}
	endpoint, err := containerengine.NewEndpoint(endpointValue)
	if err != nil {
		t.Fatalf("invalid test Docker endpoint: %v", err)
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker CLI is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G702: opt-in integration uses a resolved Docker CLI, validated local endpoint, and fixed pinned image argv.
	inspect := exec.CommandContext(ctx, docker, "--host", endpoint.String(), "image", "inspect", secretReaderImage) // #nosec G204 -- validated local endpoint and exact pinned test image.
	inspect.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := inspect.Run(); err != nil {
		t.Skipf("pinned secret-reader image is not installed: %v", err)
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directoryPath := filepath.Join(root, "generation")
	if err := createPrivateExecutionDirectory(ctx, directoryPath); err != nil {
		t.Fatal(err)
	}
	directory, err := openPrivateExecutionDirectory(ctx, directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	secretValue := []byte("container-readable-non-production-test-value")
	secretPath := filepath.Join(directoryPath, executionSecretName)
	secret, err := ensureExecutionFile(
		ctx, directory, executionSecretName, secretPath, secretValue, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secret.Close() }()
	environmentPath := filepath.Join(directoryPath, executionEnvironmentName)
	environment, err := ensureExecutionFile(
		ctx, directory, executionEnvironmentName, environmentPath, nil, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = environment.Close() }()
	if err := sealExecutionDirectory(directory); err != nil || syncExecutionDirectory(directory) != nil {
		t.Fatalf("seal execution directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(directoryPath, 0o700) //nolint:gosec // G302: owner-only directory cleanup mode.
	})

	directoryInfo, err := directory.Stat()
	if err != nil {
		t.Fatal(err)
	}
	secretInfo, err := secret.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o500 || secretInfo.Mode().Perm() != 0o400 ||
		directoryInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("host isolation modes directory/secret = %04o/%04o", directoryInfo.Mode().Perm(), secretInfo.Mode().Perm())
	}

	document := map[string]any{
		"services": map[string]any{
			"reader": map[string]any{
				"image":        secretReaderImage,
				"user":         "10001:10001",
				"read_only":    true,
				"network_mode": "none",
				"cap_drop":     []string{"ALL"},
				"security_opt": []string{"no-new-privileges:true"},
				"command":      []string{"/bin/cat", "/run/secrets/installation-key"},
				"secrets": []map[string]string{{
					"source": "installation-key",
					"target": "installation-key",
					"mode":   "0400",
				}},
			},
		},
		"secrets": map[string]any{
			"installation-key": map[string]string{"file": secretPath},
		},
	}
	configuration, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	projectName := "agentmemory_secret_test_" + strconv.Itoa(os.Getpid())
	//nolint:gosec // G702: opt-in integration uses exact argv, validated local endpoint, and pinned image.
	command := exec.CommandContext( // #nosec G204 -- exact argv, validated local endpoint, pinned image, and isolated test paths.
		ctx,
		docker,
		"--host", endpoint.String(),
		"compose",
		"--ansi", "never",
		"--progress", "quiet",
		"--project-name", projectName,
		"--project-directory", directoryPath,
		"--env-file", environmentPath,
		"--file", "-",
		"run",
		"--rm",
		"--no-deps",
		"--pull", "never",
		"--no-TTY",
		"--interactive=false",
		"reader",
	)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(configuration)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			t.Fatalf("UID 10001 secret reader failed (stderr bytes=%d)", len(exitError.Stderr))
		}
		t.Fatalf("UID 10001 secret reader failed: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(output), secretValue) {
		t.Fatalf("UID 10001 read unexpected secret bytes (length=%d)", len(output))
	}
}
