//go:build !darwin || cgo

package dockercli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/composefile"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001GeneratedProductionSourceRoundTripsCertifiedCompose(t *testing.T) {
	if os.Getenv("AGENTMEMORY_COMPOSE_CONFORMANCE") != "1" {
		t.Skip("set AGENTMEMORY_COMPOSE_CONFORMANCE=1 in the certified Compose conformance job")
	}
	directory, _, plan, _ := validComposePolicyFixture(t)
	source, err := composefile.Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(directory, "production-compose.json")
	writePrivateTestFile(t, configuration, source)
	environment := filepath.Join(directory, "empty.env")
	writePrivateTestFile(t, environment, nil)

	render := func() []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		//nolint:gosec // G204: conformance-only executable and option grammar are fixed; variables are test-owned paths and a fixed project name.
		command := exec.CommandContext(
			ctx, "docker", "compose", "--ansi", "never", "--project-name", composePolicyProject,
			"--project-directory", directory, "--env-file", environment, "--file", configuration,
			"config", "--format", "json", "--no-env-resolution",
		)
		command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=" + os.Getenv("PATH")}
		output, commandError := command.Output()
		if commandError != nil {
			t.Fatalf("certified Compose render: %v", commandError)
		}
		return bytes.TrimSpace(output)
	}
	first := render()
	second := render()
	model, err := decodeRenderedPolicy(first, composePolicyProject)
	if err != nil || len(composeplan.NewPolicy().Validate(model)) != 0 || !plan.Matches(model) ||
		!bytes.Equal(first, second) {
		t.Fatalf("round-trip policy/error/determinism = %+v/%v/%v", composeplan.NewPolicy().Validate(model), err, bytes.Equal(first, second))
	}
}
