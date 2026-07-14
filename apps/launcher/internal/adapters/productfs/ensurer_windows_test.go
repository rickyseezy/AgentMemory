//go:build windows

package productfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001WindowsProductFilesystemCreatesProtectedIdempotentState(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(home, ".agentmemory-product-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fixture) })
	root := filepath.Join(fixture, "AgentMemory")
	ensurer := NewEnsurer()
	directories := windowsDirectoryCommand(t, root)
	first, err := ensurer.EnsureDirectories(context.Background(), directories)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ensurer.EnsureDirectories(context.Background(), directories)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ValidFor(directories) || first.Created() != 6 || first.Reused() != 0 ||
		!second.ValidFor(directories) || second.Created() != 0 || second.Reused() != 6 ||
		!first.OutputDigest().Equal(second.OutputDigest()) {
		t.Fatal("Windows directory layout was not protected and idempotent")
	}
	secrets := windowsSecretCommand(t, root)
	secretFirst, err := ensurer.EnsureSecrets(context.Background(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	secretSecond, err := ensurer.EnsureSecrets(context.Background(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	if !secretFirst.ValidFor(secrets) || secretFirst.Created() != 7 || secretFirst.Reused() != 0 ||
		!secretSecond.ValidFor(secrets) || secretSecond.Created() != 0 || secretSecond.Reused() != 7 ||
		!secretFirst.OutputDigest().Equal(secretSecond.OutputDigest()) {
		t.Fatal("Windows secret materialization rotated or lost its binding")
	}
	seen := make(map[string]struct{}, 7)
	for _, specification := range secrets.Secrets() {
		raw, readError := os.ReadFile(specification.Path())
		if readError != nil || len(raw) != 32 {
			t.Fatalf("Windows secret %s is not exactly 256 bits", specification.Purpose())
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			t.Fatal("Windows key purposes reused random material")
		}
		seen[string(raw)] = struct{}{}
		clear(raw)
	}
}

func TestPF001WindowsProductFilesystemRejectsInheritedDirectoryAndCancellation(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "InheritedAgentMemory")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := NewEnsurer().EnsureDirectories(context.Background(), windowsDirectoryCommand(t, root))
	if !errors.Is(err, productinstall.ErrIntegrity) {
		t.Fatalf("inherited Windows DACL error = %v, want integrity", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewEnsurer().EnsureDirectories(cancelled, windowsDirectoryCommand(t, filepath.Join(t.TempDir(), "Cancelled")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Windows directory error = %v", err)
	}
}

func windowsDirectoryCommand(t testing.TB, root string) productinstall.DirectoryCommand {
	t.Helper()
	operationID, planDigest := windowsBindings(t)
	inputs := []struct {
		purpose productinstall.DirectoryPurpose
		path    string
	}{
		{productinstall.DirectoryRelease, filepath.Join(root, "releases", "v1")},
		{productinstall.DirectoryConfiguration, filepath.Join(root, "config")},
		{productinstall.DirectoryRuntime, filepath.Join(root, "runtime")},
		{productinstall.DirectorySecrets, filepath.Join(root, "secrets")},
		{productinstall.DirectoryBackups, filepath.Join(root, "backups")},
		{productinstall.DirectoryComposeProject, filepath.Join(root, "releases", "v1", "compose")},
	}
	specifications := make([]productinstall.DirectorySpec, 0, len(inputs))
	for _, input := range inputs {
		specification, err := productinstall.NewDirectorySpec(input.purpose, input.path)
		if err != nil {
			t.Fatal(err)
		}
		specifications = append(specifications, specification)
	}
	command, err := productinstall.NewDirectoryCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory, specifications,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func windowsSecretCommand(t testing.TB, root string) productinstall.SecretCommand {
	t.Helper()
	operationID, planDigest := windowsBindings(t)
	secretRoot := filepath.Join(root, "secrets")
	purposes := []installplan.SecretPurpose{
		installplan.SecretInstallationRootKey,
		installplan.SecretAPICredential,
		installplan.SecretAttestationHMACKey,
		installplan.SecretNeo4jPassword,
		installplan.SecretEmbeddingCapability,
		installplan.SecretRerankerCapability,
		installplan.SecretExtractorCapability,
	}
	specifications := make([]productinstall.SecretSpec, 0, len(purposes))
	for _, purpose := range purposes {
		specification, err := productinstall.NewSecretSpec(purpose, filepath.Join(secretRoot, string(purpose)))
		if err != nil {
			t.Fatal(err)
		}
		specifications = append(specifications, specification)
	}
	command, err := productinstall.NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory, secretRoot, specifications,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func windowsBindings(t testing.TB) (install.OperationID, install.PlanDigest) {
	t.Helper()
	operationID, err := install.NewOperationID("pf001-windows-productfs")
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := install.BindPlan([]byte("canonical-windows-productfs-plan"))
	if err != nil {
		t.Fatal(err)
	}
	return operationID, planDigest
}
