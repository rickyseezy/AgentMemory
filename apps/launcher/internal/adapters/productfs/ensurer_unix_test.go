//go:build darwin || linux

package productfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001NativeProductFilesystemCreatesAndReverifiesExactLayout(t *testing.T) {
	t.Parallel()
	root := unixTestRoot(t)
	directoryCommand := unixDirectoryCommand(t, root)
	ensurer := NewEnsurer()
	first, err := ensurer.EnsureDirectories(context.Background(), directoryCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ValidFor(directoryCommand) || first.Created() != 6 || first.Reused() != 0 {
		t.Fatalf("first directory pass created/reused = %d/%d", first.Created(), first.Reused())
	}
	second, err := ensurer.EnsureDirectories(context.Background(), directoryCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ValidFor(directoryCommand) || second.Created() != 0 || second.Reused() != 6 ||
		!second.OutputDigest().Equal(first.OutputDigest()) {
		t.Fatal("directory replay was not idempotent and identity-stable")
	}
	for _, specification := range directoryCommand.Directories() {
		info, statError := os.Stat(specification.Path())
		if statError != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s is not owner-only", specification.Purpose())
		}
	}

	secretCommand := unixSecretCommand(t, root)
	secretFirst, err := ensurer.EnsureSecrets(context.Background(), secretCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !secretFirst.ValidFor(secretCommand) || secretFirst.Created() != 7 || secretFirst.Reused() != 0 {
		t.Fatal("first secret pass did not create every purpose-separated value")
	}
	seen := make(map[string]struct{}, 7)
	for _, specification := range secretCommand.Secrets() {
		raw, readError := os.ReadFile(specification.Path())
		if readError != nil || len(raw) != 32 {
			t.Fatalf("secret %s does not contain exactly 256 bits", specification.Purpose())
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			t.Fatal("two key purposes received the same random value")
		}
		seen[string(raw)] = struct{}{}
		info, statError := os.Stat(specification.Path())
		if statError != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			t.Fatalf("secret %s is not a read-only owner file", specification.Purpose())
		}
		clear(raw)
	}
	secretSecond, err := ensurer.EnsureSecrets(context.Background(), secretCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !secretSecond.ValidFor(secretCommand) || secretSecond.Created() != 0 || secretSecond.Reused() != 7 ||
		!secretSecond.OutputDigest().Equal(secretFirst.OutputDigest()) {
		t.Fatal("secret replay rotated keys or changed its HMAC state attestation")
	}
}

func TestPF001NativeProductFilesystemRejectsSymlinkAndWeakSecretState(t *testing.T) {
	t.Parallel()
	t.Run("directory symlink", func(t *testing.T) {
		root := unixTestRoot(t)
		command := unixDirectoryCommand(t, root)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "config")); err != nil {
			t.Fatal(err)
		}
		_, err := NewEnsurer().EnsureDirectories(context.Background(), command)
		if !errors.Is(err, productinstall.ErrIntegrity) {
			t.Fatalf("symlink error = %v, want integrity", err)
		}
	})

	t.Run("weak existing secret", func(t *testing.T) {
		root := unixTestRoot(t)
		ensurer := NewEnsurer()
		if _, err := ensurer.EnsureDirectories(context.Background(), unixDirectoryCommand(t, root)); err != nil {
			t.Fatal(err)
		}
		command := unixSecretCommand(t, root)
		path := command.Secrets()[0].Path()
		if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0o644); err != nil { //nolint:gosec // Deliberately weak secret fixture.
			t.Fatal(err)
		}
		_, err := ensurer.EnsureSecrets(context.Background(), command)
		if !errors.Is(err, productinstall.ErrIntegrity) {
			t.Fatalf("weak secret error = %v, want integrity", err)
		}
	})
}

func TestPF001NativeProductFilesystemHonorsCancellationAndEntropyFailure(t *testing.T) {
	t.Parallel()
	root := unixTestRoot(t)
	ensurer := NewEnsurer()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ensurer.EnsureDirectories(cancelled, unixDirectoryCommand(t, root)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled directory error = %v", err)
	}
	if _, err := ensurer.EnsureDirectories(context.Background(), unixDirectoryCommand(t, root)); err != nil {
		t.Fatal(err)
	}
	failing := newEnsurerWithRandom(errorReader{})
	_, err := failing.EnsureSecrets(context.Background(), unixSecretCommand(t, root))
	if !errors.Is(err, productinstall.ErrUnavailable) {
		t.Fatalf("entropy error = %v, want unavailable", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func unixDirectoryCommand(t testing.TB, root string) productinstall.DirectoryCommand {
	t.Helper()
	operationID, planDigest := unixBindings(t)
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
	directories := make([]productinstall.DirectorySpec, 0, len(inputs))
	for _, input := range inputs {
		specification, err := productinstall.NewDirectorySpec(input.purpose, input.path)
		if err != nil {
			t.Fatal(err)
		}
		directories = append(directories, specification)
	}
	command, err := productinstall.NewDirectoryCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory, directories,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func unixSecretCommand(t testing.TB, root string) productinstall.SecretCommand {
	t.Helper()
	operationID, planDigest := unixBindings(t)
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
	secrets := make([]productinstall.SecretSpec, 0, len(purposes))
	for _, purpose := range purposes {
		specification, err := productinstall.NewSecretSpec(purpose, filepath.Join(secretRoot, string(purpose)))
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, specification)
	}
	command, err := productinstall.NewSecretCommand(
		operationID, planDigest, 1, install.RuntimeOwnershipProvisionedByAgentMemory, secretRoot, secrets,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func unixBindings(t testing.TB) (install.OperationID, install.PlanDigest) {
	t.Helper()
	operationID, err := install.NewOperationID("pf001-native-productfs")
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := install.BindPlan([]byte("canonical-native-productfs-plan"))
	if err != nil {
		t.Fatal(err)
	}
	return operationID, planDigest
}

func unixTestRoot(t testing.TB) string {
	t.Helper()
	realDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(realDirectory, "agentmemory")
}
