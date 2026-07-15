package runtimeprovision

import (
	"context"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006PrivilegeRepositoryManagerRendersAndPublishesExactSignedConfiguration(t *testing.T) {
	t.Parallel()
	_, original := adapterAuthority(t)
	keyPath := "/etc/apt/keyrings/agentmemory-docker-stable.gpg"
	configuration, err := renderAPTPrivilegeRepository(original, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	input := original.TransportInput()
	input.Repository.ConfigurationDigest = runtimeinstall.Sum(configuration)
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := "Architectures: amd64\nComponents: stable\nSigned-By: /etc/apt/keyrings/agentmemory-docker-stable.gpg\nSuites: noble\nTypes: deb\nURIs: https://download.docker.com/linux/ubuntu\n"
	if string(configuration) != expected {
		t.Fatalf("configuration=%q", configuration)
	}
	request := privilegeOperationRequestFromAuthority(t, authority, runtimeport.PrivilegeConfigureRepository)
	transaction := privilegeRepositoryTransaction(authority)
	writes := &privilegeProtectedFileWriterStub{}
	manager, err := NewCanonicalPrivilegeRepositoryManager(writes)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := manager.EnsurePrivilegeRepository(t.Context(), request, transaction)
	if err != nil || !changed || len(writes.files) != 1 || len(writes.artifacts) != 1 ||
		writes.files[0].path != "/etc/apt/sources.list.d/agentmemory-docker-stable.sources" ||
		string(writes.files[0].contents) != expected || writes.artifacts[0].path != keyPath {
		t.Fatalf("changed=%t files=%+v artifacts=%+v error=%v", changed, writes.files, writes.artifacts, err)
	}
}

func TestPF006PrivilegeRepositoryManagerRejectsUnsignedRenderingOrWriteFailure(t *testing.T) {
	t.Parallel()
	_, authority := adapterAuthority(t)
	request := privilegeOperationRequestFromAuthority(t, authority, runtimeport.PrivilegeConfigureRepository)
	transaction := privilegeRepositoryTransaction(authority)
	manager, err := NewCanonicalPrivilegeRepositoryManager(&privilegeProtectedFileWriterStub{})
	if err != nil {
		t.Fatal(err)
	}
	if changed, ensureError := manager.EnsurePrivilegeRepository(
		t.Context(), request, transaction,
	); !errors.Is(ensureError, runtimeport.ErrPrivilegeIntegrity) || changed {
		t.Fatalf("unsigned configuration changed=%t error=%v", changed, ensureError)
	}
	if manager, err := NewCanonicalPrivilegeRepositoryManager(nil); manager != nil || err == nil {
		t.Fatal("missing protected writer accepted")
	}
	configuration, err := renderAPTPrivilegeRepository(
		authority, "/etc/apt/keyrings/agentmemory-docker-stable.gpg",
	)
	if err != nil {
		t.Fatal(err)
	}
	input := authority.TransportInput()
	input.Repository.ConfigurationDigest = runtimeinstall.Sum(configuration)
	authority, err = runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	request = privilegeOperationRequestFromAuthority(t, authority, runtimeport.PrivilegeConfigureRepository)
	writes := &privilegeProtectedFileWriterStub{err: errors.New("write failed")}
	manager, err = NewCanonicalPrivilegeRepositoryManager(writes)
	if err != nil {
		t.Fatal(err)
	}
	if changed, ensureError := manager.EnsurePrivilegeRepository(
		t.Context(), request, privilegeRepositoryTransaction(authority),
	); !errors.Is(ensureError, runtimeport.ErrPrivilegeIntegrity) || changed {
		t.Fatalf("write failure changed=%t error=%v", changed, ensureError)
	}
}

func privilegeOperationRequestFromAuthority(
	t testing.TB,
	authority runtimeport.LinuxAuthority,
	operation runtimeport.PrivilegeOperation,
) runtimeport.PrivilegeRequest {
	t.Helper()
	expected, err := runtimeport.ExpectedPrivilegeState(authority, operation)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "repository-operation", Attempt: 1, Operation: operation,
		Authority: authority, Nonce: runtimeport.Nonce{1}, IssuedAt: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 7, 15, 12, 1, 0, 0, time.UTC), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func privilegeRepositoryTransaction(authority runtimeport.LinuxAuthority) PrivilegeArtifactTransaction {
	artifact := PrivilegeTransactionArtifact{
		artifactID: "repo-" + authority.Repository().ID() + "-signing_key",
		targetPath: "/root/transaction/repository-key", sha256: authority.Repository().SigningKeyDigest(), size: 4096,
	}
	return PrivilegeArtifactTransaction{root: "/root/transaction", artifacts: []PrivilegeTransactionArtifact{artifact}}
}

type privilegeProtectedFileWrite struct {
	path     string
	contents []byte
	mode     uint32
}

type privilegeProtectedArtifactWrite struct {
	path     string
	artifact PrivilegeTransactionArtifact
	mode     uint32
}

type privilegeProtectedFileWriterStub struct {
	files     []privilegeProtectedFileWrite
	artifacts []privilegeProtectedArtifactWrite
	err       error
}

func (s *privilegeProtectedFileWriterStub) EnsurePrivilegeFile(
	_ context.Context,
	path string,
	contents []byte,
	mode uint32,
) (bool, error) {
	s.files = append(s.files, privilegeProtectedFileWrite{path: path, contents: append([]byte(nil), contents...), mode: mode})
	if s.err != nil {
		return false, s.err
	}
	return true, nil
}

func (s *privilegeProtectedFileWriterStub) EnsurePrivilegeArtifactFile(
	_ context.Context,
	path string,
	artifact PrivilegeTransactionArtifact,
	mode uint32,
) (bool, error) {
	s.artifacts = append(s.artifacts, privilegeProtectedArtifactWrite{path: path, artifact: artifact, mode: mode})
	if s.err != nil {
		return false, s.err
	}
	return true, nil
}
