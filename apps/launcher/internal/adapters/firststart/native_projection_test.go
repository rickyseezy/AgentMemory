package firststart

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NativeProjectionBindsInvokingOwnerExecutableAndCertifiedLocation(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	executable := filepath.Join(home, "agentmemory")
	contents := []byte("signed launcher")
	if err := os.WriteFile(executable, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	owner, err := install.BindOwner("machine", "principal")
	if err != nil {
		t.Fatal(err)
	}
	location, _ := agentconfigport.NewConfigLocation(filepath.Join(home, ".codex", "config.toml"))
	source, err := newNativeHostProjectionSource(nativeProjectionDependencies{
		home:       func() (string, error) { return home, nil },
		executable: func() (string, error) { return executable, nil },
		open:       os.Open, lstat: os.Lstat, locations: projectionLocationStub{location: location},
		owners: projectionOwnerStub{owner: owner}, goos: "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := source.Project(t.Context(), agentconfigdomain.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	if projection.StorageRoot != filepath.Join(home, ".agentmemory") ||
		projection.RuntimeEndpoint != "unix:///var/run/docker.sock" ||
		projection.ConfigurationPath != location.String() || projection.LauncherPath != executable ||
		!projection.LauncherDigest.Equal(agentconfigdomain.DigestBytes(contents)) ||
		!projection.OwnerSubjectDigest.Equal(owner.PrincipalDigest()) {
		t.Fatalf("projection=%+v", projection)
	}
}

func TestPF001NativeProjectionFailsClosedWithoutEveryNativeAuthority(t *testing.T) {
	t.Parallel()
	base := nativeProjectionDependencies{
		home: os.UserHomeDir, executable: os.Executable, open: os.Open, lstat: os.Lstat,
		locations: projectionLocationStub{}, owners: projectionOwnerStub{}, goos: "linux",
	}
	for name, mutate := range map[string]func(*nativeProjectionDependencies){
		"home":       func(value *nativeProjectionDependencies) { value.home = nil },
		"executable": func(value *nativeProjectionDependencies) { value.executable = nil },
		"open":       func(value *nativeProjectionDependencies) { value.open = nil },
		"lstat":      func(value *nativeProjectionDependencies) { value.lstat = nil },
		"locations":  func(value *nativeProjectionDependencies) { value.locations = (*projectionLocationPointerStub)(nil) },
		"owners":     func(value *nativeProjectionDependencies) { value.owners = (*projectionOwnerPointerStub)(nil) },
		"platform":   func(value *nativeProjectionDependencies) { value.goos = "plan9" },
	} {
		candidate := base
		mutate(&candidate)
		if source, err := newNativeHostProjectionSource(candidate); source != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
			t.Fatalf("%s source=%v error=%v", name, source, err)
		}
	}
	var absent *NativeHostProjectionSource
	if _, err := absent.Project(t.Context(), agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil source error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := (&NativeHostProjectionSource{}).Project(nil, agentconfigdomain.AgentHostCodex); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
}

func TestPF001NativeProjectionRejectsSymlinkAndMapsPrivateFailures(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	target := filepath.Join(home, "target")
	if err := os.WriteFile(target, []byte("launcher"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(home, "launcher")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	owner, _ := install.BindOwner("machine", "principal")
	location, _ := agentconfigport.NewConfigLocation(filepath.Join(home, ".claude.json"))
	dependencies := nativeProjectionDependencies{
		home:       func() (string, error) { return home, nil },
		executable: func() (string, error) { return symlink, nil },
		open:       os.Open, lstat: os.Lstat, locations: projectionLocationStub{location: location},
		owners: projectionOwnerStub{owner: owner}, goos: "darwin",
	}
	source, _ := newNativeHostProjectionSource(dependencies)
	if _, err := source.Project(t.Context(), agentconfigdomain.AgentHostClaude); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("symlink error=%v", err)
	}
	dependencies.executable = func() (string, error) { return "", errors.New("private") }
	source, _ = newNativeHostProjectionSource(dependencies)
	if _, err := source.Project(t.Context(), agentconfigdomain.AgentHostClaude); !errors.Is(err, firststartapp.ErrUnavailable) {
		t.Fatalf("private executable error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Project(cancelled, agentconfigdomain.AgentHostClaude); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

type projectionLocationStub struct {
	location agentconfigport.ConfigLocation
	err      error
}

func (s projectionLocationStub) Resolve(context.Context, agentconfigdomain.AgentHost) (agentconfigport.ConfigLocation, error) {
	return s.location, s.err
}

type projectionOwnerStub struct {
	owner install.OwnerBinding
	err   error
}

func (s projectionOwnerStub) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, s.err
}

type projectionLocationPointerStub struct{ projectionLocationStub }
type projectionOwnerPointerStub struct{ projectionOwnerStub }
