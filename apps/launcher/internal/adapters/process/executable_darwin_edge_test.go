//go:build darwin && cgo

package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001DarwinExecutablePathPolicyAcceptsInstalledAuthorities(t *testing.T) {
	t.Parallel()
	rootInfo := unixFileInfoStub{
		mode:   os.ModeDir | 0o755,
		system: &syscall.Stat_t{Uid: 0, Gid: 0},
	}
	executableInfo := unixFileInfoStub{
		mode:   0o755,
		system: &syscall.Stat_t{Uid: 0, Gid: 0},
	}
	ancestors := []executableAncestor{{identity: rootInfo}}
	tests := []struct {
		name      string
		path      string
		role      argvprocess.ExecutableRole
		ancestors []executableAncestor
		info      os.FileInfo
		uid       uint32
		want      bool
	}{
		{
			name: "docker CLI", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors, info: executableInfo, want: true,
		},
		{
			name: "compose plugin", path: "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
			role: argvprocess.ExecutableRoleComposePlugin, ancestors: ancestors, info: executableInfo, want: true,
		},
		{
			name: "AgentMemory launcher", path: "/Applications/AgentMemory.app/Contents/MacOS/AgentMemory",
			role: argvprocess.ExecutableRoleAgentMemoryLauncher, ancestors: ancestors, info: executableInfo, want: true,
		},
		{
			name: "Linux rootless setup capability", path: "/usr/bin/dockerd-rootless-setuptool.sh",
			role: argvprocess.ExecutableRoleRootlessSetup, ancestors: ancestors, info: executableInfo,
		},
		{
			name: "role path substitution", path: "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors, info: executableInfo,
		},
		{
			name: "non-root plan owner", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors, info: executableInfo, uid: 501,
		},
		{
			name: "missing metadata", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors,
		},
		{
			name: "foreign executable owner", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors,
			info: unixFileInfoStub{mode: 0o755, system: &syscall.Stat_t{Uid: 501, Gid: 0}},
		},
		{
			name: "foreign executable group", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors,
			info: unixFileInfoStub{mode: 0o755, system: &syscall.Stat_t{Uid: 0, Gid: 20}},
		},
		{
			name: "writable executable", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors,
			info: unixFileInfoStub{mode: 0o775, system: &syscall.Stat_t{Uid: 0, Gid: 0}},
		},
		{
			name: "invalid executable metadata", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, ancestors: ancestors,
			info: unixFileInfoStub{mode: 0o755, system: struct{}{}},
		},
		{
			name: "foreign ancestor owner", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI,
			ancestors: []executableAncestor{{identity: unixFileInfoStub{
				mode: os.ModeDir | 0o755, system: &syscall.Stat_t{Uid: 501, Gid: 0},
			}}}, info: executableInfo,
		},
		{
			name: "writable ancestor", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI,
			ancestors: []executableAncestor{{identity: unixFileInfoStub{
				mode: os.ModeDir | 0o777, system: &syscall.Stat_t{Uid: 0, Gid: 0},
			}}}, info: executableInfo,
		},
		{
			name: "invalid ancestor metadata", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI,
			ancestors: []executableAncestor{{identity: unixFileInfoStub{
				mode: os.ModeDir | 0o755, system: struct{}{},
			}}}, info: executableInfo,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := darwinAuthority(t, test.path, test.role, "test-publisher", "test-policy")
			if got := platformExecutablePathSupported(authority, test.ancestors, test.info, test.uid, false); got != test.want {
				t.Fatalf("path supported = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPF001DarwinExecutableNativeHelpersFailClosed(t *testing.T) {
	t.Parallel()
	if got, err := platformExecutableIdentity(unixFileInfoStub{system: struct{}{}}); err == nil || got != "" {
		t.Fatalf("invalid identity = %q, %v", got, err)
	}
	if command, err := platformExecutableCommand(context.Background(), nil, nil); err == nil || command != nil {
		t.Fatalf("nil lease command = %+v, %v", command, err)
	}
	if executableACLFree(nil) {
		t.Fatal("nil executable descriptor was ACL-free")
	}
}

func TestPF001DarwinPublisherRequirementBindsRoleAndPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		role       argvprocess.ExecutableRole
		publisher  string
		identifier string
		teamID     string
	}{
		{
			name: "docker CLI", path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			role: argvprocess.ExecutableRoleDockerCLI, publisher: dockerPublisherIdentity,
			identifier: `identifier "docker"`, teamID: dockerPublisherIdentity[7:],
		},
		{
			name: "compose plugin", path: "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
			role: argvprocess.ExecutableRoleComposePlugin, publisher: dockerPublisherIdentity,
			identifier: `identifier "docker-compose"`, teamID: dockerPublisherIdentity[7:],
		},
		{
			name: "AgentMemory launcher", path: "/Applications/AgentMemory.app/Contents/MacOS/AgentMemory",
			role: argvprocess.ExecutableRoleAgentMemoryLauncher, publisher: "teamid:AB12CD34EF",
			identifier: `identifier "com.agentmemory.AgentMemory"`, teamID: "AB12CD34EF",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := darwinAuthority(t, test.path, test.role, test.publisher, darwinPublisherPolicy)
			requirement, err := darwinPublisherRequirement(context.Background(), authority, ExecutableEvidence{Digest: authority.SHA256()})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(requirement, test.identifier) || !strings.Contains(requirement, test.teamID) {
				t.Fatalf("requirement = %q", requirement)
			}
		})
	}
	rootless := darwinAuthority(
		t, "/usr/bin/dockerd-rootless-setuptool.sh", argvprocess.ExecutableRoleRootlessSetup,
		dockerPublisherIdentity, darwinPublisherPolicy,
	)
	if _, err := darwinPublisherRequirement(
		context.Background(), rootless, ExecutableEvidence{Digest: rootless.SHA256()},
	); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("Linux rootless setup publisher error = %v", err)
	}
	for _, teamID := range []string{
		"ab12cd34ef", "SHORT", `AB12CD34E"`, "9BNSXJN65R-extra",
	} {
		if validDarwinTeamID(teamID) {
			t.Fatalf("invalid Team ID %q was accepted", teamID)
		}
	}
	foreignDocker := darwinAuthority(
		t, "/Applications/Docker.app/Contents/Resources/bin/docker",
		argvprocess.ExecutableRoleDockerCLI, "teamid:AB12CD34EF", darwinPublisherPolicy,
	)
	if _, err := darwinPublisherRequirement(
		context.Background(), foreignDocker, ExecutableEvidence{Digest: foreignDocker.SHA256()},
	); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("foreign Docker publisher error = %v", err)
	}
}

func TestPF001DarwinPublisherVerificationRejectsUnassessedObject(t *testing.T) {
	t.Parallel()
	path := "/Applications/Docker.app/Contents/Resources/bin/not-installed-agentmemory-fixture"
	authority := darwinAuthority(t, path, argvprocess.ExecutableRoleDockerCLI, dockerPublisherIdentity, darwinPublisherPolicy)
	verifier, err := NewNativePublisherVerifier(NativePublisherDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyExecutablePublisher(
		context.Background(), authority, ExecutableEvidence{Digest: authority.SHA256()},
	); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("unassessed object error = %v", err)
	}
}

func darwinAuthority(
	t *testing.T,
	path string,
	role argvprocess.ExecutableRole,
	publisher string,
	policy string,
) argvprocess.ExecutableAuthority {
	t.Helper()
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "darwin-executable", CanonicalPath: path,
		SHA256: sha256.Sum256([]byte(path)), OwnerIdentity: "uid:0",
		PublisherIdentity: publisher, PublisherPolicyID: policy,
		PublisherTrustDigest:  sha256.Sum256([]byte("test-publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("release")),
		RuntimePlanDigest:     sha256.Sum256([]byte("plan")),
		Role:                  role, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
