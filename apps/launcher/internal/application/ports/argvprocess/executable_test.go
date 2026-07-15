package argvprocess

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestPF001ExecutableAuthorityIsRoleAndSignedPlanBound(t *testing.T) {
	t.Parallel()
	input := validExecutableAuthorityInput()
	authority, err := NewExecutableAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	equivalent := authority
	if !authority.Valid() || authority.CanonicalID() != input.CanonicalID ||
		authority.CanonicalPath() != input.CanonicalPath || authority.SHA256() != input.SHA256 ||
		authority.OwnerIdentity() != input.OwnerIdentity ||
		authority.PublisherIdentity() != input.PublisherIdentity ||
		authority.PublisherPolicyID() != input.PublisherPolicyID ||
		authority.PublisherTrustDigest() != input.PublisherTrustDigest ||
		authority.Role() != ExecutableRoleDockerCLI || authority.Platform() != input.Platform ||
		authority.Architecture() != input.Architecture ||
		authority.ReleaseManifestDigest() != input.ReleaseManifestDigest ||
		authority.RuntimePlanDigest() != input.RuntimePlanDigest || !authority.Equal(equivalent) {
		t.Fatalf("authority lost signed bindings: %+v", authority)
	}
	composeInput := input
	composeInput.CanonicalID = "compose"
	composeInput.CanonicalPath += "-compose"
	composeInput.Role = ExecutableRoleComposePlugin
	compose, err := NewExecutableAuthority(composeInput)
	if err != nil || !authority.SameSignedPlan(compose) {
		t.Fatalf("same signed plan = %v, %v", authority.SameSignedPlan(compose), err)
	}
	composeInput.RuntimePlanDigest = sha256.Sum256([]byte("substituted-plan"))
	substituted, err := NewExecutableAuthority(composeInput)
	if err != nil || authority.SameSignedPlan(substituted) {
		t.Fatal("runtime-plan substitution retained authority equivalence")
	}
	if authority.SameSignedPlan(ExecutableAuthority{}) || (ExecutableAuthority{}).SameSignedPlan(authority) {
		t.Fatal("unconstructed authority acquired signed-plan equivalence")
	}
	rootlessInput := input
	rootlessInput.CanonicalID = "rootless-setup"
	rootlessInput.CanonicalPath = "/verified/rootless-setup"
	rootlessInput.Role = ExecutableRoleRootlessSetup
	if rootless, rootlessError := NewExecutableAuthority(rootlessInput); rootlessError != nil || !rootless.Valid() {
		t.Fatalf("rootless setup authority rejected: %v", rootlessError)
	}
	rpmKeysInput := input
	rpmKeysInput.CanonicalID = "rpmkeys"
	rpmKeysInput.CanonicalPath = "/verified/rpmkeys"
	rpmKeysInput.Role = ExecutableRoleRPMKeys
	if rpmKeys, rpmKeysError := NewExecutableAuthority(rpmKeysInput); rpmKeysError != nil || !rpmKeys.Valid() ||
		rpmKeys.Role() != ExecutableRoleRPMKeys {
		t.Fatalf("RPM keys authority rejected: %v", rpmKeysError)
	}
	privilegeInput := input
	privilegeInput.CanonicalID = "pkexec"
	privilegeInput.CanonicalPath = "/verified/pkexec"
	privilegeInput.Role = ExecutableRolePrivilegeBroker
	if privilege, privilegeError := NewExecutableAuthority(privilegeInput); privilegeError != nil ||
		!privilege.Valid() || privilege.Role() != ExecutableRolePrivilegeBroker {
		t.Fatalf("privilege broker authority rejected: %v", privilegeError)
	}
	launcherInput := input
	launcherInput.CanonicalID = "agentmemory-launcher"
	launcherInput.CanonicalPath = "/verified/agentmemory"
	launcherInput.Role = ExecutableRoleAgentMemoryLauncher
	if launcher, launcherError := NewExecutableAuthority(launcherInput); launcherError != nil || !launcher.Valid() ||
		launcher.Role() != ExecutableRoleAgentMemoryLauncher {
		t.Fatalf("launcher authority rejected: %v", launcherError)
	}
}

func TestPF001ExecutableAuthorityRejectsIncompleteOrOpenPolicy(t *testing.T) {
	t.Parallel()
	valid := validExecutableAuthorityInput()
	tests := []struct {
		name   string
		mutate func(*ExecutableAuthorityInput)
	}{
		{name: "empty canonical identity", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalID = "" }},
		{name: "oversized canonical identity", mutate: func(v *ExecutableAuthorityInput) {
			v.CanonicalID = strings.Repeat("a", maximumExecutableIdentityBytes+1)
		}},
		{name: "padded canonical identity", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalID = " docker" }},
		{name: "invalid canonical identity character", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalID = "docker?" }},
		{name: "newline owner identity", mutate: func(v *ExecutableAuthorityInput) { v.OwnerIdentity = "uid:0\n" }},
		{name: "zero release digest", mutate: func(v *ExecutableAuthorityInput) { v.ReleaseManifestDigest = [sha256.Size]byte{} }},
		{name: "zero runtime plan digest", mutate: func(v *ExecutableAuthorityInput) { v.RuntimePlanDigest = [sha256.Size]byte{} }},
		{name: "zero publisher trust digest", mutate: func(v *ExecutableAuthorityInput) { v.PublisherTrustDigest = [sha256.Size]byte{} }},
		{name: "unknown role", mutate: func(v *ExecutableAuthorityInput) { v.Role = ExecutableRole("generic") }},
		{name: "cross platform", mutate: func(v *ExecutableAuthorityInput) { v.Platform = "other" }},
		{name: "unsupported architecture", mutate: func(v *ExecutableAuthorityInput) { v.Architecture = "386" }},
		{name: "relative path", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalPath = "docker" }},
		{name: "trailing path separator", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalPath = "/verified/docker/" }},
		{name: "empty path component", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalPath = "/verified//docker" }},
		{name: "dot path component", mutate: func(v *ExecutableAuthorityInput) { v.CanonicalPath = "/verified/./docker" }},
		{name: "zero executable digest", mutate: func(v *ExecutableAuthorityInput) { v.SHA256 = [sha256.Size]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			test.mutate(&input)
			if _, err := NewExecutableAuthority(input); !errors.Is(err, ErrInvalidInvocation) {
				t.Fatalf("NewExecutableAuthority() error = %v", err)
			}
		})
	}
}

func TestPF001ExecutableAuthorityValidatesWindowsPathWithoutHostRuntime(t *testing.T) {
	t.Parallel()
	valid := validExecutableAuthorityInput()
	valid.Platform = "windows"
	valid.Architecture = "amd64"
	valid.CanonicalPath = `C:\Program Files\Docker\docker.exe`
	authority, err := NewExecutableAuthority(valid)
	if err != nil || !authority.Valid() || authority.Platform() != "windows" || authority.Architecture() != "amd64" {
		t.Fatalf("Windows authority = %+v, %v", authority, err)
	}
	for _, path := range []string{
		`c:\Docker\docker.exe`,
		`C:/Docker/docker.exe`,
		`C:\Docker\docker.exe\`,
		`C:\Docker\\docker.exe`,
		`C:\Docker\..\docker.exe`,
	} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			input := valid
			input.CanonicalPath = path
			if _, err := NewExecutableAuthority(input); !errors.Is(err, ErrInvalidInvocation) {
				t.Fatalf("unsafe Windows path %q error = %v", path, err)
			}
		})
	}
}

func validExecutableAuthorityInput() ExecutableAuthorityInput {
	return ExecutableAuthorityInput{
		CanonicalID: "docker", CanonicalPath: "/verified/docker",
		SHA256: sha256.Sum256([]byte("docker")), OwnerIdentity: "uid:0",
		PublisherIdentity: "publisher", PublisherPolicyID: "policy",
		PublisherTrustDigest:  sha256.Sum256([]byte("publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("release")),
		RuntimePlanDigest:     sha256.Sum256([]byte("plan")), Role: ExecutableRoleDockerCLI,
		Platform: "darwin", Architecture: "arm64",
	}
}
