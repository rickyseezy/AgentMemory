package mcpsession

import (
	"strings"
	"testing"
	"time"
)

const (
	testSessionID      = "019d2b4e-7a10-7def-8abc-0123456789ab"
	testInstallationID = "019d2b4e-7a11-7def-8abc-0123456789ab"
	testWorkspaceHash  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCredentialHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testImage          = "registry.local/agentmemory/mcp-session@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestPF005ExecutionPlanFixesEverySessionSandboxControl(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2026, 7, 22, 22, 0, 0, 0, time.UTC)
	workspace, err := NewWorkspaceIdentity(WorkspaceIdentityInput{
		LogicalPath:     "/Users/Ricky/Code/My project [α];$(touch nope)",
		RealPath:        "/Users/Ricky/Code/My project [α];$(touch nope)",
		DeviceIdentity:  "dev:16777234",
		PathFingerprint: testWorkspaceHash,
		GitRepositoryID: "repository-keyed-fingerprint",
		GitWorktreeID:   "worktree-keyed-fingerprint",
		GitCoverage:     GitCoveragePartial,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceIdentity() error = %v", err)
	}
	credential, err := NewCredentialLease(
		testCredentialHash, "/Users/Ricky/.agentmemory/sessions/credential",
		expiresAt.Add(-12*time.Hour), expiresAt,
	)
	if err != nil {
		t.Fatalf("NewCredentialLease() error = %v", err)
	}
	plan, err := NewExecutionPlan(ExecutionPlanInput{
		SessionID:       testSessionID,
		InstallationID:  testInstallationID,
		AgentID:         "codex",
		ReleaseID:       "v1.0.0",
		ManifestDigest:  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SecurityEpoch:   7,
		RuntimeEndpoint: "unix:///var/run/docker.sock",
		Workspace:       workspace,
		Image:           testImage,
		Network:         "agentmemory_019d2b4e7a117def8abc0123456789ab_internal",
		Credential:      credential,
	})
	if err != nil {
		t.Fatalf("NewExecutionPlan() error = %v", err)
	}

	if plan.SessionID() != testSessionID || plan.InstallationID() != testInstallationID ||
		plan.AgentID() != "codex" || plan.ReleaseID() != "v1.0.0" ||
		plan.ManifestDigest() != "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" ||
		plan.SecurityEpoch() != 7 || plan.RuntimeEndpoint() != "unix:///var/run/docker.sock" ||
		plan.Image() != testImage {
		t.Fatalf("plan identity = %#v", plan)
	}
	if plan.Network() != "agentmemory_019d2b4e7a117def8abc0123456789ab_internal" ||
		plan.Workspace().LogicalPath() != workspace.LogicalPath() ||
		plan.Credential().Digest() != credential.Digest() || credential.IssuedAt().IsZero() ||
		credential.ExpiresAt() != expiresAt {
		t.Fatalf("plan authority is incomplete: %#v", plan)
	}
	if workspace.DeviceIdentity() != "dev:16777234" ||
		workspace.PathFingerprint() != testWorkspaceHash ||
		workspace.GitRepositoryID() != "repository-keyed-fingerprint" ||
		workspace.GitWorktreeID() != "worktree-keyed-fingerprint" ||
		workspace.GitCoverage() != GitCoveragePartial {
		t.Fatalf("workspace identity = %#v", workspace)
	}
	if plan.WorkspaceMount().Source() != workspace.RealPath() ||
		plan.WorkspaceMount().Target() != "/workspace" || !plan.WorkspaceMount().ReadOnly() ||
		plan.WorkspaceMount().Propagation() != "rprivate" || !plan.WorkspaceMount().RecursiveReadOnly() {
		t.Fatalf("workspace mount = %#v", plan.WorkspaceMount())
	}
	if plan.CredentialMount().Source() != credential.ProtectedFile() ||
		plan.CredentialMount().Target() != "/run/secrets/agentmemory-session" ||
		!plan.CredentialMount().ReadOnly() || !credential.Valid() || !plan.Valid() {
		t.Fatalf("credential mount = %#v", plan.CredentialMount())
	}
	security := plan.Security()
	if !security.AutoRemove() || !security.ReadOnlyRootFS() || !security.DropAllCapabilities() ||
		!security.NoNewPrivileges() || security.TTY() || security.PublishPorts() ||
		security.MountDockerSocket() || security.Privileged() {
		t.Fatalf("security controls = %#v", security)
	}
	if security.PIDsLimit() != 128 || security.MemoryBytes() != 512*1024*1024 ||
		security.NanoCPUs() != 1_000_000_000 || security.TmpfsTarget() != "/tmp" {
		t.Fatalf("resource controls = %#v", security)
	}
}

func TestPF005ExecutionPlanRejectsMutableOrUnsafeAuthority(t *testing.T) {
	t.Parallel()
	valid := validExecutionPlanInput(t)
	cases := []struct {
		name   string
		mutate func(*ExecutionPlanInput)
	}{
		{name: "session UUID not v7", mutate: func(value *ExecutionPlanInput) { value.SessionID = "019d2b4e-7a10-4def-8abc-0123456789ab" }},
		{name: "installation UUID not v7", mutate: func(value *ExecutionPlanInput) { value.InstallationID = "019d2b4e-7a11-4def-8abc-0123456789ab" }},
		{name: "agent injection", mutate: func(value *ExecutionPlanInput) { value.AgentID = "codex\n--privileged" }},
		{name: "missing release", mutate: func(value *ExecutionPlanInput) { value.ReleaseID = "" }},
		{name: "bad manifest", mutate: func(value *ExecutionPlanInput) { value.ManifestDigest = "bad" }},
		{name: "zero epoch", mutate: func(value *ExecutionPlanInput) { value.SecurityEpoch = 0 }},
		{name: "remote runtime", mutate: func(value *ExecutionPlanInput) { value.RuntimeEndpoint = "ssh://remote" }},
		{name: "mutable image tag", mutate: func(value *ExecutionPlanInput) { value.Image = "agentmemory/mcp-session:latest" }},
		{name: "uppercase digest", mutate: func(value *ExecutionPlanInput) { value.Image = strings.Replace(testImage, "bbbb", "BBBB", 1) }},
		{name: "host network", mutate: func(value *ExecutionPlanInput) { value.Network = "host" }},
		{name: "empty workspace", mutate: func(value *ExecutionPlanInput) { value.Workspace = WorkspaceIdentity{} }},
		{name: "empty credential", mutate: func(value *ExecutionPlanInput) { value.Credential = CredentialLease{} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.mutate(&candidate)
			if _, err := NewExecutionPlan(candidate); err == nil {
				t.Fatal("NewExecutionPlan() error = nil")
			}
		})
	}
}

func TestPF005WorkspaceIdentityAcceptsHostPathsButRejectsTraversal(t *testing.T) {
	t.Parallel()
	valid := WorkspaceIdentityInput{
		LogicalPath:     `C:\Users\Ricky\My project [α];$HOME`,
		RealPath:        `C:\Users\Ricky\My project [α];$HOME`,
		DeviceIdentity:  "volume:01234567",
		PathFingerprint: testWorkspaceHash,
		GitCoverage:     GitCoverageNone,
	}
	if _, err := NewWorkspaceIdentity(valid); err != nil {
		t.Fatalf("NewWorkspaceIdentity(windows) error = %v", err)
	}
	for _, path := range []string{
		"relative/workspace", "/workspace/../secret", "/workspace//child", "/workspace\x00child",
		`C:\Users\Ricky\..\secret`, `\\server`,
	} {
		candidate := valid
		candidate.RealPath = path
		if _, err := NewWorkspaceIdentity(candidate); err == nil {
			t.Fatalf("NewWorkspaceIdentity(%q) error = nil", path)
		}
	}
}

func TestPF005WorkspaceIdentityAcceptsCanonicalUNCAndCompleteGitEvidence(t *testing.T) {
	t.Parallel()
	workspace, err := NewWorkspaceIdentity(WorkspaceIdentityInput{
		LogicalPath: `\\server\share\project`, RealPath: `\\server\share\project`,
		DeviceIdentity: "volume:share", PathFingerprint: testWorkspaceHash,
		GitRepositoryID: "repository", GitWorktreeID: "worktree", GitCoverage: GitCoverageComplete,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceIdentity(UNC) error = %v", err)
	}
	if workspace.GitCoverage() != GitCoverageComplete {
		t.Fatalf("GitCoverage() = %s", workspace.GitCoverage())
	}
	for _, input := range []WorkspaceIdentityInput{
		{LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1", PathFingerprint: testWorkspaceHash, GitCoverage: GitCoveragePartial},
		{LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1", PathFingerprint: testWorkspaceHash, GitRepositoryID: "repository", GitCoverage: GitCoverageComplete},
		{LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1", PathFingerprint: testWorkspaceHash, GitRepositoryID: "repository", GitCoverage: GitCoverageNone},
	} {
		if _, err := NewWorkspaceIdentity(input); err == nil {
			t.Fatal("NewWorkspaceIdentity(inconsistent Git evidence) error = nil")
		}
	}
}

func TestPF005ExportedAuthorityValidatorsUseClosedGrammar(t *testing.T) {
	t.Parallel()
	if !ValidAgentID("claude-code") || ValidAgentID("Claude Code") ||
		!ValidImageReference(testImage) || ValidImageReference("mcp-session:latest") ||
		!ValidNetworkName("agentmemory_install_internal") || ValidNetworkName("bridge") ||
		!ValidSHA256Digest(testCredentialHash) || ValidSHA256Digest("bad") ||
		!ValidUUIDv7(testSessionID) || ValidUUIDv7("019d2b4e-7a10-4def-8abc-0123456789ab") {
		t.Fatal("exported authority validation mismatch")
	}
}

func TestPF005CredentialLeaseRequiresOwnerProtectedReferenceAndBoundedExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	if _, err := NewCredentialLease(
		testCredentialHash, "/owner/session.key", now, now.Add(12*time.Hour),
	); err != nil {
		t.Fatalf("NewCredentialLease() error = %v", err)
	}
	for _, test := range []struct {
		digest string
		path   string
		issued time.Time
		expiry time.Time
	}{
		{digest: "", path: "/owner/session.key", issued: now, expiry: now.Add(time.Hour)},
		{digest: testCredentialHash, path: "relative.key", issued: now, expiry: now.Add(time.Hour)},
		{digest: testCredentialHash, path: "/owner/../session.key", issued: now, expiry: now.Add(time.Hour)},
		{digest: testCredentialHash, path: "/owner/session.key", issued: now, expiry: time.Time{}},
		{digest: testCredentialHash, path: "/owner/session.key", issued: now, expiry: now.Add(12*time.Hour + time.Microsecond)},
	} {
		if _, err := NewCredentialLease(test.digest, test.path, test.issued, test.expiry); err == nil {
			t.Fatal("NewCredentialLease() error = nil")
		}
	}
}

func validExecutionPlanInput(t testing.TB) ExecutionPlanInput {
	t.Helper()
	workspace, err := NewWorkspaceIdentity(WorkspaceIdentityInput{
		LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1",
		PathFingerprint: testWorkspaceHash, GitCoverage: GitCoverageNone,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceIdentity() error = %v", err)
	}
	credential, err := NewCredentialLease(
		testCredentialHash, "/owner/session.key",
		time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 22, 22, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("NewCredentialLease() error = %v", err)
	}
	return ExecutionPlanInput{
		SessionID: testSessionID, InstallationID: testInstallationID, AgentID: "codex",
		ReleaseID: "v1.0.0", ManifestDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SecurityEpoch: 7, RuntimeEndpoint: "unix:///var/run/docker.sock",
		Workspace: workspace, Image: testImage,
		Network: "agentmemory_019d2b4e7a117def8abc0123456789ab_internal", Credential: credential,
	}
}
