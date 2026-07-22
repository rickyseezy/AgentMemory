package mcpsessionapp

import (
	"context"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

// InstallationLock is an idempotently releasable machine-global startup lock.
type InstallationLock interface {
	Release(context.Context) error
}

// InstallationLockPort serializes runtime and active-release startup decisions.
type InstallationLockPort interface {
	Acquire(context.Context) (InstallationLock, error)
}

// ActiveReleasePort loads the sole authenticated host active pointer.
type ActiveReleasePort interface {
	LoadActive(context.Context) (activerelease.Pointer, error)
}

// RuntimeController starts/probes the selected endpoint and exact active Compose release.
type RuntimeController interface {
	EnsureReady(context.Context, activerelease.Pointer) (SessionRelease, error)
}

// PathIdentityPort canonicalizes logical/real paths and proves host/device identity.
type PathIdentityPort interface {
	Resolve(context.Context, string) (PathIdentity, error)
}

// GitIdentityPort resolves worktree metadata on the host without widening the mount.
type GitIdentityPort interface {
	Resolve(context.Context, PathIdentity) (GitIdentity, error)
}

// SessionIDPort creates an unpredictable UUIDv7 session identifier.
type SessionIDPort interface {
	NewSessionID(context.Context) (string, error)
}

// SessionCredentialPort mints and revokes owner-protected scoped credentials.
type SessionCredentialPort interface {
	Mint(context.Context, CredentialScope) (mcpsession.CredentialLease, error)
	Revoke(context.Context, mcpsession.CredentialLease) error
}

// SessionRepository persists lease and terminal lifecycle evidence.
type SessionRepository interface {
	Begin(context.Context, mcpsession.ExecutionPlan, time.Duration) error
	Heartbeat(context.Context, string, time.Time) error
	Finish(context.Context, string, Status, time.Time) error
}

// ChildProcessPort owns exact argv execution and post-run container removal.
type ChildProcessPort interface {
	Run(context.Context, mcpsession.ExecutionPlan, Streams) error
	Remove(context.Context, mcpsession.ExecutionPlan) error
}

// WorkspaceCheckpointPort streams only changed authorized content before mount removal.
type WorkspaceCheckpointPort interface {
	Begin(context.Context, mcpsession.ExecutionPlan) error
	Checkpoint(context.Context, mcpsession.ExecutionPlan) error
}

// Clock supplies trusted UTC lifecycle time.
type Clock interface {
	Now() time.Time
}

// Dependencies is the complete PF-005 application composition contract.
type Dependencies struct {
	Authority     SessionAuthorityScope
	Lock          InstallationLockPort
	ActiveRelease ActiveReleasePort
	Runtime       RuntimeController
	Paths         PathIdentityPort
	Git           GitIdentityPort
	IDs           SessionIDPort
	Credentials   SessionCredentialPort
	Sessions      SessionRepository
	Child         ChildProcessPort
	Checkpoints   WorkspaceCheckpointPort
	Clock         Clock
}
