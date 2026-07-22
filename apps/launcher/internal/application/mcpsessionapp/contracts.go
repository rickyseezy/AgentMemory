// Package mcpsessionapp orchestrates one automatic PF-005 MCP session.
package mcpsessionapp

import (
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const maximumCredentialTTL = 12 * time.Hour

// Status is the closed durable session outcome.
type Status string

const (
	// StatusCompleted means child exit and the bounded final checkpoint both succeeded.
	StatusCompleted Status = "completed"
	// StatusInterrupted means source capture may be incomplete and the credential is revoked.
	StatusInterrupted Status = "interrupted"
)

// ErrorCode is the privacy-safe PF-005 application failure taxonomy.
type ErrorCode string

const (
	errorInvalidArgument ErrorCode = "AM_SESSION_INVALID_ARGUMENT"
	errorIntegrity       ErrorCode = "AM_SESSION_INTEGRITY"
	errorDeadline        ErrorCode = "AM_SESSION_DEADLINE"
	errorUnavailable     ErrorCode = "AM_SESSION_UNAVAILABLE"
)

// ApplicationError exposes only a stable classification across the launcher boundary.
type ApplicationError struct{ code ErrorCode }

func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the stable failure classification.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// IsInvalidArgument reports a malformed caller request.
func IsInvalidArgument(err error) bool { return hasCode(err, errorInvalidArgument) }

// IsIntegrity reports contradictory or untrusted local authority.
func IsIntegrity(err error) bool { return hasCode(err, errorIntegrity) }

// IsDeadline reports cancellation or deadline expiry.
func IsDeadline(err error) bool { return hasCode(err, errorDeadline) }

// IsUnavailable reports a temporary runtime, persistence, or cleanup failure.
func IsUnavailable(err error) bool { return hasCode(err, errorUnavailable) }

func hasCode(err error, code ErrorCode) bool {
	var applicationError *ApplicationError
	return errors.As(err, &applicationError) && applicationError.code == code
}

func newError(code ErrorCode) *ApplicationError { return &ApplicationError{code: code} }

// Command binds the host, exact working directory, and distinct protocol/diagnostic streams.
type Command struct {
	AgentID          string
	WorkingDirectory string
	Input            io.Reader
	Output           io.Writer
	Diagnostics      io.Writer
}

// Streams reserves stdout for MCP protocol frames and stderr for diagnostics.
type Streams struct {
	Input       io.Reader
	Output      io.Writer
	Diagnostics io.Writer
}

// Result is content-free terminal session evidence.
type Result struct {
	SessionID string
	Status    Status
}

// Policy contains bounded lifecycle timing. Production uses ProductionPolicy.
type Policy struct {
	HeartbeatInterval time.Duration
	LeaseTimeout      time.Duration
	CredentialTTL     time.Duration
	CheckpointTimeout time.Duration
	CleanupTimeout    time.Duration
}

// ProductionPolicy returns the reviewed local session timing contract.
func ProductionPolicy() Policy {
	return Policy{
		HeartbeatInterval: 30 * time.Second,
		LeaseTimeout:      120 * time.Second,
		CredentialTTL:     maximumCredentialTTL,
		CheckpointTimeout: 5 * time.Second,
		CleanupTimeout:    5 * time.Second,
	}
}

func (p Policy) valid() bool {
	return p.HeartbeatInterval > 0 && p.HeartbeatInterval <= 30*time.Second &&
		p.LeaseTimeout >= 2*p.HeartbeatInterval && p.LeaseTimeout <= 120*time.Second &&
		p.CredentialTTL > 0 && p.CredentialTTL <= maximumCredentialTTL &&
		p.CheckpointTimeout > 0 && p.CheckpointTimeout <= 30*time.Second &&
		p.CleanupTimeout > 0 && p.CleanupTimeout <= 30*time.Second
}

// SessionRelease is the exact active pointer plus manifest-bound session resources.
type SessionRelease struct {
	pointer activerelease.Pointer
	image   string
	network string
}

// NewSessionRelease validates immutable image/network authority against a nonzero active pointer.
func NewSessionRelease(
	pointer activerelease.Pointer,
	image string,
	network string,
) (SessionRelease, error) {
	if pointer.IsZero() || !mcpsession.ValidImageReference(image) ||
		!mcpsession.ValidNetworkName(network) {
		return SessionRelease{}, newError(errorIntegrity)
	}
	return SessionRelease{pointer: pointer, image: image, network: network}, nil
}

// Pointer returns the authenticated active-release authority.
func (r SessionRelease) Pointer() activerelease.Pointer { return r.pointer }

// Image returns the exact digest-qualified mcp-session image.
func (r SessionRelease) Image() string { return r.image }

// Network returns the exact installation-scoped internal network.
func (r SessionRelease) Network() string { return r.network }

func (r SessionRelease) validFor(pointer activerelease.Pointer) bool {
	return !pointer.IsZero() && r.pointer.Digest().Equal(pointer.Digest()) &&
		mcpsession.ValidImageReference(r.image) && mcpsession.ValidNetworkName(r.network)
}

// PathIdentity is canonical logical/real path and host-device evidence.
type PathIdentity struct {
	LogicalPath     string
	RealPath        string
	DeviceIdentity  string
	PathFingerprint string
}

// GitIdentity is host-resolved repository/worktree evidence without widening the mount.
type GitIdentity struct {
	RepositoryID string
	WorktreeID   string
	Coverage     mcpsession.GitCoverage
}

// CredentialScope binds minting to one session, workspace, agent, and security epoch.
type CredentialScope struct {
	SessionID            string
	InstallationID       string
	BrainID              string
	ActorID              string
	GrantID              string
	AgentID              string
	WorkspaceFingerprint string
	DeviceIdentity       string
	GitRepositoryID      string
	GitWorktreeID        string
	GitCoverage          mcpsession.GitCoverage
	SecurityEpoch        uint64
	TTL                  time.Duration
}

// SessionAuthorityScope binds every transient session to the installed owner
// grant and sole local Brain without deriving identity inside an adapter.
type SessionAuthorityScope struct {
	BrainID string
	ActorID string
	GrantID string
}

func (s SessionAuthorityScope) valid() bool {
	return mcpsession.ValidUUIDv7(s.BrainID) && mcpsession.ValidUUIDv7(s.ActorID) &&
		mcpsession.ValidUUIDv7(s.GrantID)
}

// CredentialRegistration is the content-free, hash-only authority persisted by Core.
type CredentialRegistration struct {
	Scope     CredentialScope
	Digest    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
