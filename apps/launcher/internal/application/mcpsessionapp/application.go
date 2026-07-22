package mcpsessionapp

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

// Application coordinates startup authority, isolated execution, and terminal cleanup.
type Application struct {
	dependencies Dependencies
	policy       Policy
}

// New rejects partial composition before any session side effect is possible.
func New(dependencies Dependencies, policy Policy) (*Application, error) {
	required := []any{
		dependencies.Lock, dependencies.ActiveRelease, dependencies.Runtime,
		dependencies.Paths, dependencies.Git, dependencies.IDs, dependencies.Credentials,
		dependencies.Sessions, dependencies.Child, dependencies.Checkpoints, dependencies.Clock,
	}
	for _, dependency := range required {
		if nilCapability(dependency) {
			return nil, newError(errorIntegrity)
		}
	}
	if !policy.valid() || !dependencies.Authority.valid() {
		return nil, newError(errorIntegrity)
	}
	return &Application{dependencies: dependencies, policy: policy}, nil
}

// Start launches one exact active-release session and settles every cleanup obligation.
func (a *Application) Start(ctx context.Context, command Command) (Result, error) {
	if a == nil || ctx == nil || !validCommand(command) {
		return Result{}, newError(errorInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, newError(errorDeadline)
	}
	lock, err := a.dependencies.Lock.Acquire(ctx)
	if err != nil || nilCapability(lock) {
		return Result{}, mapDependencyError(err)
	}

	prepared, prepareError := a.prepareLocked(ctx, command)
	if prepareError != nil {
		a.cleanupFailedPreparation(ctx, lock, prepared)
		return Result{}, prepareError
	}
	if releaseError := a.releaseLock(ctx, lock); releaseError != nil {
		result := Result{SessionID: prepared.plan.SessionID(), Status: StatusInterrupted}
		a.cleanupUnstarted(ctx, prepared)
		return result, newError(errorUnavailable)
	}
	return a.runAndFinalize(ctx, command, prepared)
}

type preparedSession struct {
	plan       mcpsession.ExecutionPlan
	credential mcpsession.CredentialLease
	minted     bool
	begun      bool
}

func (a *Application) prepareLocked(
	ctx context.Context,
	command Command,
) (preparedSession, error) {
	pointer, err := a.dependencies.ActiveRelease.LoadActive(ctx)
	if err != nil || pointer.IsZero() {
		return preparedSession{}, mapIntegrityDependency(err)
	}
	release, err := a.dependencies.Runtime.EnsureReady(ctx, pointer)
	if err != nil {
		return preparedSession{}, mapDependencyError(err)
	}
	if !release.validFor(pointer) {
		return preparedSession{}, newError(errorIntegrity)
	}
	path, err := a.dependencies.Paths.Resolve(ctx, command.WorkingDirectory)
	if err != nil {
		return preparedSession{}, mapDependencyError(err)
	}
	git, err := a.dependencies.Git.Resolve(ctx, path)
	if err != nil {
		return preparedSession{}, mapDependencyError(err)
	}
	workspace, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: path.LogicalPath, RealPath: path.RealPath,
		DeviceIdentity: path.DeviceIdentity, PathFingerprint: path.PathFingerprint,
		GitRepositoryID: git.RepositoryID, GitWorktreeID: git.WorktreeID, GitCoverage: git.Coverage,
	})
	if err != nil || workspace.LogicalPath() != command.WorkingDirectory {
		return preparedSession{}, newError(errorIntegrity)
	}
	sessionID, err := a.dependencies.IDs.NewSessionID(ctx)
	if err != nil {
		return preparedSession{}, mapDependencyError(err)
	}
	now := a.dependencies.Clock.Now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return preparedSession{}, newError(errorIntegrity)
	}
	credential, err := a.dependencies.Credentials.Mint(ctx, CredentialScope{
		SessionID: sessionID, InstallationID: pointer.InstallationID(),
		BrainID: a.dependencies.Authority.BrainID, ActorID: a.dependencies.Authority.ActorID,
		GrantID: a.dependencies.Authority.GrantID, AgentID: command.AgentID,
		WorkspaceFingerprint: workspace.PathFingerprint(), DeviceIdentity: workspace.DeviceIdentity(),
		GitRepositoryID: workspace.GitRepositoryID(), GitWorktreeID: workspace.GitWorktreeID(),
		GitCoverage: workspace.GitCoverage(), SecurityEpoch: pointer.SecurityEpoch(),
		TTL: a.policy.CredentialTTL,
	})
	prepared := preparedSession{credential: credential, minted: err == nil}
	if err != nil {
		return preparedSession{}, mapDependencyError(err)
	}
	if !credential.IssuedAt().Equal(now) || !credential.ExpiresAt().Equal(now.Add(a.policy.CredentialTTL)) {
		return prepared, newError(errorIntegrity)
	}
	plan, err := mcpsession.NewExecutionPlan(mcpsession.ExecutionPlanInput{
		SessionID: sessionID, InstallationID: pointer.InstallationID(), AgentID: command.AgentID,
		ReleaseID: pointer.ReleaseID(), ManifestDigest: pointer.ManifestDigest().String(),
		SecurityEpoch: pointer.SecurityEpoch(), RuntimeEndpoint: pointer.RuntimeEndpoint(),
		Workspace: workspace, Image: release.Image(), Network: release.Network(), Credential: credential,
	})
	if err != nil {
		return prepared, newError(errorIntegrity)
	}
	prepared.plan = plan
	if err := a.dependencies.Sessions.Begin(ctx, plan, a.policy.LeaseTimeout); err != nil {
		return prepared, mapDependencyError(err)
	}
	prepared.begun = true
	if err := a.dependencies.Checkpoints.Begin(ctx, plan); err != nil {
		return prepared, mapDependencyError(err)
	}
	return prepared, nil
}

func (a *Application) runAndFinalize(
	ctx context.Context,
	command Command,
	prepared preparedSession,
) (Result, error) {
	runError := a.runWithHeartbeats(ctx, prepared.plan, Streams{
		Input: command.Input, Output: command.Output, Diagnostics: command.Diagnostics,
	})
	checkpointContext, cancelCheckpoint := context.WithTimeout(
		context.WithoutCancel(ctx), a.policy.CheckpointTimeout,
	)
	checkpointError := a.dependencies.Checkpoints.Checkpoint(checkpointContext, prepared.plan)
	cancelCheckpoint()
	status := StatusInterrupted
	if runError == nil && checkpointError == nil {
		status = StatusCompleted
	}
	status, cleanupError := a.finalize(ctx, prepared, status)
	result := Result{SessionID: prepared.plan.SessionID(), Status: status}
	if runError != nil {
		return result, mapRunError(ctx, runError)
	}
	if checkpointError != nil || cleanupError != nil {
		return result, newError(errorUnavailable)
	}
	return result, nil
}

func (a *Application) runWithHeartbeats(
	ctx context.Context,
	plan mcpsession.ExecutionPlan,
	streams Streams,
) error {
	childContext, cancelChild := context.WithCancel(ctx)
	defer cancelChild()
	childResult := make(chan error, 1)
	go func() {
		childResult <- a.dependencies.Child.Run(childContext, plan, streams)
	}()
	ticker := time.NewTicker(a.policy.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-childResult:
			return err
		case <-ctx.Done():
			cancelChild()
			<-childResult
			return ctx.Err()
		case <-ticker.C:
			heartbeatContext, cancelHeartbeat := context.WithTimeout(
				childContext, a.policy.HeartbeatInterval,
			)
			heartbeatError := a.dependencies.Sessions.Heartbeat(
				heartbeatContext, plan.SessionID(),
				a.dependencies.Clock.Now().UTC().Truncate(time.Microsecond),
			)
			cancelHeartbeat()
			if heartbeatError != nil {
				cancelChild()
				<-childResult
				return heartbeatError
			}
		}
	}
}

func (a *Application) cleanupFailedPreparation(
	parent context.Context,
	lock InstallationLock,
	prepared preparedSession,
) {
	cleanupContext, cancel := a.cleanupContext(parent)
	defer cancel()
	if prepared.begun {
		_ = a.dependencies.Sessions.Finish(
			cleanupContext, prepared.plan.SessionID(), StatusInterrupted,
			a.dependencies.Clock.Now().UTC().Truncate(time.Microsecond),
		)
	}
	if prepared.minted {
		_ = a.dependencies.Credentials.Revoke(cleanupContext, prepared.credential)
	}
	_ = a.releaseLock(parent, lock)
}

func (a *Application) cleanupUnstarted(parent context.Context, prepared preparedSession) {
	cleanupContext, cancel := a.cleanupContext(parent)
	defer cancel()
	_ = a.dependencies.Credentials.Revoke(cleanupContext, prepared.credential)
	_ = a.dependencies.Child.Remove(cleanupContext, prepared.plan)
	_ = a.dependencies.Sessions.Finish(
		cleanupContext, prepared.plan.SessionID(), StatusInterrupted,
		a.dependencies.Clock.Now().UTC().Truncate(time.Microsecond),
	)
}

func (a *Application) finalize(
	parent context.Context,
	prepared preparedSession,
	status Status,
) (Status, error) {
	cleanupContext, cancel := a.cleanupContext(parent)
	defer cancel()
	revokeError := a.dependencies.Credentials.Revoke(cleanupContext, prepared.credential)
	removeError := a.dependencies.Child.Remove(cleanupContext, prepared.plan)
	if revokeError != nil || removeError != nil {
		status = StatusInterrupted
	}
	finishError := a.dependencies.Sessions.Finish(
		cleanupContext, prepared.plan.SessionID(), status,
		a.dependencies.Clock.Now().UTC().Truncate(time.Microsecond),
	)
	if finishError != nil {
		status = StatusInterrupted
	}
	return status, errors.Join(revokeError, removeError, finishError)
}

func (a *Application) releaseLock(parent context.Context, lock InstallationLock) error {
	cleanupContext, cancel := a.cleanupContext(parent)
	defer cancel()
	return lock.Release(cleanupContext)
}

func (a *Application) cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), a.policy.CleanupTimeout)
}

func validCommand(command Command) bool {
	return mcpsession.ValidAgentID(command.AgentID) && command.WorkingDirectory != "" &&
		len(command.WorkingDirectory) <= 4096 && utf8.ValidString(command.WorkingDirectory) &&
		!strings.ContainsAny(command.WorkingDirectory, "\x00\r\n") &&
		!nilCapability(command.Input) && !nilCapability(command.Output) &&
		!nilCapability(command.Diagnostics)
}

func mapIntegrityDependency(err error) *ApplicationError {
	if err == nil {
		return newError(errorIntegrity)
	}
	return mapDependencyError(err)
}

func mapDependencyError(err error) *ApplicationError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return newError(errorDeadline)
	}
	return newError(errorUnavailable)
}

func mapRunError(ctx context.Context, err error) *ApplicationError {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return newError(errorDeadline)
	}
	return newError(errorUnavailable)
}
