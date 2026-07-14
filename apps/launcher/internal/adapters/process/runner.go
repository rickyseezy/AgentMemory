// Package process implements constrained host argv execution.
package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

const defaultOutputLimit = 1024 * 1024

// Runner executes an exact absolute executable with a scrubbed environment.
// It is not suitable for privileged helpers, which require dedicated native
// adapters and a closed signed operation contract.
type Runner struct {
	outputLimit              int
	authority                argvprocess.ExecutableAuthority
	publisher                PublisherVerifier
	testOnlyAllowMutablePath bool
}

// ExecutableEvidence binds native publisher validation to the same opened OS
// object whose bytes and owner the runner verified.
type ExecutableEvidence struct {
	CanonicalID           string
	FileIdentity          string
	Digest                [sha256.Size]byte
	OwnerIdentity         string
	ReleaseManifestDigest [sha256.Size]byte
	RuntimePlanDigest     [sha256.Size]byte
	Role                  argvprocess.ExecutableRole
}

// PublisherVerifier validates the signed publisher/policy identity against
// the opened executable evidence. Production must use a native platform
// verifier; nil and typed-nil verifiers are rejected.
type PublisherVerifier interface {
	VerifyExecutablePublisher(context.Context, argvprocess.ExecutableAuthority, ExecutableEvidence) error
}

// ExecutableAuthority returns the exact immutable authority supplied at
// construction; Runner has no method that can replace or broaden it.
func (r *Runner) ExecutableAuthority() argvprocess.ExecutableAuthority {
	if r == nil {
		return argvprocess.ExecutableAuthority{}
	}
	return r.authority
}

// NewRunner constructs an argv runner only from a complete signed executable
// authority and mandatory native publisher verifier.
func NewRunner(
	authority argvprocess.ExecutableAuthority,
	publisher PublisherVerifier,
) (*Runner, error) {
	if !authority.Valid() || authority.Platform() != runtime.GOOS || authority.Architecture() != runtime.GOARCH ||
		nilPublisherVerifier(publisher) {
		return nil, argvprocess.ErrInvalidInvocation
	}
	return &Runner{outputLimit: defaultOutputLimit, authority: authority, publisher: publisher}, nil
}

// Run executes without a command shell, inherited environment, ambient stdin,
// or caller-controlled working directory. Optional stdin is copied from the
// bounded invocation contract.
func (r *Runner) Run(ctx context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	if r == nil || ctx == nil || !r.authority.Valid() || nilPublisherVerifier(r.publisher) {
		return argvprocess.Result{}, argvprocess.ErrInvalidInvocation
	}
	if err := ctx.Err(); err != nil {
		return argvprocess.Result{}, err
	}
	if invocation.Executable() != r.authority.CanonicalPath() {
		return argvprocess.Result{}, argvprocess.ErrInvalidInvocation
	}
	arguments := invocation.Arguments()
	lease, err := acquireExecutableLease(ctx, r.authority, r.testOnlyAllowMutablePath)
	if err != nil {
		return argvprocess.Result{}, invocationOrContextError(ctx)
	}
	defer lease.close()
	if err := lease.verify(ctx, r.authority); err != nil {
		return argvprocess.Result{}, invocationOrContextError(ctx)
	}
	evidence := lease.evidence(r.authority)
	if err := r.publisher.VerifyExecutablePublisher(ctx, r.authority, evidence); err != nil {
		return argvprocess.Result{}, invocationOrContextError(ctx)
	}
	// Publisher validation can be comparatively expensive and may invoke native
	// trust services. Re-prove every held object after it returns and before any
	// process can observe a side effect.
	if err := lease.verify(ctx, r.authority); err != nil {
		return argvprocess.Result{}, invocationOrContextError(ctx)
	}
	command, err := lease.command(ctx, arguments)
	if err != nil {
		return argvprocess.Result{}, invocationOrContextError(ctx)
	}
	environment := invocation.Environment()
	if invocation.EnvironmentProfile() == argvprocess.EnvironmentProfileRootlessSetup {
		if r.authority.Role() != argvprocess.ExecutableRoleRootlessSetup || len(environment) != 8 {
			return argvprocess.Result{}, argvprocess.ErrInvalidInvocation
		}
		command.Env = environment
	} else {
		if len(environment) != 0 || invocation.EnvironmentProfile() != argvprocess.EnvironmentProfileDefault {
			return argvprocess.Result{}, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C"}
	}
	standardInput := invocation.StandardInput()
	if len(standardInput) != 0 {
		command.Stdin = bytes.NewReader(standardInput)
	}
	command.Dir = lease.trustedWorkingDirectory()

	stdout := newBoundedBuffer(r.outputLimit)
	stderr := newBoundedBuffer(r.outputLimit)
	command.Stdout = stdout
	command.Stderr = stderr
	runError := runCommandInProcessTree(ctx, command)
	result := argvprocess.Result{
		ExitCode:        exitCode(runError),
		StandardOutput:  stdout.Bytes(),
		StandardError:   stderr.Bytes(),
		OutputTruncated: stdout.Truncated() || stderr.Truncated(),
	}
	if verifyError := lease.verify(context.WithoutCancel(ctx), r.authority); verifyError != nil {
		return result, argvprocess.ErrInvalidInvocation
	}
	if result.OutputTruncated {
		return result, argvprocess.ErrOutputLimit
	}
	if runError != nil {
		if errors.Is(runError, context.Canceled) || errors.Is(runError, context.DeadlineExceeded) || ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("argv process exited unsuccessfully: %w", runError)
	}
	return result, nil
}

func invocationOrContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return argvprocess.ErrInvalidInvocation
}

func nilPublisherVerifier(verifier PublisherVerifier) bool {
	if verifier == nil {
		return true
	}
	value := reflect.ValueOf(verifier)
	//nolint:exhaustive // Non-nilable reflection kinds are intentionally handled by default.
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError interface{ ExitCode() int }
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

type boundedBuffer struct {
	bytes     []byte
	limit     int
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit <= 0 {
		limit = defaultOutputLimit
	}
	return &boundedBuffer{bytes: make([]byte, 0, limit), limit: limit}
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - len(b.bytes)
	if remaining > 0 {
		copyLength := len(value)
		if copyLength > remaining {
			copyLength = remaining
		}
		b.bytes = append(b.bytes, value[:copyLength]...)
	}
	if len(value) > remaining {
		b.truncated = true
	}
	return len(value), nil
}

func (b *boundedBuffer) Bytes() []byte   { return append([]byte(nil), b.bytes...) }
func (b *boundedBuffer) Truncated() bool { return b.truncated }
