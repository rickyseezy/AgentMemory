// Package process implements constrained host argv execution.
package process

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os/exec"
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
	// retainedHandle is the exact open executable object held by the lease.
	// It is consumed only by native code in this package and is never caller
	// supplied or persisted as release evidence.
	retainedHandle uintptr
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
	command, lease, err := r.prepareCommand(ctx, invocation)
	if err != nil {
		return argvprocess.Result{}, err
	}
	defer lease.close()
	standardInput := invocation.StandardInput()
	if len(standardInput) != 0 {
		command.Stdin = bytes.NewReader(standardInput)
	}

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

// RunStreaming executes one verified process with exact caller-owned stdio.
// It preserves the same executable lease, native publisher proof, scrubbed
// environment, process-tree cancellation, and post-execution identity check as Run.
func (r *Runner) RunStreaming(
	ctx context.Context,
	invocation argvprocess.Invocation,
	streams argvprocess.Streams,
) error {
	if !streams.Valid() || len(invocation.StandardInput()) != 0 {
		return argvprocess.ErrInvalidInvocation
	}
	command, lease, err := r.prepareCommand(ctx, invocation)
	if err != nil {
		return err
	}
	defer lease.close()
	command.Stdin = &streamingInput{Reader: streams.Input()}
	command.Stdout = streams.Output()
	command.Stderr = streams.Diagnostics()
	runError := runCommandInProcessTree(ctx, command)
	if verifyError := lease.verify(context.WithoutCancel(ctx), r.authority); verifyError != nil {
		return argvprocess.ErrInvalidInvocation
	}
	if runError != nil {
		if errors.Is(runError, context.Canceled) || errors.Is(runError, context.DeadlineExceeded) ||
			ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("argv streaming process exited unsuccessfully: %w", runError)
	}
	return nil
}

func (r *Runner) prepareCommand(
	ctx context.Context,
	invocation argvprocess.Invocation,
) (*exec.Cmd, *executableLease, error) {
	if r == nil || ctx == nil || !r.authority.Valid() || nilPublisherVerifier(r.publisher) {
		return nil, nil, argvprocess.ErrInvalidInvocation
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if invocation.Executable() != r.authority.CanonicalPath() {
		return nil, nil, argvprocess.ErrInvalidInvocation
	}
	arguments := invocation.Arguments()
	lease, err := acquireExecutableLease(ctx, r.authority, r.testOnlyAllowMutablePath)
	if err != nil {
		return nil, nil, invocationOrContextError(ctx)
	}
	failed := true
	defer func() {
		if failed {
			lease.close()
		}
	}()
	if err := lease.verify(ctx, r.authority); err != nil {
		return nil, nil, invocationOrContextError(ctx)
	}
	evidence := lease.evidence(r.authority)
	if err := r.publisher.VerifyExecutablePublisher(ctx, r.authority, evidence); err != nil {
		return nil, nil, invocationOrContextError(ctx)
	}
	// Publisher validation can be comparatively expensive and may invoke native
	// trust services. Re-prove every held object after it returns and before any
	// process can observe a side effect.
	if err := lease.verify(ctx, r.authority); err != nil {
		return nil, nil, invocationOrContextError(ctx)
	}
	command, err := lease.command(ctx, arguments)
	if err != nil {
		return nil, nil, invocationOrContextError(ctx)
	}
	environment := invocation.Environment()
	switch invocation.EnvironmentProfile() {
	case argvprocess.EnvironmentProfileAPTTransaction:
		if r.authority.Role() != argvprocess.ExecutableRoleAPTTransaction || len(environment) != 5 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = environment
	case argvprocess.EnvironmentProfileDNFTransaction:
		if r.authority.Role() != argvprocess.ExecutableRoleDNFTransaction || len(environment) != 4 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = environment
	case argvprocess.EnvironmentProfilePackageQuery:
		if r.authority.Role() != argvprocess.ExecutableRoleDPKGQuery &&
			r.authority.Role() != argvprocess.ExecutableRoleRPMQuery || len(environment) != 0 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C"}
	case argvprocess.EnvironmentProfileLoginCTL:
		if r.authority.Role() != argvprocess.ExecutableRoleLoginCTL || len(environment) != 0 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C"}
	case argvprocess.EnvironmentProfileSystemCTL:
		if r.authority.Role() != argvprocess.ExecutableRoleSystemCTL || len(environment) != 0 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_PAGERSECURE=1"}
	case argvprocess.EnvironmentProfileRootlessSetup:
		if r.authority.Role() != argvprocess.ExecutableRoleRootlessSetup || len(environment) != 8 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = environment
	case argvprocess.EnvironmentProfilePrivilegeBroker:
		if r.authority.Role() != argvprocess.ExecutableRolePrivilegeBroker || len(environment) != 0 {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C"}
	case argvprocess.EnvironmentProfileDefault:
		if len(environment) != 0 || r.authority.Role() == argvprocess.ExecutableRoleAPTTransaction ||
			r.authority.Role() == argvprocess.ExecutableRoleDNFTransaction ||
			r.authority.Role() == argvprocess.ExecutableRoleDPKGQuery ||
			r.authority.Role() == argvprocess.ExecutableRoleRPMQuery ||
			r.authority.Role() == argvprocess.ExecutableRoleLoginCTL ||
			r.authority.Role() == argvprocess.ExecutableRoleSystemCTL {
			return nil, nil, argvprocess.ErrInvalidInvocation
		}
		command.Env = []string{"LANG=C", "LC_ALL=C"}
	default:
		return nil, nil, argvprocess.ErrInvalidInvocation
	}
	command.Dir = lease.trustedWorkingDirectory()
	failed = false
	return command, lease, nil
}

type conversationPipeReader struct{ *io.PipeReader }
type conversationPipeWriter struct{ *io.PipeWriter }
type streamingInput struct{ io.Reader }

// RunLineConversation executes one bounded request/response sequence. It
// writes the next gated request only after one newline-delimited response has
// been received, preserving protocols whose initialization is stateful.
func (r *Runner) RunLineConversation(
	ctx context.Context,
	invocation argvprocess.Invocation,
	conversation argvprocess.LineConversation,
) (argvprocess.Result, error) {
	steps := conversation.Steps()
	validated, err := argvprocess.NewLineConversation(steps)
	if ctx == nil || err != nil || len(invocation.StandardInput()) != 0 {
		return argvprocess.Result{}, argvprocess.ErrInvalidInvocation
	}
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command, lease, err := r.prepareCommand(sessionContext, invocation)
	if err != nil {
		return argvprocess.Result{}, err
	}
	defer lease.close()

	childInput, requestWriter := io.Pipe()
	responseReader, childOutput := io.Pipe()
	command.Stdin = &conversationPipeReader{PipeReader: childInput}
	command.Stdout = &conversationPipeWriter{PipeWriter: childOutput}
	stderr := newBoundedBuffer(r.outputLimit)
	command.Stderr = stderr
	stopPipeWatch := make(chan struct{})
	pipeWatchComplete := make(chan struct{})
	go func() {
		defer close(pipeWatchComplete)
		select {
		case <-sessionContext.Done():
			_ = requestWriter.CloseWithError(sessionContext.Err())
			_ = responseReader.CloseWithError(sessionContext.Err())
		case <-stopPipeWatch:
		}
	}()
	defer func() {
		close(stopPipeWatch)
		<-pipeWatchComplete
	}()
	completed := make(chan error, 1)
	go func() {
		runError := runCommandInProcessTree(sessionContext, command)
		_ = childInput.CloseWithError(runError)
		_ = childOutput.Close()
		completed <- runError
	}()

	stdout := newBoundedBuffer(r.outputLimit)
	reader := bufio.NewReaderSize(responseReader, 4096)
	conversationError := runLineConversation(requestWriter, reader, stdout, validated.Steps(), r.outputLimit)
	if conversationError != nil {
		cancel()
		_ = requestWriter.CloseWithError(conversationError)
		_ = responseReader.CloseWithError(conversationError)
	} else {
		_ = requestWriter.Close()
	}
	runError := <-completed
	_ = responseReader.Close()
	result := argvprocess.Result{
		ExitCode:        exitCode(runError),
		StandardOutput:  stdout.Bytes(),
		StandardError:   stderr.Bytes(),
		OutputTruncated: stdout.Truncated() || stderr.Truncated(),
	}
	if verifyError := lease.verify(context.WithoutCancel(ctx), r.authority); verifyError != nil {
		return result, argvprocess.ErrInvalidInvocation
	}
	if result.OutputTruncated || errors.Is(conversationError, argvprocess.ErrOutputLimit) {
		result.OutputTruncated = true
		return result, argvprocess.ErrOutputLimit
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if conversationError != nil {
		return result, argvprocess.ErrConversation
	}
	if runError != nil {
		return result, fmt.Errorf("argv process exited unsuccessfully: %w", runError)
	}
	return result, nil
}

func runLineConversation(
	requestWriter *io.PipeWriter,
	reader *bufio.Reader,
	stdout *boundedBuffer,
	steps []argvprocess.ConversationStep,
	limit int,
) error {
	if requestWriter == nil || reader == nil || stdout == nil || len(steps) == 0 || limit <= 0 {
		return argvprocess.ErrInvalidInvocation
	}
	for _, step := range steps {
		if _, err := requestWriter.Write(step.Request()); err != nil {
			return argvprocess.ErrConversation
		}
		if !step.AwaitResponse() {
			continue
		}
		line, err := readBoundedProtocolLine(reader, limit)
		if err != nil {
			return err
		}
		_, _ = stdout.Write(line)
		if stdout.Truncated() {
			return argvprocess.ErrOutputLimit
		}
	}
	if err := requestWriter.Close(); err != nil {
		return argvprocess.ErrConversation
	}
	for {
		line, err := readBoundedProtocolLine(reader, limit)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, _ = stdout.Write(line)
		if stdout.Truncated() {
			return argvprocess.ErrOutputLimit
		}
	}
}

func readBoundedProtocolLine(reader *bufio.Reader, limit int) ([]byte, error) {
	if reader == nil || limit <= 0 {
		return nil, argvprocess.ErrInvalidInvocation
	}
	line := make([]byte, 0, min(limit, 4096))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > limit-len(line) {
			return nil, argvprocess.ErrOutputLimit
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, argvprocess.ErrConversation
		default:
			return nil, argvprocess.ErrConversation
		}
	}
}

var _ argvprocess.ConversationRunner = (*Runner)(nil)

func closeConversationInput(command *exec.Cmd) {
	if command == nil {
		return
	}
	if input, ok := command.Stdin.(*conversationPipeReader); ok && input != nil && input.PipeReader != nil {
		_ = input.Close()
	}
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
