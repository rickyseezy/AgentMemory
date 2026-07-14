package process

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type pointerPublisherVerifier struct{}

type publisherVerifierFunc func(
	context.Context,
	argvprocess.ExecutableAuthority,
	ExecutableEvidence,
) error

func (f publisherVerifierFunc) VerifyExecutablePublisher(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	return f(ctx, authority, evidence)
}

func (*pointerPublisherVerifier) VerifyExecutablePublisher(
	context.Context,
	argvprocess.ExecutableAuthority,
	ExecutableEvidence,
) error {
	return nil
}

func TestPF001ArgvRunnerRejectsNilReceiverAndContext(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, nil)
	if err != nil {
		t.Fatal(err)
	}
	var runner *Runner
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("nil runner error = %v", err)
	}
	runner = mustTestRunner(t, executable)
	//lint:ignore SA1012 Deliberate nil-context attack proves the public runner fails closed.
	//nolint:staticcheck // SA1012: deliberate nil-context attack; owner=security expiry=2027-07-14.
	if _, err := runner.Run(nil, invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestPF001ArgvRunnerPropagatesPrelaunchCancellation(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := mustTestRunner(t, executable).Run(ctx, invocation); !errors.Is(err, context.Canceled) {
		t.Fatalf("prelaunch cancellation error = %v", err)
	}
}

func TestPF001ArgvRunnerAuthorityIsImmutableAndNilSafe(t *testing.T) {
	t.Parallel()
	var nilRunner *Runner
	if nilRunner.ExecutableAuthority().Valid() {
		t.Fatal("nil runner exposed a valid authority")
	}
	executable := testCurrentExecutable(t)
	runner := mustTestRunner(t, executable)
	if !runner.ExecutableAuthority().Equal(testExecutableAuthority(t, executable)) {
		t.Fatal("runner did not return its exact immutable authority")
	}
}

func TestPF001ArgvRunnerRequiresConcretePublisherVerifier(t *testing.T) {
	t.Parallel()
	authority := testExecutableAuthority(t, testCurrentExecutable(t))
	if _, err := NewRunner(authority, nil); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("nil verifier error = %v", err)
	}
	var typedNil *pointerPublisherVerifier
	if _, err := NewRunner(authority, typedNil); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("typed-nil verifier error = %v", err)
	}
}

func TestPF001ArgvRunnerRejectsPublisherDenialBeforeLaunch(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	authority := testExecutableAuthority(t, executable)
	runner, err := NewRunner(authority, publisherVerifierFunc(func(
		context.Context,
		argvprocess.ExecutableAuthority,
		ExecutableEvidence,
	) error {
		return errors.New("publisher denied")
	}))
	if err != nil {
		t.Fatal(err)
	}
	runner.testOnlyAllowMutablePath = true
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "emit", "must-not-run",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), invocation)
	if !errors.Is(err, argvprocess.ErrInvalidInvocation) || len(result.StandardOutput) != 0 {
		t.Fatalf("publisher denial result/error = %+v/%v", result, err)
	}
}

func TestPF001ArgvRunnerReportsExactNonzeroExit(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "fail",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mustTestRunner(t, executable).Run(context.Background(), invocation)
	if err == nil || result.ExitCode != 17 {
		t.Fatalf("failure result/error = %+v/%v", result, err)
	}
}

func TestPF001ArgvRunnerPrimitiveDecisions(t *testing.T) {
	t.Parallel()
	if exitCode(errors.New("not an exit status")) != -1 {
		t.Fatal("generic process error acquired an exit status")
	}
	buffer := newBoundedBuffer(0)
	if buffer.limit != defaultOutputLimit {
		t.Fatalf("default buffer limit = %d", buffer.limit)
	}
	buffer = newBoundedBuffer(2)
	if written, err := buffer.Write([]byte("abcd")); err != nil || written != 4 {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if written, err := buffer.Write([]byte("e")); err != nil || written != 1 {
		t.Fatalf("write after saturation = %d, %v", written, err)
	}
	if got := string(buffer.Bytes()); got != "ab" || !buffer.Truncated() {
		t.Fatalf("bounded buffer = %q, truncated=%v", got, buffer.Truncated())
	}
}
