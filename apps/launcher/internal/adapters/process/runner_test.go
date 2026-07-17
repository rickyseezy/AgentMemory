//go:build !darwin || cgo

package process

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001ArgvRunnerPreservesMetacharactersAsLiteralArguments(t *testing.T) {
	t.Parallel()

	executable := testCurrentExecutable(t)
	arguments := []string{
		"-test.run=^TestPF001ArgvRunnerHelper$",
		"--",
		"emit",
		"$(touch /tmp/agentmemory-must-not-exist)",
		"; rm -rf /",
		"spaces and ünicode",
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mustTestRunner(t, executable).Run(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(arguments[3:], "\n") + "\n"
	if string(result.StandardOutput) != want || result.ExitCode != 0 {
		t.Fatalf("stdout/exit = %q/%d, want %q/0", result.StandardOutput, result.ExitCode, want)
	}
}

func TestPF001ArgvRunnerRejectsRelativeAndSymlinkExecutables(t *testing.T) {
	t.Parallel()

	executable := testCurrentExecutable(t)
	runner := mustTestRunner(t, executable)
	invocation, err := argvprocess.NewInvocation("docker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("relative executable error = %v", err)
	}

	link := filepath.Join(t.TempDir(), "linked-runner")
	if err := os.Symlink(executable, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	invocation, err = argvprocess.NewInvocation(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("symlink executable error = %v", err)
	}
}

func TestPF001ArgvRunnerRejectsCrossPlatformAndCrossArchitectureAuthorities(t *testing.T) {
	t.Parallel()
	otherPlatform := "linux"
	if runtime.GOOS == "linux" {
		otherPlatform = "darwin"
	}
	otherArchitecture := "amd64"
	if runtime.GOARCH == "amd64" {
		otherArchitecture = "arm64"
	}
	base := argvprocess.ExecutableAuthorityInput{
		CanonicalID: "cross-target", CanonicalPath: "/verified/docker",
		SHA256: sha256.Sum256([]byte("docker")), OwnerIdentity: "test-owner",
		PublisherIdentity: "test-publisher", PublisherPolicyID: "test-policy",
		PublisherTrustDigest:  sha256.Sum256([]byte("test-publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("release")),
		RuntimePlanDigest:     sha256.Sum256([]byte("plan")), Role: argvprocess.ExecutableRoleDockerCLI,
		Platform: otherPlatform, Architecture: runtime.GOARCH,
	}
	crossPlatform, err := argvprocess.NewExecutableAuthority(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(crossPlatform, testPublisherVerifier{}); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("cross-platform NewRunner() error = %v", err)
	}
	base.Platform = runtime.GOOS
	if runtime.GOOS == "windows" {
		base.CanonicalPath = `C:\verified\docker.exe`
	}
	base.Architecture = otherArchitecture
	crossArchitecture, err := argvprocess.NewExecutableAuthority(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(crossArchitecture, testPublisherVerifier{}); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("cross-architecture NewRunner() error = %v", err)
	}
}

func TestPF001ArgvRunnerBoundsOutputAndReportsTruncation(t *testing.T) {
	t.Parallel()

	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "large-output",
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := mustTestRunner(t, executable)
	runner.outputLimit = 128
	result, err := runner.Run(context.Background(), invocation)
	if !errors.Is(err, argvprocess.ErrOutputLimit) || !result.OutputTruncated {
		t.Fatalf("result/error = %+v/%v", result, err)
	}
	if len(result.StandardOutput) != 128 || len(result.StandardError) != 128 {
		t.Fatalf("bounded lengths = %d/%d", len(result.StandardOutput), len(result.StandardError))
	}
}

func TestPF001ArgvRunnerHonorsCancellation(t *testing.T) {
	t.Parallel()

	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "wait",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = mustTestRunner(t, executable).Run(ctx, invocation)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestPF001ArgvRunnerInvocationCopiesArguments(t *testing.T) {
	t.Parallel()

	arguments := []string{"version"}
	invocation, err := argvprocess.NewInvocation("/absolute/docker", arguments)
	if err != nil {
		t.Fatal(err)
	}
	arguments[0] = "system prune"
	returned := invocation.Arguments()
	returned[0] = "other"
	if invocation.Arguments()[0] != "version" {
		t.Fatal("invocation arguments were mutable through caller aliases")
	}
}

func TestPF001ArgvRunnerUsesOnlyExplicitBoundedStandardInput(t *testing.T) {
	t.Parallel()

	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocationWithStandardInput(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "copy-input",
	}, []byte("verified input;$(id)"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := mustTestRunner(t, executable).Run(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.StandardOutput) != "verified input;$(id)" {
		t.Fatalf("stdout = %q", result.StandardOutput)
	}
}

func TestPF001ArgvRunnerSequencesLineConversationAfterEachResponse(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "conversation",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation := mustLineConversation(t,
		conversationInput{line: "initialize\n", await: true},
		conversationInput{line: "initialized\n", await: false},
		conversationInput{line: "tools/list\n", await: true},
	)
	result, err := mustTestRunner(t, executable).RunLineConversation(t.Context(), invocation, conversation)
	if err != nil {
		t.Fatal(err)
	}
	if actual := string(result.StandardOutput); actual != "initialize-ok\ntools-ok\n" || result.ExitCode != 0 {
		t.Fatalf("conversation output/exit=%q/%d", actual, result.ExitCode)
	}
}

func TestPF001ArgvRunnerConversationFailsClosedOnFramingBoundsAndCancellation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		command string
		want    error
		limit   int
	}{
		{name: "unterminated response", command: "conversation-unterminated", want: argvprocess.ErrConversation},
		{name: "oversized response", command: "conversation-large", want: argvprocess.ErrOutputLimit, limit: 128},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			executable := testCurrentExecutable(t)
			invocation, err := argvprocess.NewInvocation(executable, []string{
				"-test.run=^TestPF001ArgvRunnerHelper$", "--", test.command,
			})
			if err != nil {
				t.Fatal(err)
			}
			runner := mustTestRunner(t, executable)
			if test.limit != 0 {
				runner.outputLimit = test.limit
			}
			result, err := runner.RunLineConversation(
				t.Context(), invocation,
				mustLineConversation(t, conversationInput{line: "initialize\n", await: true}),
			)
			if !errors.Is(err, test.want) || errors.Is(test.want, argvprocess.ErrOutputLimit) && !result.OutputTruncated {
				t.Fatalf("conversation result/error=%+v/%v want=%v", result, err, test.want)
			}
		})
	}

	executable := testCurrentExecutable(t)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "conversation-wait",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := mustTestRunner(t, executable).RunLineConversation(
		ctx, invocation, mustLineConversation(t, conversationInput{line: "initialize\n", await: true}),
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("conversation cancellation error=%v", err)
	}
}

func TestPF001ArgvRunnerConversationRejectsAmbientOrInvalidInput(t *testing.T) {
	t.Parallel()
	executable := testCurrentExecutable(t)
	conversation := mustLineConversation(t, conversationInput{line: "initialize\n", await: true})
	preloaded, err := argvprocess.NewInvocationWithStandardInput(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "conversation",
	}, []byte("preloaded"))
	if err != nil {
		t.Fatal(err)
	}
	runner := mustTestRunner(t, executable)
	if _, err := runner.RunLineConversation(t.Context(), preloaded, conversation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("preloaded conversation error=%v", err)
	}
	invocation, _ := argvprocess.NewInvocation(executable, nil)
	//lint:ignore SA1012 Deliberate nil-context process boundary test.
	if _, err := runner.RunLineConversation(nil, invocation, conversation); !errors.Is(err, argvprocess.ErrInvalidInvocation) { //nolint:staticcheck
		t.Fatalf("nil-context conversation error=%v", err)
	}
	if _, err := runner.RunLineConversation(t.Context(), invocation, argvprocess.LineConversation{}); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("zero conversation error=%v", err)
	}
}

type conversationInput struct {
	line  string
	await bool
}

func mustLineConversation(t testing.TB, inputs ...conversationInput) argvprocess.LineConversation {
	t.Helper()
	steps := make([]argvprocess.ConversationStep, 0, len(inputs))
	for _, input := range inputs {
		step, err := argvprocess.NewConversationStep([]byte(input.line), input.await)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, step)
	}
	conversation, err := argvprocess.NewLineConversation(steps)
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

type testPublisherVerifier struct{}

func (testPublisherVerifier) VerifyExecutablePublisher(
	_ context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	if evidence.CanonicalID != authority.CanonicalID() || evidence.Digest != authority.SHA256() ||
		evidence.OwnerIdentity != authority.OwnerIdentity() || evidence.FileIdentity == "" ||
		evidence.ReleaseManifestDigest != authority.ReleaseManifestDigest() ||
		evidence.RuntimePlanDigest != authority.RuntimePlanDigest() || evidence.Role != authority.Role() ||
		runtime.GOOS == "windows" && evidence.retainedHandle == 0 ||
		runtime.GOOS != "windows" && evidence.retainedHandle != 0 {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

func mustTestRunner(t *testing.T, executable string) *Runner {
	t.Helper()
	authority := testExecutableAuthority(t, executable)
	runner, err := NewRunner(authority, testPublisherVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	runner.testOnlyAllowMutablePath = true
	return runner
}

// TestPF001ArgvRunnerHelper executes only in child test processes.
func TestPF001ArgvRunnerHelper(_ *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(os.Args) {
		return
	}
	command := os.Args[separator+1]
	switch command {
	case "emit":
		for _, argument := range os.Args[separator+2:] {
			_, _ = os.Stdout.WriteString(argument + "\n")
		}
	case "large-output":
		_, _ = os.Stdout.WriteString(strings.Repeat("o", 512))
		_, _ = os.Stderr.WriteString(strings.Repeat("e", 512))
	case "wait":
		time.Sleep(10 * time.Second)
	case "copy-input":
		_, _ = os.Stdout.ReadFrom(os.Stdin)
	case "conversation":
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || scanner.Text() != "initialize" {
			os.Exit(21)
		}
		_, _ = os.Stdout.WriteString("initialize-ok\n")
		if !scanner.Scan() || scanner.Text() != "initialized" || !scanner.Scan() || scanner.Text() != "tools/list" {
			os.Exit(22)
		}
		_, _ = os.Stdout.WriteString("tools-ok\n")
	case "conversation-unterminated":
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			os.Exit(23)
		}
		_, _ = os.Stdout.WriteString("unterminated")
	case "conversation-large":
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			os.Exit(24)
		}
		_, _ = os.Stdout.WriteString(strings.Repeat("o", 512) + "\n")
	case "conversation-wait":
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			os.Exit(25)
		}
		time.Sleep(10 * time.Second)
	case "ignore-termination":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals)
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(10 * time.Second)
		signal.Stop(signals)
	case "rename-path":
		//nolint:gosec // G703: parent test supplies the isolated executable fixture path intentionally.
		if separator+2 >= len(os.Args) || os.Rename(os.Args[separator+2], os.Args[separator+2]+".retained") != nil {
			os.Exit(19)
		}
		_, _ = os.Stdout.WriteString("renamed\n")
	case "spawn-child":
		//nolint:gosec // G702: current signed test executable and fixed child argv.
		child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestPF001ArgvRunnerHelper$", "--", "wait") // #nosec G204 -- current test executable and fixed argv.
		if err := child.Start(); err != nil {
			os.Exit(18)
		}
		_, _ = os.Stdout.WriteString(strconv.Itoa(child.Process.Pid) + "\n")
		//nolint:gosec // G703: parent supplies an isolated marker path to the test helper.
		if len(os.Args) <= separator+2 || os.WriteFile(os.Args[separator+2], []byte("started"), 0o600) != nil {
			os.Exit(19)
		}
		time.Sleep(10 * time.Second)
	case "spawn-child-and-exit":
		//nolint:gosec // G702: current signed test executable and fixed child argv.
		child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestPF001ArgvRunnerHelper$", "--", "wait") // #nosec G204 -- current test executable and fixed argv.
		if err := child.Start(); err != nil {
			os.Exit(18)
		}
		_, _ = os.Stdout.WriteString(strconv.Itoa(child.Process.Pid) + "\n")
	default:
		os.Exit(17)
	}
	os.Exit(0)
}
