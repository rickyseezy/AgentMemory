//go:build !darwin || cgo

package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001ExecutionMaterializationRejectsUnsafeFilesAndParserInput(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "managed")
	if err := createPrivateExecutionDirectory(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(directory, "empty")
	writePrivateTestFile(t, empty, nil)
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if _, err := readPrivateExecutionFile(nil, empty, true, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("nil context read error = %v", err)
	}
	if _, err := readPrivateExecutionFile(context.Background(), empty, false, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty secret read error = %v", err)
	}
	if contents, err := readPrivateExecutionFile(context.Background(), empty, true, 1); err != nil || len(contents) != 0 {
		t.Fatalf("empty environment read = %q/%v", contents, err)
	}
	value := filepath.Join(directory, "value")
	writePrivateTestFile(t, value, []byte("ab"))
	if _, err := readPrivateExecutionFile(context.Background(), value, false, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("oversized protected input error = %v", err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(value, link); err == nil {
		if _, err := readPrivateExecutionFile(context.Background(), link, false, 8); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
			t.Fatalf("linked protected input error = %v", err)
		}
	}
	if err := writeComplete(nil, []byte("x")); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("nil materialization error = %v", err)
	}
	for _, malformed := range [][]byte{[]byte("{"), []byte("{} {}")} {
		if _, err := escapeComposeInterpolation(malformed); err == nil {
			t.Fatalf("malformed execution JSON %q was accepted", malformed)
		}
	}
}

func TestPF001ExecutionMaterializationReusesOnlyIdenticalNoReplaceFiles(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "managed")
	if err := createPrivateExecutionDirectory(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bound-secret")
	contents := []byte("bound-value")
	directoryHandle, err := openPrivateExecutionDirectory(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directoryHandle.Close() }()
	first, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, contents, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Production materialization is serialized by the machine-global install
	// lock and releases the write authority before a durable replay begins.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, contents, false,
	)
	if err != nil {
		t.Fatalf("identical materialization reuse: %v", err)
	}
	defer func() { _ = second.Close() }()
	third, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, []byte("other"), false,
	)
	if !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("non-identical materialization error = %v", err)
	}
	if third != nil {
		_ = third.Close()
		t.Fatal("content-mismatched materialization returned authority")
	}
	notDirectory := filepath.Join(directory, "not-directory")
	writePrivateTestFile(t, notDirectory, []byte("x"))
	if err := errEnsureExecutionDirectory(context.Background(), notDirectory); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("file-as-directory error = %v", err)
	}
}

func TestPF001BoundExecutionFailsBeforeMutationAndCanBeReused(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "bound-reuse")
	runner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {}, {},
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {}, {},
	}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatalf("reuse bound generation: %v", err)
	}
	if len(runner.invocations) != 8 {
		t.Fatalf("reused invocation count = %d", len(runner.invocations))
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledRunner := &composeRunner{}
	cancelledCompose, _ := NewCompose(testExecutorsForCompose(t, cancelledRunner))
	if _, err := cancelledCompose.VerifyConfiguration(cancelled, project); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) || len(cancelledRunner.invocations) != 0 {
		t.Fatalf("pre-cancelled verification error/calls = %v/%d", err, len(cancelledRunner.invocations))
	}
	if _, err := prepareBoundComposeExecution(cancelled, project, rendered, validExecutionSecretValues()); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("cancelled binding error = %v", err)
	}
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if _, err := prepareBoundComposeExecution(nil, project, rendered, validExecutionSecretValues()); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("nil-context binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, nil, validExecutionSecretValues()); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty canonical binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, []byte("{"), validExecutionSecretValues()); !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
		t.Fatalf("invalid canonical binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, rendered, nil); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty secret binding error = %v", err)
	}
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if err := compose.runBound(nil, project, boundComposeExecution{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context bound run error = %v", err)
	}
	oversized, err := prepareBoundComposeExecution(
		context.Background(), project, rendered, validExecutionSecretValues(),
	)
	if err != nil {
		t.Fatal(err)
	}
	oversized.configuration = []byte(strings.Repeat("x", maximumDockerJSON+1))
	if err := compose.runBound(context.Background(), project, oversized, nil); !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("oversized bound invocation error = %v", err)
	}
}

func TestPF001BoundExecutionRejectsEmptySecretAndRootCollision(t *testing.T) {
	t.Parallel()

	for _, collision := range []bool{false, true} {
		collision := collision
		t.Run(map[bool]string{false: "empty-secret", true: "root-collision"}[collision], func(t *testing.T) {
			t.Parallel()
			project, rendered := composeFixture(t, "bound-failure")
			if collision {
				writePrivateTestFile(t, filepath.Join(project.ProjectDirectory(), executionMaterializationRoot), []byte("x"))
			} else {
				secret := filepath.Join(project.ProjectDirectory(), executionSecretName)
				if err := os.Truncate(secret, 0); err != nil {
					t.Fatal(err)
				}
			}
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if err := compose.StartAndWait(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
				t.Fatalf("bound failure error = %v", err)
			}
			wantInvocations := 0
			if collision {
				wantInvocations = 1
			}
			if len(runner.invocations) != wantInvocations {
				t.Fatalf("bound failure used %d invocations, want %d", len(runner.invocations), wantInvocations)
			}
		})
	}
}

func TestPF001BoundExecutionRejectsEverySecretSubstitutionAndInvalidAuthorityShape(t *testing.T) {
	t.Parallel()
	project, rendered := composeFixture(t, "bound-secret-policy")
	valid := validExecutionSecretValues()
	for name, mutate := range map[string]func(map[string][]byte){
		"unknown name": func(values map[string][]byte) {
			delete(values, executionSecretName)
			values["foreign-secret"] = make([]byte, 32)
		},
		"zero key":  func(values map[string][]byte) { values[executionSecretName] = make([]byte, 32) },
		"short key": func(values map[string][]byte) { values[executionSecretName] = make([]byte, 31) },
		"oversized key": func(values map[string][]byte) {
			values[executionSecretName] = make([]byte, maximumExecutionSecretBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := validExecutionSecretValues()
			mutate(values)
			if execution, err := prepareBoundComposeExecution(context.Background(), project, rendered, values); err == nil {
				execution.authority.close()
				t.Fatal("substituted secret set accepted")
			}
		})
	}
	if execution, err := prepareBoundComposeExecution(
		context.Background(), project, []byte(strings.Repeat("x", maximumDockerJSON+1)), valid,
	); err == nil {
		execution.authority.close()
		t.Fatal("oversized canonical configuration accepted")
	}
	for _, test := range []struct {
		name  string
		value []byte
		valid bool
	}{
		{"root key", bytesOf(0x11, 32), true},
		{"zero", make([]byte, 32), false},
		{"short", bytesOf(0x11, 31), false},
		{"unknown", bytesOf(0x11, 32), false},
		{"egress", []byte("attestation"), true},
		{"egress empty", nil, false},
		{"gateway capability", bytesOf(0x22, 32), true},
		{"gateway capability zero", make([]byte, 32), false},
		{"credential vault", []byte("{}"), true},
		{"credential vault empty", nil, false},
		{"credential vault oversized", make([]byte, maximumExecutionSecretBytes+1), false},
	} {
		name := executionSecretName
		switch {
		case test.name == "unknown":
			name = "unknown"
		case strings.HasPrefix(test.name, "egress"):
			name = composeplan.SecretEgressAttestation
		case strings.HasPrefix(test.name, "gateway"):
			name = composeplan.SecretProviderGatewayClientCapability
		case strings.HasPrefix(test.name, "credential vault"):
			name = composeplan.SecretProviderGatewayCredentialVault
		}
		if got := validExecutionSecret(name, test.value); got != test.valid {
			t.Fatalf("validExecutionSecret(%s)=%v", test.name, got)
		}
	}
	if authority, err := newExecutionMaterializationAuthority(
		context.Background(), "", nil, "", nil, nil, nil, nil, nil,
	); authority != nil || !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty authority=%v,%v", authority, err)
	}
	var absent *executionMaterializationAuthority
	if err := absent.verify(context.Background()); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("nil authority verify=%v", err)
	}
	absent.close()
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
