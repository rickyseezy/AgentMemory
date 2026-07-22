package launcher

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

func TestPF005SessionRunnerRejectsPartialComposition(t *testing.T) {
	t.Parallel()
	if runner, err := NewSessionRunner(nil, agentconfig.AgentHostCodex); runner != nil || err == nil {
		t.Fatalf("NewSessionRunner(nil)=%+v/%v", runner, err)
	}
	if runner, err := NewSessionRunner(&sessionApplicationStub{}, "unknown"); runner != nil || err == nil {
		t.Fatalf("NewSessionRunner(unknown)=%+v/%v", runner, err)
	}
	var nilRunner *sessionRunner
	if err := nilRunner.RunHostSession(
		context.Background(), "/workspace", bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); err == nil {
		t.Fatal("nil session runner accepted")
	}
}

func TestPF005SessionRunnerPreservesCwdAndProtocolDiagnosticStreams(t *testing.T) {
	t.Parallel()
	application := &sessionApplicationStub{}
	raw, err := NewSessionRunner(application, agentconfig.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	runner := raw.(HostSessionRunner)
	input := strings.NewReader("MCP frame\n")
	var output, diagnostics bytes.Buffer
	if err := runner.RunHostSession(
		t.Context(), "/workspace [α];$(false)", input, &output, &diagnostics,
	); err != nil {
		t.Fatal(err)
	}
	if application.command.AgentID != "codex" ||
		application.command.WorkingDirectory != "/workspace [α];$(false)" ||
		application.command.Input != input || application.command.Output != &output ||
		application.command.Diagnostics != &diagnostics {
		t.Fatalf("command=%+v", application.command)
	}
	application.err = errors.New("private child detail")
	if err := runner.RunHostSession(
		t.Context(), "/workspace", input, &output, &diagnostics,
	); err == nil {
		t.Fatal("application failure hidden")
	}
}

func TestPF005ManagedSessionClosesNativeResourcesAfterRawStdio(t *testing.T) {
	t.Parallel()
	application := &sessionApplicationStub{}
	lifecycle := &sessionLifecycleStub{}
	raw, err := NewManagedSessionRunner(application, agentconfig.AgentHostCodex, lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := newManagedRunner(t.Context(), bootstrapSurface{
		session: raw, lifecycle: sessionLifecycle(raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	host, ok := managed.(HostSessionRunner)
	if !ok {
		t.Fatalf("managed runner type=%T", managed)
	}
	if err := host.RunHostSession(
		t.Context(), "/workspace", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	if lifecycle.calls != 1 {
		t.Fatalf("lifecycle closes=%d", lifecycle.calls)
	}
}

func TestPF005SessionRunnerRejectsGenericTransportAndOwnsLifecycleErrors(t *testing.T) {
	t.Parallel()
	application := &sessionApplicationStub{}
	raw, err := NewSessionRunner(application, agentconfig.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Run(t.Context(), nil); err == nil {
		t.Fatal("generic MCP transport accepted")
	}
	closer := raw.(RuntimeLifecycle)
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if err := closer.Close(nil); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("nil close context accepted")
	}
	if err := closer.Close(t.Context()); err != nil {
		t.Fatalf("standalone Close()=%v", err)
	}
	if err := raw.(HostSessionRunner).RunHostSession(
		//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
		nil, "/workspace", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, //nolint:staticcheck // Deliberate invalid boundary.
	); err == nil {
		t.Fatal("nil host session context accepted")
	}

	if _, err := NewManagedSessionRunner(application, agentconfig.AgentHostCodex, nil); err == nil {
		t.Fatal("nil managed lifecycle accepted")
	}
	if _, err := NewManagedSessionRunner(nil, agentconfig.AgentHostCodex, &sessionLifecycleStub{}); err == nil {
		t.Fatal("invalid application accepted by managed runner")
	}
	lifecycle := &sessionLifecycleStub{err: errors.New("close failed")}
	managed, err := NewManagedSessionRunner(application, agentconfig.AgentHostCodex, lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.(RuntimeLifecycle).Close(t.Context()); !errors.Is(err, lifecycle.err) {
		t.Fatalf("managed Close()=%v", err)
	}
}

type sessionApplicationStub struct {
	command mcpsessionapp.Command
	result  mcpsessionapp.Result
	err     error
}

type sessionLifecycleStub struct {
	calls int
	err   error
}

func (s *sessionLifecycleStub) Close(context.Context) error {
	s.calls++
	return s.err
}

func (s *sessionApplicationStub) Start(
	_ context.Context,
	command mcpsessionapp.Command,
) (mcpsessionapp.Result, error) {
	s.command = command
	return s.result, s.err
}
