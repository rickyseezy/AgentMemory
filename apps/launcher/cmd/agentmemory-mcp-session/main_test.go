package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessionbridge"
)

func TestPF005SessionCommandMapsTransportFailureWithoutLeakingIt(t *testing.T) {
	t.Parallel()
	diagnostics := diagnosticFile(t)
	code := runWithServer(
		t.Context(),
		[]string{"--session-id", "019d2b4e-7a10-7def-8abc-0123456789ab"},
		diagnostics,
		func(context.Context, *mcpsessionbridge.Server) error { return errors.New("private transport failure") },
	)
	if code != 6 || readDiagnostics(t, diagnostics) != "AM_SESSION_UNAVAILABLE\n" {
		t.Fatalf("runWithServer()=%d diagnostics=%q", code, readDiagnostics(t, diagnostics))
	}
	if code := runWithServer(t.Context(), nil, diagnostics, nil); code != 2 {
		t.Fatalf("runWithServer(nil server)=%d", code)
	}
}

func TestPF005SessionCommandRejectsUsageAndIntegrityWithoutPanic(t *testing.T) {
	t.Parallel()
	if code := run(t.Context(), nil, nil); code != 2 {
		t.Fatalf("run(nil diagnostics)=%d", code)
	}
	diagnostics := diagnosticFile(t)
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if code := run(nil, nil, diagnostics); code != 2 { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatalf("run(nil context)=%d", code)
	}
	if code := run(t.Context(), []string{"--wrong", "value"}, diagnostics); code != 2 {
		t.Fatalf("run(wrong flag)=%d", code)
	}
	if code := run(t.Context(), []string{"--session-id", "invalid"}, diagnostics); code != 4 {
		t.Fatalf("run(invalid session)=%d", code)
	}
	assertDiagnostics(t, diagnostics, "AM_SESSION_USAGE", "AM_SESSION_INTEGRITY")
}

func TestPF005SessionCommandTreatsCancelledTransportAsGracefulShutdown(t *testing.T) {
	t.Parallel()
	diagnostics := diagnosticFile(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	code := run(
		ctx,
		[]string{"--session-id", "019d2b4e-7a10-7def-8abc-0123456789ab"},
		diagnostics,
	)
	if code != 0 {
		t.Fatalf("run(cancelled)=%d diagnostics=%q", code, readDiagnostics(t, diagnostics))
	}
	if value := readDiagnostics(t, diagnostics); value != "" {
		t.Fatalf("cancelled diagnostics=%q", value)
	}
}

func TestPF005SessionRunMainOwnsSignalContextAndArguments(t *testing.T) {
	oldArguments, oldDiagnostics := os.Args, os.Stderr
	diagnostics := diagnosticFile(t)
	os.Args = []string{"agentmemory-mcp-session", "--wrong"}
	os.Stderr = diagnostics
	t.Cleanup(func() {
		os.Args = oldArguments
		os.Stderr = oldDiagnostics
	})
	if code := runMain(); code != 2 {
		t.Fatalf("runMain()=%d", code)
	}
	assertDiagnostics(t, diagnostics, "AM_SESSION_USAGE")
}

func diagnosticFile(t testing.TB) *os.File {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "diagnostics"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func assertDiagnostics(t testing.TB, file *os.File, expected ...string) {
	t.Helper()
	value := readDiagnostics(t, file)
	for _, item := range expected {
		if !strings.Contains(value, item) {
			t.Fatalf("diagnostics=%q missing=%q", value, item)
		}
	}
}

func readDiagnostics(t testing.TB, file *os.File) string {
	t.Helper()
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
