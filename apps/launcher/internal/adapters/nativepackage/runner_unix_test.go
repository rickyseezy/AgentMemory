//go:build darwin || linux

package nativepackage

import (
	"context"
	"errors"
	"testing"
)

func TestPF001UnixNativeCommandExecutionSettlesSuccessExitAndCancellation(t *testing.T) {
	t.Parallel()
	if code, err := executeNativeCommand(context.Background(), Command{Executable: "/usr/bin/true"}); err != nil || code != 0 {
		t.Fatalf("true = %d, %v", code, err)
	}
	if code, err := executeNativeCommand(context.Background(), Command{Executable: "/usr/bin/false"}); err != nil || code != 1 {
		t.Fatalf("false = %d, %v", code, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if code, err := executeNativeCommand(cancelled, Command{Executable: "/usr/bin/true"}); code != -1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %d, %v", code, err)
	}
	if code, err := executeNativeCommand(context.Background(), Command{}); code != -1 ||
		!errors.Is(err, ErrInstallation) {
		t.Fatalf("empty command = %d, %v", code, err)
	}
	if code, err := executeNativeCommand(
		context.Background(), Command{Executable: "/definitely/missing/agentmemory-test"},
	); code != -1 || !errors.Is(err, ErrInstallation) {
		t.Fatalf("missing executable = %d, %v", code, err)
	}
}
