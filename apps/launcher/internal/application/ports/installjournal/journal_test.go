package installjournal_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

func TestPF001TypedErrorsSupportStandardErrorInspection(t *testing.T) {
	t.Parallel()

	cause := io.ErrClosedPipe
	err := journalport.NewError(journalport.ErrorCorrupt, "verify", cause)
	if !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("errors.Is(_, ErrCorrupt) = false: %v", err)
	}
	if errors.Is(err, journalport.ErrNotFound) {
		t.Fatalf("corrupt error unexpectedly matches ErrNotFound: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("typed error does not unwrap its cause: %v", err)
	}
	if !strings.Contains(err.Error(), "verify: corrupt") {
		t.Fatalf("error message omits operation/code: %v", err)
	}
}

func TestPF001TypedErrorWithoutCauseIsSafe(t *testing.T) {
	t.Parallel()

	err := journalport.NewError(journalport.ErrorNotFound, "load", nil)
	if !errors.Is(err, journalport.ErrNotFound) {
		t.Fatalf("errors.Is(_, ErrNotFound) = false: %v", err)
	}
	if err.Error() != "install journal load: not_found" {
		t.Fatalf("error message = %q", err.Error())
	}
}

func TestPF001NilTypedErrorFormattingDoesNotPanic(t *testing.T) {
	t.Parallel()

	var err *journalport.Error
	if err.Error() != "<nil>" {
		t.Fatalf("nil typed error message = %q", err.Error())
	}
}
