package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

func TestPF001NativeHelperExitContract(t *testing.T) {
	originalRun := runSelectedNativeHelper
	originalExit := exitNativeHelper
	originalArgs := slices.Clone(os.Args)
	t.Cleanup(func() {
		runSelectedNativeHelper = originalRun
		exitNativeHelper = originalExit
		os.Args = originalArgs
	})

	var observed []string
	runSelectedNativeHelper = func(_ context.Context, args []string) error {
		observed = slices.Clone(args)
		return nil
	}
	if code := nativeHelperExitCode(context.Background(), []string{"--request", "value"}); code != 0 {
		t.Fatalf("success exit code=%d", code)
	}
	runSelectedNativeHelper = func(context.Context, []string) error { return errors.New("rejected") }
	if code := nativeHelperExitCode(context.Background(), nil); code != 1 {
		t.Fatalf("failure exit code=%d", code)
	}

	runSelectedNativeHelper = func(_ context.Context, args []string) error {
		observed = slices.Clone(args)
		return nil
	}
	exited := -1
	exitNativeHelper = func(code int) { exited = code }
	os.Args = []string{"agentmemory-runtime-helper", "--request-file", "request.json"}
	main()
	if exited != 0 || !slices.Equal(observed, os.Args[1:]) {
		t.Fatalf("main exit=%d args=%v", exited, observed)
	}
}
