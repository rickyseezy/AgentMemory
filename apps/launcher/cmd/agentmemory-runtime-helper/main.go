package main

import (
	"context"
	"os"
)

var (
	runSelectedNativeHelper = runPlatformNativeHelper
	exitNativeHelper        = os.Exit
)

func nativeHelperExitCode(ctx context.Context, args []string) int {
	if runSelectedNativeHelper(ctx, args) != nil {
		return 1
	}
	return 0
}

func main() {
	exitNativeHelper(nativeHelperExitCode(context.Background(), os.Args[1:]))
}
