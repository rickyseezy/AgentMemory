//go:build linux

package filesystem

import (
	"context"
	"os"
)

func verifyPlatformDescriptor(context.Context, *os.File) error { return nil }

func platformDurableSync(file *os.File) error { return file.Sync() }
