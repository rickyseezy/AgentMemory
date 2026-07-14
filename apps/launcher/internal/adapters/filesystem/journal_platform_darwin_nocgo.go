//go:build darwin && !cgo

package filesystem

import (
	"context"
	"errors"
	"os"
)

var errDarwinFilesystemProofUnavailable = errors.New("native Darwin ACL and F_FULLFSYNC proof requires cgo")

func verifyPlatformDescriptor(context.Context, *os.File) error {
	return errDarwinFilesystemProofUnavailable
}

func platformDurableSync(*os.File) error { return errDarwinFilesystemProofUnavailable }
