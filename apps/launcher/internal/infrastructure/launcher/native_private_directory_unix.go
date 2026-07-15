//go:build darwin || linux

package launcher

import (
	"context"
	"errors"
	"os"
)

func ensureNativePrivateDirectory(ctx context.Context, path string) error {
	if ctx == nil {
		return errors.New("native private directory context is absent")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}
