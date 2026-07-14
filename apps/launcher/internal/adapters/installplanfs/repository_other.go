//go:build !darwin && !linux && !windows

package installplanfs

import (
	"context"
	"errors"
)

func openPlatformStore(context.Context, string) (platformStore, error) {
	return nil, errors.New("canonical plan repository platform is unsupported")
}
