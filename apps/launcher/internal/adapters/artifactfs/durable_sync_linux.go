//go:build linux

package artifactfs

import (
	"errors"
	"os"
)

func durableSync(file *os.File) error {
	if file == nil {
		return errors.New("durability descriptor is absent")
	}
	return file.Sync()
}
