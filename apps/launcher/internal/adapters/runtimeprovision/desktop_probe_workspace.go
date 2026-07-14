//go:build darwin || windows

package runtimeprovision

import "os"

func writeAndSyncDesktopProbe(file *os.File, content []byte) error {
	if file == nil {
		return ErrProbeFailed
	}
	written, err := file.Write(content)
	if err != nil || written != len(content) {
		return ErrProbeFailed
	}
	return file.Sync()
}
