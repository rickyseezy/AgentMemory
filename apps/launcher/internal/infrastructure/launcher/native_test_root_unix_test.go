//go:build darwin || linux

package launcher

import (
	"os"
	"path/filepath"
)

func protectNativeTestRoot(root string) (string, error) {
	return filepath.EvalSymlinks(root)
}

func createNativePrivateTestDirectory(parent, name string) (string, error) {
	root := filepath.Join(parent, name)
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}
