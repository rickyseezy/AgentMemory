//go:build windows

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func protectedSessionTestRoot(t testing.TB) (string, error) {
	t.Helper()
	root, err := protectNativeTestRoot(t.TempDir())
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}

func writeProtectedSessionTestFile(path string, value []byte) error {
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		return err
	}
	written, writeError := file.Write(value)
	flushError := windowssecurity.Flush(file)
	closeError := file.Close()
	if writeError != nil {
		return writeError
	}
	if written != len(value) {
		return os.ErrInvalid
	}
	if flushError != nil {
		return flushError
	}
	return closeError
}

func createProtectedSessionTestDirectory(parent, name string) (string, error) {
	return createNativePrivateTestDirectory(parent, name)
}
