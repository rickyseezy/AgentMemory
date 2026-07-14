//go:build windows

package dockercli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func ensurePrivateTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), path); err != nil && !errors.Is(err, os.ErrExist) {
		if file, _, verifyError := windowssecurity.OpenVerified(context.Background(), path, true, false, true); verifyError == nil {
			_ = file.Close()
			return
		}
		t.Fatal(err)
	}
}

func writePrivateTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		file, _, err = windowssecurity.OpenVerified(context.Background(), path, false, true, true)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(contents, 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}
