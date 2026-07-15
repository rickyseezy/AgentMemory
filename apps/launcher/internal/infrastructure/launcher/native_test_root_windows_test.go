//go:build windows

package launcher

import (
	"context"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func protectNativeTestRoot(root string) (string, error) {
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	return createNativePrivateTestDirectory(base, "agentmemory-private")
}

func createNativePrivateTestDirectory(parent, name string) (string, error) {
	root := filepath.Join(parent, name)
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), root); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}
