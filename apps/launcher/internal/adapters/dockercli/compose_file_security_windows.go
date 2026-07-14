//go:build windows

package dockercli

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func privateComposePath(path string, wantDirectory bool) bool {
	file, _, err := windowssecurity.OpenVerified(context.Background(), path, wantDirectory, false, true)
	if err != nil {
		return false
	}
	return file.Close() == nil
}
