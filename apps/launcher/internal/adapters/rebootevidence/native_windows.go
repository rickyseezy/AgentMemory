//go:build windows

package rebootevidence

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func platformOpenNativeObject(ctx context.Context, path string, executable bool) (*os.File, error) {
	// The user-owned launcher may inherit read/execute ACEs required by its host;
	// the operation journal must retain the strict owner-only DACL.
	file, _, err := windowssecurity.OpenVerified(ctx, path, false, false, !executable)
	return file, err
}
