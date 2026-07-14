//go:build windows

package installplanfs

import (
	"context"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func securePublishedPlanFile(t *testing.T, path string, info os.FileInfo) bool {
	t.Helper()
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	file, _, err := windowssecurity.OpenVerified(context.Background(), path, false, false, true)
	if err != nil {
		return false
	}
	return file.Close() == nil
}
