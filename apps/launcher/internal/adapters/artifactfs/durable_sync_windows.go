//go:build windows

package artifactfs

import (
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func durableSync(file *os.File) error { return windowssecurity.Flush(file) }
