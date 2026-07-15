//go:build darwin || windows

package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func newNativeLauncherPublisherVerifier(
	argvprocess.ExecutableAuthority,
) (process.PublisherVerifier, error) {
	return newNativeDesktopExecutablePublisherVerifier()
}
