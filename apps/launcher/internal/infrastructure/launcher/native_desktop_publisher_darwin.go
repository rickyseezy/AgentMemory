//go:build darwin

package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
)

func newNativeDesktopExecutablePublisherVerifier() (process.PublisherVerifier, error) {
	return process.NewNativePublisherVerifier(process.NativePublisherDependencies{})
}
