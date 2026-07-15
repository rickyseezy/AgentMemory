//go:build !darwin && !windows

package launcher

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
)

func newNativeDesktopExecutablePublisherVerifier() (process.PublisherVerifier, error) {
	return nil, errors.New("desktop executable publisher verification is unavailable")
}
