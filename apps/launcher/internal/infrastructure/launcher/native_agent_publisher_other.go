//go:build !linux && !darwin && !windows

package launcher

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func newNativeLauncherPublisherVerifier(
	argvprocess.ExecutableAuthority,
) (process.PublisherVerifier, error) {
	return nil, errors.New("launcher publisher verification is unavailable")
}

func nativeLauncherExecutionPolicy(
	*nativeReleaseAuthority,
	string,
	[32]byte,
) (string, string, [32]byte, error) {
	return "", "", [32]byte{}, errors.New("launcher publisher policy is unavailable")
}
