//go:build (!linux && !darwin && !windows) || (linux && !amd64 && !arm64)

package launcher

import (
	"errors"

	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
)

func newNativeAgentConfigurationStore(string) (agentconfigport.Store, error) {
	return nil, errors.New("native agent configuration store is unavailable")
}
