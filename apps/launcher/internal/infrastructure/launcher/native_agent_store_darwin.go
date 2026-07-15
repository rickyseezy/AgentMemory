//go:build darwin

package launcher

import (
	agentconfigadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/agentconfig"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
)

func newNativeAgentConfigurationStore(backupDirectory string) (agentconfigport.Store, error) {
	return agentconfigadapter.NewDarwinStore(backupDirectory)
}
