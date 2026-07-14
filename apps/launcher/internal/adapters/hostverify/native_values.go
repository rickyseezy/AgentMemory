package hostverify

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"

func nativeArchitecture(value string) (hostverification.Architecture, bool) {
	switch value {
	case "amd64":
		return hostverification.ArchitectureAMD64, true
	case "arm64":
		return hostverification.ArchitectureARM64, true
	default:
		return "", false
	}
}
