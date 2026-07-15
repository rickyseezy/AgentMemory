//go:build darwin || linux

package nativepackage

import "errors"

func nativeInstalledLayout() (InstalledLayout, error) {
	switch runtimeOS() {
	case "darwin":
		return InstalledLayout{
			Launcher:             "/usr/local/bin/agentmemory",
			RuntimeHelper:        "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
			DistributionEnvelope: "/Library/Application Support/AgentMemory/resources/bundle/bootstrap/distribution-manifest.json",
		}, nil
	case "linux":
		return InstalledLayout{
			Launcher:             "/usr/libexec/agentmemory/agentmemory",
			RuntimeHelper:        "/usr/libexec/agentmemory/agentmemory-runtime-helper",
			DistributionEnvelope: "/usr/libexec/agentmemory/resources/bundle/bootstrap/distribution-manifest.json",
		}, nil
	default:
		return InstalledLayout{}, errors.New("native installed layout is unsupported")
	}
}
