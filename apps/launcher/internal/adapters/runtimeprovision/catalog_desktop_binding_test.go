package runtimeprovision

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestNativeDesktopBindingRequestClosesArtifactVocabulary(t *testing.T) {
	t.Parallel()
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	tests := []struct {
		name     string
		digest   runtimecatalog.Digest
		artifact string
		platform runtimeinstall.Platform
		valid    bool
	}{
		{name: "mac", digest: digest, artifact: "Docker.dmg", platform: runtimeinstall.PlatformDarwin, valid: true},
		{name: "windows", digest: digest, artifact: "Docker Desktop Installer.exe", platform: runtimeinstall.PlatformWindows, valid: true},
		{name: "zero digest", artifact: "Docker.dmg", platform: runtimeinstall.PlatformDarwin},
		{name: "cross extension", digest: digest, artifact: "Docker.exe", platform: runtimeinstall.PlatformDarwin},
		{name: "traversal", digest: digest, artifact: "../Docker.dmg", platform: runtimeinstall.PlatformDarwin},
		{name: "separator", digest: digest, artifact: `nested\\Docker.exe`, platform: runtimeinstall.PlatformWindows},
		{name: "alternate stream", digest: digest, artifact: "Docker.exe:evil", platform: runtimeinstall.PlatformWindows},
		{name: "unknown", digest: digest, artifact: "Docker.dmg", platform: runtimeinstall.PlatformUnknown},
		{name: "linux", digest: digest, artifact: "Docker.dmg", platform: runtimeinstall.PlatformLinux},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if actual := validNativeDesktopBindingRequest(test.digest, test.artifact, test.platform); actual != test.valid {
				t.Fatalf("validNativeDesktopBindingRequest()=%v want=%v", actual, test.valid)
			}
		})
	}
}
