//go:build darwin

package artifactfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPF001DarwinArtifactDurabilityUsesLiveFullSyncDescriptors(t *testing.T) {
	t.Parallel()
	if err := durableSync(nil); err == nil {
		t.Fatal("nil durability descriptor accepted")
	}
	path := filepath.Join(resolvedTempDir(t), "durable")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("durable")); err != nil {
		t.Fatal(err)
	}
	if err := durableSync(file); err != nil {
		t.Fatalf("F_FULLFSYNC file error=%v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := durableSync(file); err == nil {
		t.Fatal("closed descriptor reported durable")
	}
}
