package hostpackage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001HostManifestsUseExactVendorContracts(t *testing.T) {
	t.Parallel()
	tests := map[Host]struct {
		name, command, agent string
	}{
		HostClaude:  {"manifest.json", "${__dirname}/bin/agentmemory-bootstrap", "claude"},
		HostGemini:  {"gemini-extension.json", "${extensionPath}${/}bin${/}agentmemory-bootstrap", "gemini"},
		HostGeneric: {"agentmemory-mcp.json", "bin/agentmemory-bootstrap", "custom"},
	}
	for host, want := range tests {
		host, want := host, want
		t.Run(string(host), func(t *testing.T) {
			t.Parallel()
			name, err := ManifestName(host)
			if err != nil || name != want.name {
				t.Fatalf("ManifestName()=%q,%v", name, err)
			}
			raw, err := EncodeManifest(ManifestInput{Host: host, Target: Target{"linux", "amd64"},
				Version: "1.2.3", Executable: "agentmemory-bootstrap"})
			if err != nil || bytes.HasSuffix(raw, []byte{'\n'}) {
				t.Fatalf("EncodeManifest()=%q,%v", raw, err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(want.command)) || !bytes.Contains(raw, []byte(`"`+want.agent+`"`)) {
				t.Fatalf("manifest=%s", raw)
			}
		})
	}
	windows, err := EncodeManifest(ManifestInput{Host: HostClaude, Target: Target{"windows", "amd64"},
		Version: "1.2.3", Executable: "agentmemory-bootstrap.exe"})
	if err != nil || !bytes.Contains(windows, []byte(`"platforms":["win32"]`)) {
		t.Fatalf("windows MCPB=%s,%v", windows, err)
	}
}

func TestPF001HostManifestRejectsOpenIdentity(t *testing.T) {
	t.Parallel()
	base := ManifestInput{Host: HostClaude, Target: Target{"darwin", "arm64"}, Version: "1.2.3", Executable: "agentmemory-bootstrap"}
	for name, mutate := range map[string]func(*ManifestInput){
		"host":        func(value *ManifestInput) { value.Host = "future" },
		"os":          func(value *ManifestInput) { value.Target.OperatingSystem = "freebsd" },
		"arch":        func(value *ManifestInput) { value.Target.Architecture = "386" },
		"windows arm": func(value *ManifestInput) { value.Target = Target{"windows", "arm64"} },
		"version":     func(value *ManifestInput) { value.Version = "01.2.3" },
		"executable":  func(value *ManifestInput) { value.Executable = "../bootstrap" },
	} {
		value := base
		mutate(&value)
		if _, err := EncodeManifest(value); err == nil {
			t.Fatalf("%s invalid manifest accepted", name)
		}
	}
	if _, err := ManifestName("future"); err == nil {
		t.Fatal("future host accepted")
	}
}

func TestPF001HostPackageRecordBindsDetachedArchive(t *testing.T) {
	t.Parallel()
	input := RecordInput{
		SchemaVersion: 1, Host: HostClaude, Target: Target{"linux", "amd64"}, Version: "1.2.3",
		SourceCommit: strings.Repeat("a", 40), SourceEpoch: 1_784_073_600,
		FileName: "agentmemory-claude-linux-amd64.mcpb", ArchiveDigest: digest("archive"), ArchiveSize: 42,
		BootstrapDigest: digest("bootstrap"), PublicationDigest: digest("publication"),
		PublicationSignatureDigest: digest("publication-signature"),
	}
	raw, err := EncodeRecord(input)
	if err != nil || !bytes.Contains(raw, []byte(input.ArchiveDigest.Hex())) || bytes.HasSuffix(raw, []byte{'\n'}) {
		t.Fatalf("EncodeRecord()=%s,%v", raw, err)
	}
	for name, mutate := range map[string]func(*RecordInput){
		"schema":  func(value *RecordInput) { value.SchemaVersion = 2 },
		"host":    func(value *RecordInput) { value.Host = "future" },
		"cell":    func(value *RecordInput) { value.Target.Architecture = "386" },
		"version": func(value *RecordInput) { value.Version = "latest" },
		"commit":  func(value *RecordInput) { value.SourceCommit = strings.Repeat("A", 40) },
		"epoch":   func(value *RecordInput) { value.SourceEpoch = 0 },
		"file":    func(value *RecordInput) { value.FileName = "foreign.zip" },
		"size":    func(value *RecordInput) { value.ArchiveSize = 0 },
		"digest":  func(value *RecordInput) { value.ArchiveDigest = releaseinventory.Digest{} },
	} {
		value := input
		mutate(&value)
		if _, err := EncodeRecord(value); err == nil {
			t.Fatalf("%s invalid record accepted", name)
		}
	}
}

func digest(value string) releaseinventory.Digest { return releaseinventory.DigestBytes([]byte(value)) }
