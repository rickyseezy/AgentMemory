//go:build !darwin || cgo

package dockercli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func FuzzPF001RenderedComposeStrictDecoder(f *testing.F) {
	golden, err := os.ReadFile(filepath.Join("testdata", "compose-v5.1.2-rendered.json"))
	if err != nil {
		f.Fatalf("read Compose golden: %v", err)
	}
	golden = bytes.ReplaceAll(golden, []byte("{{SECRET_FILE}}"), []byte("/managed/release/installation-key"))
	f.Add(golden)
	f.Add([]byte(`{"name":"first","name":"second","services":{}}`))
	f.Add([]byte(`{"name":"agentmemory_019f5f2012347abc81230123456789ab","services":{},"unknown":true}`))
	f.Add([]byte(strings.Repeat("[", maximumJSONDepth+2) + "0" + strings.Repeat("]", maximumJSONDepth+2)))
	f.Fuzz(func(_ *testing.T, payload []byte) {
		model, decodeError := decodeRenderedPolicy(payload, composePolicyProject)
		if decodeError == nil {
			_ = composeplan.NewPolicy().Validate(model)
		}
	})
}
