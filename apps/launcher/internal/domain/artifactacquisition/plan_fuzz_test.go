package artifactacquisition

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func FuzzPF001ArtifactSourceAndRangeValidation(f *testing.F) {
	f.Add("https://releases.agentmemory.dev/artifacts/core.bin", uint64(0), uint64(3))
	f.Add("http://bad/../mutable", ^uint64(0), uint64(0))
	f.Fuzz(func(_ *testing.T, source string, offset uint64, size uint64) {
		_, _ = NewPlan(PlanInput{
			PlanDigest: releaseinventory.DigestBytes([]byte("plan")),
			ProxyMode:  ProxyModeSystem,
			Artifacts: []ArtifactInput{{
				ID: "artifact", Digest: releaseinventory.DigestBytes([]byte("content")), Size: size,
				Sources: []string{source}, Chunks: []ChunkInput{{Offset: offset, Size: size, Digest: releaseinventory.DigestBytes([]byte("chunk"))}},
			}},
			Totals: TotalsInput{DownloadBytes: size, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: size + 2},
		})
	})
}
