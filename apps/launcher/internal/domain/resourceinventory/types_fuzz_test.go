package resourceinventory

import (
	"strings"
	"testing"
)

func FuzzPF001DockerObservationValidation(f *testing.F) {
	f.Add("agentmemory_example", strings.Repeat("a", 64), "value")
	f.Add("../foreign", "short", "\x00")
	f.Fuzz(func(_ *testing.T, name string, objectID string, labelValue string) {
		labels := map[string]string{
			"io.agentmemory.installation": labelValue,
			"io.agentmemory.release":      "0.1.0",
			"io.agentmemory.generation":   "stable",
			"io.agentmemory.purpose":      "models",
			"io.agentmemory.managed":      "true",
		}
		_, _ = NewObserved(KindNetwork, name, objectID, labels)
		_, _ = NewObserved(KindVolume, name, objectID, labels)
	})
}
