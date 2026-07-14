package releaseanchor

import (
	"bytes"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

// FuzzPF001ReleaseAnchorSnapshotStrictDecoder proves arbitrary journal payloads
// cannot panic or be normalized into accepted anti-rollback state.
func FuzzPF001ReleaseAnchorSnapshotStrictDecoder(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"anchors":[{"channel":"stable","sequence":1,"manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_id":"release"}]}`))
	f.Add([]byte(`{"schema_version":1,"anchors":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		snapshot := installjournal.Snapshot{
			OperationID: releaseAnchorOperationID,
			Revision:    1,
			CapturedAt:  time.Unix(1, 0).UTC(),
			Payload:     append([]byte(nil), payload...),
		}
		anchors, err := decodeSnapshot(snapshot)
		if err != nil {
			return
		}
		canonical, encodeError := encodeAnchors(anchors)
		if encodeError != nil {
			t.Fatalf("accepted state cannot be encoded: %v", encodeError)
		}
		if !bytes.Equal(canonical, payload) {
			t.Fatal("decoder normalized untrusted release-anchor bytes")
		}
	})
}
