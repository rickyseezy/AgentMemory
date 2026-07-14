package releaseinventory

import (
	"errors"
	"testing"
)

func TestPF001ReleaseExpandedTargetBindsRawComposePublication(t *testing.T) {
	t.Parallel()
	content := []byte("services:\n  core:\n    image: example@sha256:abc\n")
	source := DigestBytes(content)
	target, err := NewReleaseExpandedTarget(source, uint64(len(content)), ReleaseExpandedTargetInput{
		Kind: ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
		Digest: source, Bytes: uint64(len(content)),
	})
	if err != nil || !target.Valid() || target.Kind() != ExpandedTargetComposeBundle ||
		target.StorageID() != "compose/compose.yaml" || !target.Digest().Equal(source) ||
		target.Bytes() != uint64(len(content)) || target.AuthorityDigest().IsZero() {
		t.Fatalf("NewReleaseExpandedTarget()=%+v,%v", target, err)
	}
	replay, err := NewReleaseExpandedTarget(source, uint64(len(content)), ReleaseExpandedTargetInput{
		Kind: ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
		Digest: source, Bytes: uint64(len(content)),
	})
	if err != nil || !replay.AuthorityDigest().Equal(target.AuthorityDigest()) {
		t.Fatalf("authority digest replay=%+v,%v", replay, err)
	}
	changed, _ := NewReleaseExpandedTarget(source, uint64(len(content)), ReleaseExpandedTargetInput{
		Kind: ExpandedTargetComposeBundle, StorageID: "compose/alternate.yaml",
		Digest: source, Bytes: uint64(len(content)),
	})
	if changed.AuthorityDigest().Equal(target.AuthorityDigest()) {
		t.Fatal("storage substitution did not alter signed target authority")
	}
}

func TestPF001ReleaseExpandedTargetRejectsUnknownOrInferredSemantics(t *testing.T) {
	t.Parallel()
	source := DigestBytes([]byte("compose"))
	for name, input := range map[string]ReleaseExpandedTargetInput{
		"missing kind":     {StorageID: "compose/compose.yaml", Digest: source, Bytes: 7},
		"unknown kind":     {Kind: "tar-tree", StorageID: "compose/compose.yaml", Digest: source, Bytes: 7},
		"absolute storage": {Kind: ExpandedTargetComposeBundle, StorageID: "/compose/compose.yaml", Digest: source, Bytes: 7},
		"traversal":        {Kind: ExpandedTargetComposeBundle, StorageID: "../compose.yaml", Digest: source, Bytes: 7},
		"foreign digest":   {Kind: ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: DigestBytes([]byte("normalized")), Bytes: 7},
		"short allocation": {Kind: ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: source, Bytes: 6},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReleaseExpandedTarget(source, 7, input); !errors.Is(err, ErrExpandedTargetInvalid) {
				t.Fatalf("NewReleaseExpandedTarget() error=%v", err)
			}
		})
	}
}
