package install

import (
	"bytes"
	"testing"
)

func TestPF001OwnerBindingHashesAndSeparatesMachineAndPrincipal(t *testing.T) {
	t.Parallel()
	first, err := BindOwner("machine-a", "linux:uid:1000")
	if err != nil {
		t.Fatal(err)
	}
	same, _ := BindOwner("machine-a", "linux:uid:1000")
	otherMachine, _ := BindOwner("machine-b", "linux:uid:1000")
	otherPrincipal, _ := BindOwner("machine-a", "linux:uid:1001")
	if !first.Equal(same) || first.Equal(otherMachine) || first.Equal(otherPrincipal) || first.IsZero() {
		t.Fatal("owner binding equality did not bind both identities")
	}
	if first.MachineDigest().String() == "machine-a" || first.PrincipalDigest().String() == "linux:uid:1000" {
		t.Fatal("raw local identity escaped its digest binding")
	}
	restored, err := RestoreOwnerBinding(first.MachineDigest().String(), first.PrincipalDigest().String())
	if err != nil || !restored.Equal(first) || restored.Fingerprint().IsZero() {
		t.Fatalf("restored binding = %#v, %v", restored, err)
	}
}

func TestPF001OwnerBindingRejectsUnsafeIdentity(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", " padded", "line\nbreak", string(bytes.Repeat([]byte{'x'}, maxOwnerIdentityLength+1))} {
		if _, err := BindOwner(value, "linux:uid:1000"); err == nil {
			t.Fatalf("unsafe machine identity accepted: %q", value)
		}
		if _, err := BindOwner("machine", value); err == nil {
			t.Fatalf("unsafe principal identity accepted: %q", value)
		}
	}
	if _, err := RestoreOwnerBinding("bad", "bad"); err == nil {
		t.Fatal("invalid persisted binding was accepted")
	}
	valid, _ := BindOwner("machine", "principal")
	if _, err := RestoreOwnerBinding(valid.MachineDigest().String(), "bad"); err == nil {
		t.Fatal("invalid persisted principal binding was accepted")
	}
}

func TestPF001BootstrapKeyRefAndRollbackAnchorAreStrictValues(t *testing.T) {
	t.Parallel()
	keyDigest := DigestBytes([]byte("key reference"))
	keyRef, err := BootstrapKeyRefFromDigest(keyDigest)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := NewBootstrapKeyRef(keyRef.String())
	if err != nil || !parsed.Equal(keyRef) || parsed.IsZero() {
		t.Fatalf("parsed ref = %q, %v", parsed.String(), err)
	}
	if _, err := NewBootstrapKeyRef("../../key"); err == nil {
		t.Fatal("path-shaped key reference was accepted")
	}
	if _, err := NewBootstrapKeyRef(bootstrapKeyRefPrefix + "bad"); err == nil {
		t.Fatal("invalid key reference digest was accepted")
	}
	if _, err := BootstrapKeyRefFromDigest(Digest{}); err == nil {
		t.Fatal("zero key digest was accepted")
	}

	owner, _ := BindOwner("machine", "linux:uid:1000")
	id, _ := NewOperationID("019f5c00-0000-7000-8000-000000000001")
	anchor, err := NewRollbackAnchor(id, owner, 7, DigestBytes([]byte("journal revision seven")))
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Sequence() != 7 || anchor.OperationID() != id || !anchor.Owner().Equal(owner) || anchor.StateDigest().IsZero() || len(anchor.CanonicalBytes()) == 0 {
		t.Fatal("rollback anchor did not retain its exact bindings")
	}
	if _, err := NewRollbackAnchor(id, owner, 0, DigestBytes([]byte("state"))); err == nil {
		t.Fatal("zero rollback sequence was accepted")
	}
	invalidAnchors := []struct {
		id     OperationID
		owner  OwnerBinding
		digest Digest
	}{
		{id: OperationID{}, owner: owner, digest: DigestBytes([]byte("state"))},
		{id: id, owner: OwnerBinding{}, digest: DigestBytes([]byte("state"))},
		{id: id, owner: owner, digest: Digest{}},
	}
	for _, invalid := range invalidAnchors {
		if _, err := NewRollbackAnchor(invalid.id, invalid.owner, 1, invalid.digest); err == nil {
			t.Fatal("invalid rollback anchor was accepted")
		}
	}
}
