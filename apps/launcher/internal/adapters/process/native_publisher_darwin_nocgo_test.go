//go:build darwin && !cgo

package process

import "testing"

func TestPF001DarwinNoCGONativePublisherVerifierFailsClosed(t *testing.T) {
	t.Parallel()
	verifier, err := NewNativePublisherVerifier(NativePublisherDependencies{})
	if verifier != nil || err == nil {
		t.Fatalf("no-cgo publisher verifier=%+v error=%v", verifier, err)
	}
}
