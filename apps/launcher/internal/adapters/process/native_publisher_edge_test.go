package process

import "testing"

func TestPF001NativePublisherDependencyNilDetection(t *testing.T) {
	t.Parallel()
	if !nilTrustDependency(nil) {
		t.Fatal("nil dependency was accepted")
	}
	var typedNil *packageReceiptStub
	if !nilTrustDependency(typedNil) {
		t.Fatal("typed-nil dependency was accepted")
	}
	if nilTrustDependency(packageReceiptStub{}) {
		t.Fatal("concrete dependency was rejected")
	}
}
