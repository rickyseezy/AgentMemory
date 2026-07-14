package artifactacquisition

import (
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ExpandedTargetObservationRejectsEveryMalformedIdentityAndBound(t *testing.T) {
	t.Parallel()
	lease, consume := expandedTargetLeaseAndConsume(t, "install-expanded-observation-edges")
	authority, err := NewExpandedTargetAuthority(
		consume, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	valid := expandedObservation(t, authority, lease.Owner(), lease.Bytes(), true)
	invalid := map[string]func(*ExpandedTargetObservationInput){
		"lease":                 func(v *ExpandedTargetObservationInput) { v.LeaseID = "" },
		"receipt":               func(v *ExpandedTargetObservationInput) { v.ReceiptToken = "" },
		"plan":                  func(v *ExpandedTargetObservationInput) { v.PlanDigest = releaseinventory.Digest{} },
		"pool id":               func(v *ExpandedTargetObservationInput) { v.PoolID = "" },
		"pool kind":             func(v *ExpandedTargetObservationInput) { v.PoolKind = "" },
		"source digest":         func(v *ExpandedTargetObservationInput) { v.SourceDigest = releaseinventory.Digest{} },
		"source bytes zero":     func(v *ExpandedTargetObservationInput) { v.SourceBytes = 0 },
		"source bytes overflow": func(v *ExpandedTargetObservationInput) { v.SourceBytes = maximumSafeBytes + 1 },
		"target digest":         func(v *ExpandedTargetObservationInput) { v.TargetDigest = releaseinventory.Digest{} },
		"reserved zero":         func(v *ExpandedTargetObservationInput) { v.ReservedBytes = 0 },
		"reserved overflow":     func(v *ExpandedTargetObservationInput) { v.ReservedBytes = maximumSafeBytes + 1 },
		"target kind":           func(v *ExpandedTargetObservationInput) { v.TargetKind = "" },
		"storage absolute":      func(v *ExpandedTargetObservationInput) { v.TargetStorageID = "/absolute" },
		"storage trailing":      func(v *ExpandedTargetObservationInput) { v.TargetStorageID = "target/" },
		"storage duplicate":     func(v *ExpandedTargetObservationInput) { v.TargetStorageID = "target//child" },
		"storage dot":           func(v *ExpandedTargetObservationInput) { v.TargetStorageID = "target/./child" },
		"storage parent":        func(v *ExpandedTargetObservationInput) { v.TargetStorageID = "target/../child" },
		"storage slash":         func(v *ExpandedTargetObservationInput) { v.TargetStorageID = `target\child` },
		"storage too long":      func(v *ExpandedTargetObservationInput) { v.TargetStorageID = strings.Repeat("x", 257) },
		"root empty":            func(v *ExpandedTargetObservationInput) { v.TargetRoot = "" },
		"root newline":          func(v *ExpandedTargetObservationInput) { v.TargetRoot = "root\nforeign" },
		"root too long":         func(v *ExpandedTargetObservationInput) { v.TargetRoot = "/" + strings.Repeat("r", 4096) },
		"authority":             func(v *ExpandedTargetObservationInput) { v.TargetAuthorityDigest = releaseinventory.Digest{} },
		"owner":                 func(v *ExpandedTargetObservationInput) { v.Owner = "" },
		"allocated reserve":     func(v *ExpandedTargetObservationInput) { v.ReservedAllocatedBytes = v.ReservedBytes - 1 },
		"allocated overflow":    func(v *ExpandedTargetObservationInput) { v.ReservedAllocatedBytes = maximumSafeBytes + 1 },
		"measured overflow":     func(v *ExpandedTargetObservationInput) { v.MeasuredBytes = v.ReservedBytes + 1 },
		"blocks overflow":       func(v *ExpandedTargetObservationInput) { v.AllocatedBytes = v.ReservedAllocatedBytes + 1 },
		"present zero bytes":    func(v *ExpandedTargetObservationInput) { v.TargetPresent, v.MeasuredBytes = true, 0 },
		"present zero blocks":   func(v *ExpandedTargetObservationInput) { v.TargetPresent, v.AllocatedBytes = true, 0 },
	}
	for name, mutate := range invalid {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			mutate(&candidate)
			if _, constructErr := NewExpandedTargetObservation(candidate); !errors.Is(constructErr, ErrInvalidTransition) {
				t.Fatalf("malformed observation accepted: %+v error=%v", candidate, constructErr)
			}
		})
	}
}

func TestPF001ExpandedTargetAggregateRejectsConflictingLifecycleReplays(t *testing.T) {
	t.Parallel()
	lease, consume := expandedTargetLeaseAndConsume(t, "install-expanded-lifecycle-edges")
	authority, _ := NewExpandedTargetAuthority(
		consume, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	aggregate, _ := NewExpandedTargetAggregate(authority)
	if _, err := aggregate.BeginTransfer("generation-active"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pre-consume transfer error=%v", err)
	}
	if _, err := aggregate.BeginTransfer(""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("empty owner transfer error=%v", err)
	}
	consumed := expandedObservation(t, authority, lease.Owner(), lease.Bytes(), true)
	if _, err := aggregate.RecordConsumed(consumed); err != nil {
		t.Fatal(err)
	}
	if _, err := aggregate.BeginTransfer("generation-active"); err != nil {
		t.Fatal(err)
	}
	if _, err := aggregate.BeginTransfer("generation-foreign"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pending owner substitution error=%v", err)
	}
	if _, err := aggregate.RecordTransferred(consumed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unobserved transfer error=%v", err)
	}
	transferred := expandedObservation(t, authority, "generation-active", lease.Bytes(), true)
	if _, err := aggregate.RecordTransferred(transferred); err != nil {
		t.Fatal(err)
	}
	if _, err := aggregate.BeginTransfer("generation-foreign"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("completed owner substitution error=%v", err)
	}
	if _, err := aggregate.RecordConsumed(consumed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("consume after transfer error=%v", err)
	}

	foreignConsume := consume
	foreignAuthorityDigest := releaseinventory.DigestBytes([]byte("foreign-authority"))
	if _, err := NewExpandedTargetAuthority(
		foreignConsume, string(lease.TargetKind()), lease.TargetStorageID(), foreignAuthorityDigest,
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("foreign target authority error=%v", err)
	}
	if _, err := NewExpandedTargetAggregate(ExpandedTargetAuthority{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("zero aggregate authority error=%v", err)
	}
}
