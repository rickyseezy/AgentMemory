package activerelease

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	testInstallationID = "019f5f20-1234-7abc-8123-0123456789ab"
	testGenerationID   = "019f5f21-5678-7def-9123-abcdef012345"
)

func TestPF001ActivePointerIsCanonicalImmutableAndRestorable(t *testing.T) {
	t.Parallel()

	input := validPointerInput()
	pointer, err := NewPointer(input)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.InstallationID() != input.InstallationID || pointer.ReleaseID() != input.ReleaseID ||
		pointer.GenerationID() != input.GenerationID || pointer.RuntimeEndpoint() != input.RuntimeEndpoint ||
		pointer.ReleaseSequence() != input.ReleaseSequence || pointer.ResourceInventoryVersion() != input.ResourceInventoryVersion ||
		pointer.SecurityEpoch() != input.SecurityEpoch || pointer.ActivatedAt() != input.ActivatedAt.UTC().Truncate(time.Microsecond) ||
		pointer.Digest().IsZero() {
		t.Fatalf("pointer = %+v", pointer)
	}

	restored, err := RestorePointer(pointer.Record())
	if err != nil || !restored.Digest().Equal(pointer.Digest()) {
		t.Fatalf("RestorePointer() = %+v, %v", restored, err)
	}
	record := pointer.Record()
	if record.SchemaVersion != pointerSchemaVersion || record.InstallationID != input.InstallationID ||
		record.ReleaseID != input.ReleaseID || record.GenerationID != input.GenerationID ||
		record.ManifestDigest != input.ManifestDigest.String() || record.ComposeDigest != input.ComposeDigest.String() ||
		record.ReadinessReceiptDigest != input.ReadinessReceiptDigest.String() ||
		record.RuntimeEndpoint != input.RuntimeEndpoint || record.ReleaseSequence != input.ReleaseSequence ||
		record.ResourceInventoryVersion != input.ResourceInventoryVersion ||
		record.ResourceInventoryDigest != input.ResourceInventoryDigest.String() || record.SecurityEpoch != input.SecurityEpoch ||
		record.ActivatedAt != input.ActivatedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) ||
		record.PointerDigest != pointer.Digest().String() {
		t.Fatalf("record = %+v", record)
	}
	record.ReleaseID = "mutated"
	if pointer.ReleaseID() != input.ReleaseID {
		t.Fatal("Pointer exposed mutable record storage")
	}
}

func TestPF001ActivePointerDigestAndAccessorsBindEveryField(t *testing.T) {
	t.Parallel()

	input := validPointerInput()
	pointer := mustPointer(t, input)
	if pointer.InstallationID() != input.InstallationID || pointer.ReleaseID() != input.ReleaseID ||
		pointer.GenerationID() != input.GenerationID || !pointer.ManifestDigest().Equal(input.ManifestDigest) ||
		!pointer.ComposeDigest().Equal(input.ComposeDigest) ||
		!pointer.ReadinessReceiptDigest().Equal(input.ReadinessReceiptDigest) ||
		pointer.RuntimeEndpoint() != input.RuntimeEndpoint || pointer.ReleaseSequence() != input.ReleaseSequence ||
		pointer.ResourceInventoryVersion() != input.ResourceInventoryVersion ||
		!pointer.ResourceInventoryDigest().Equal(input.ResourceInventoryDigest) ||
		pointer.SecurityEpoch() != input.SecurityEpoch ||
		pointer.ActivatedAt() != input.ActivatedAt.UTC().Truncate(time.Microsecond) || pointer.IsZero() {
		t.Fatal("pointer accessors lost a field")
	}

	mutations := []func(*PointerInput){
		func(value *PointerInput) { value.InstallationID = "019f5f20-1234-7abc-9123-0123456789ac" },
		func(value *PointerInput) { value.ReleaseID = "release-v2" },
		func(value *PointerInput) { value.GenerationID = "019f5f22-5678-7def-9123-abcdef012346" },
		func(value *PointerInput) { value.ManifestDigest = install.DigestBytes([]byte("manifest-2")) },
		func(value *PointerInput) { value.ComposeDigest = install.DigestBytes([]byte("compose-2")) },
		func(value *PointerInput) { value.ReadinessReceiptDigest = install.DigestBytes([]byte("ready-2")) },
		func(value *PointerInput) { value.RuntimeEndpoint = "unix:///run/user/1000/docker.sock" },
		func(value *PointerInput) { value.ReleaseSequence++ },
		func(value *PointerInput) { value.ResourceInventoryVersion++ },
		func(value *PointerInput) { value.ResourceInventoryDigest = install.DigestBytes([]byte("inventory-2")) },
		func(value *PointerInput) { value.SecurityEpoch++ },
		func(value *PointerInput) { value.ActivatedAt = value.ActivatedAt.Add(time.Microsecond) },
	}
	for index, mutate := range mutations {
		candidate := input
		mutate(&candidate)
		changed := mustPointer(t, candidate)
		if changed.Digest().Equal(pointer.Digest()) {
			t.Fatalf("field mutation %d did not change pointer digest", index)
		}
	}
}

func TestPF001ActivePointerClosedIdentifierAndEndpointValidators(t *testing.T) {
	t.Parallel()

	validRelease := []string{"a", "0", "a-b", "a_b", "a.b", "a" + string(make([]byte, 0)), "a" + repeat("a", maximumReleaseID-1)}
	for _, value := range validRelease {
		if !validReleaseID(value) {
			t.Fatalf("validReleaseID(%q) = false", value)
		}
	}
	for _, value := range []string{"", "-a", "_a", ".a", "A", "a/b", " a", "a ", "a\n", "a" + repeat("a", maximumReleaseID)} {
		if validReleaseID(value) {
			t.Fatalf("validReleaseID(%q) = true", value)
		}
	}

	validUUIDs := []string{
		"019f5f20-1234-7abc-8123-0123456789ab",
		"019f5f20-1234-7abc-9123-0123456789ab",
		"019f5f20-1234-7abc-a123-0123456789ab",
		"019f5f20-1234-7abc-b123-0123456789ab",
	}
	for _, value := range validUUIDs {
		if !validUUIDv7(value) {
			t.Fatalf("validUUIDv7(%q) = false", value)
		}
	}
	invalidUUIDs := []string{
		"", "019f5f20-1234-7abc-8123-0123456789a", "019f5f20-1234-7abc-8123-0123456789abc",
		"019f5f201234-7abc-8123-0123456789ab", "019f5f20-12347abc-8123-0123456789ab",
		"019f5f20-1234-7abc8123-0123456789ab", "019f5f20-1234-7abc-81230123456789ab",
		"019f5f20-1234-6abc-8123-0123456789ab", "019f5f20-1234-7abc-7123-0123456789ab",
		"019F5f20-1234-7abc-8123-0123456789ab", "019g5f20-1234-7abc-8123-0123456789ab",
	}
	for _, value := range invalidUUIDs {
		if validUUIDv7(value) {
			t.Fatalf("validUUIDv7(%q) = true", value)
		}
	}

	for _, value := range []string{"unix:///a", "unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"} {
		if !validLocalEndpoint(value) {
			t.Fatalf("validLocalEndpoint(%q) = false", value)
		}
	}
	invalidEndpoints := []string{
		"", "tcp://127.0.0.1:2375", "unix://relative", "unix:///", "unix:///a/", "unix:///a//b",
		"unix:///a/./b", "unix:///a/../b", "unix:///a\x00b", "unix:///a\rb", "unix:///a\nb",
		"npipe:////./pipe/", "npipe:////./pipe/.", "npipe:////./pipe/..", "npipe:////./pipe/a/b", "npipe:////./pipe/a\\b",
		repeat("x", maximumEndpoint+1),
	}
	for _, value := range invalidEndpoints {
		if validLocalEndpoint(value) {
			t.Fatalf("validLocalEndpoint(%q) = true", value)
		}
	}
}

func TestPF001ActivePointerRejectsIncompleteRemoteOrNonCanonicalState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*PointerInput)
	}{
		{name: "installation", mutate: func(value *PointerInput) { value.InstallationID = "not-a-uuid" }},
		{name: "installation not v7", mutate: func(value *PointerInput) { value.InstallationID = "019f5f20-1234-4abc-8123-0123456789ab" }},
		{name: "release", mutate: func(value *PointerInput) { value.ReleaseID = " Release" }},
		{name: "release uppercase", mutate: func(value *PointerInput) { value.ReleaseID = "Release" }},
		{name: "generation", mutate: func(value *PointerInput) { value.GenerationID = "019f5f21-5678-4def-9123-abcdef012345" }},
		{name: "manifest", mutate: func(value *PointerInput) { value.ManifestDigest = install.Digest{} }},
		{name: "compose", mutate: func(value *PointerInput) { value.ComposeDigest = install.Digest{} }},
		{name: "readiness", mutate: func(value *PointerInput) { value.ReadinessReceiptDigest = install.Digest{} }},
		{name: "remote endpoint", mutate: func(value *PointerInput) { value.RuntimeEndpoint = "tcp://127.0.0.1:2375" }},
		{name: "relative endpoint", mutate: func(value *PointerInput) { value.RuntimeEndpoint = "unix://relative.sock" }},
		{name: "endpoint traversal", mutate: func(value *PointerInput) { value.RuntimeEndpoint = "unix:///run/../docker.sock" }},
		{name: "release sequence", mutate: func(value *PointerInput) { value.ReleaseSequence = 0 }},
		{name: "inventory version", mutate: func(value *PointerInput) { value.ResourceInventoryVersion = 0 }},
		{name: "inventory digest", mutate: func(value *PointerInput) { value.ResourceInventoryDigest = install.Digest{} }},
		{name: "security epoch", mutate: func(value *PointerInput) { value.SecurityEpoch = 0 }},
		{name: "activation time", mutate: func(value *PointerInput) { value.ActivatedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPointerInput()
			test.mutate(&input)
			if _, err := NewPointer(input); err == nil {
				t.Fatal("NewPointer() accepted invalid state")
			}
		})
	}

	valid, err := NewPointer(validPointerInput())
	if err != nil {
		t.Fatal(err)
	}
	record := valid.Record()
	record.PointerDigest = install.DigestBytes([]byte("other")).String()
	if _, err := RestorePointer(record); err == nil {
		t.Fatal("RestorePointer() accepted a mismatched digest")
	}
	record = valid.Record()
	record.SchemaVersion++
	if _, err := RestorePointer(record); err == nil {
		t.Fatal("RestorePointer() accepted an unknown schema")
	}
}

func TestPF001ActivePointerReplacementPolicyBlocksRollbackAndAmbiguity(t *testing.T) {
	t.Parallel()

	target := mustPointer(t, validPointerInput())
	if decision := DecideReplacement(Pointer{}, target); decision != DecisionActivate {
		t.Fatalf("empty decision = %v", decision)
	}
	if decision := DecideReplacement(target, target); decision != DecisionAlreadyActive {
		t.Fatalf("same decision = %v", decision)
	}
	if decision := DecideReplacement(target, Pointer{}); decision != DecisionConflict {
		t.Fatalf("zero target decision = %v", decision)
	}

	tests := []struct {
		name   string
		mutate func(*PointerInput)
	}{
		{name: "installation mismatch", mutate: func(value *PointerInput) { value.InstallationID = "019f5f20-1234-7abc-9123-0123456789ac" }},
		{name: "release rollback", mutate: func(value *PointerInput) { value.ReleaseSequence-- }},
		{name: "inventory rollback", mutate: func(value *PointerInput) { value.ResourceInventoryVersion -= 2 }},
		{name: "security rollback", mutate: func(value *PointerInput) { value.SecurityEpoch -= 2 }},
		{name: "same sequence equivocation", mutate: func(value *PointerInput) {
			value.ReleaseSequence = 10
			value.ReleaseID = "release-v1-equivocation"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			currentInput := validPointerInput()
			currentInput.ReleaseSequence = 10
			currentInput.ResourceInventoryVersion = 10
			currentInput.SecurityEpoch = 10
			current := mustPointer(t, currentInput)
			targetInput := currentInput
			targetInput.ReleaseSequence++
			targetInput.ResourceInventoryVersion++
			targetInput.SecurityEpoch++
			targetInput.ReleaseID = "release-v2"
			targetInput.GenerationID = "019f5f22-5678-7def-9123-abcdef012346"
			test.mutate(&targetInput)
			if decision := DecideReplacement(current, mustPointer(t, targetInput)); decision != DecisionConflict {
				t.Fatalf("decision = %v", decision)
			}
		})
	}

	currentInput := validPointerInput()
	currentInput.ReleaseSequence = 10
	current := mustPointer(t, currentInput)
	for _, mutate := range []func(*PointerInput){
		func(value *PointerInput) {
			value.ReleaseSequence = currentInput.ReleaseSequence
			value.ManifestDigest = install.DigestBytes([]byte("equivocal-manifest"))
		},
		func(value *PointerInput) {
			value.ReleaseSequence = currentInput.ReleaseSequence
			value.ComposeDigest = install.DigestBytes([]byte("equivocal-compose"))
		},
	} {
		candidate := currentInput
		mutate(&candidate)
		if decision := DecideReplacement(current, mustPointer(t, candidate)); decision != DecisionConflict {
			t.Fatalf("same-sequence evidence decision = %v", decision)
		}
	}
}

func validPointerInput() PointerInput {
	return PointerInput{
		InstallationID:           testInstallationID,
		ReleaseID:                "release-v1",
		GenerationID:             testGenerationID,
		ManifestDigest:           install.DigestBytes([]byte("manifest")),
		ComposeDigest:            install.DigestBytes([]byte("compose")),
		ReadinessReceiptDigest:   install.DigestBytes([]byte("ready")),
		RuntimeEndpoint:          "unix:///var/run/docker.sock",
		ReleaseSequence:          7,
		ResourceInventoryVersion: 9,
		ResourceInventoryDigest:  install.DigestBytes([]byte("inventory")),
		SecurityEpoch:            3,
		ActivatedAt:              time.Date(2026, 7, 13, 10, 11, 12, 123456789, time.FixedZone("test", 4*60*60)),
	}
}

func mustPointer(t *testing.T, input PointerInput) Pointer {
	t.Helper()
	pointer, err := NewPointer(input)
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
