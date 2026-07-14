package hostverification

import (
	"errors"
	"testing"
)

func TestPF001HostPolicyEvaluatesEveryClosedBoundary(t *testing.T) {
	t.Parallel()
	plan := hostPlanFixture(t)
	base := observationInput(plan)
	tests := []struct {
		name   string
		mutate func(*ObservationInput)
		want   FailureReason
	}{
		{name: "certified", want: FailureNone},
		{name: "platform", mutate: func(input *ObservationInput) { input.Platform.Build = "6.8.0-64-generic" }, want: FailureUnsupportedPlatform},
		{name: "cpu", mutate: func(input *ObservationInput) { input.CPUCores-- }, want: FailureInsufficientCPU},
		{name: "memory", mutate: func(input *ObservationInput) { input.MemoryBytes-- }, want: FailureInsufficientMemory},
		{name: "disk", mutate: func(input *ObservationInput) { input.FreeDiskBytes-- }, want: FailureInsufficientDisk},
		{name: "target", mutate: func(input *ObservationInput) { input.StorageTarget = "/home/user/other" }, want: FailureTargetNotOwnerControlled},
		{name: "port", mutate: func(input *ObservationInput) { input.AvailablePorts[0].Port++ }, want: FailureLoopbackPortUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.AvailablePorts = append([]LoopbackEndpoint(nil), base.AvailablePorts...)
			if test.mutate != nil {
				test.mutate(&input)
			}
			observation, err := NewObservation(input)
			if err != nil {
				t.Fatal(err)
			}
			if got := plan.Evaluate(observation); got != test.want {
				t.Fatalf("Evaluate() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPF001HostObservationRejectsCrossPlatformProofClaims(t *testing.T) {
	t.Parallel()
	plan := hostPlanFixture(t)
	base := observationInput(plan)
	tests := []struct {
		name   string
		mutate func(*ObservationInput)
	}{
		{name: "zero cpu", mutate: func(input *ObservationInput) { input.CPUCores = 0 }},
		{name: "zero memory", mutate: func(input *ObservationInput) { input.MemoryBytes = 0 }},
		{name: "zero disk", mutate: func(input *ObservationInput) { input.FreeDiskBytes = 0 }},
		{name: "wrong virtualization", mutate: func(input *ObservationInput) { input.Virtualization = VirtualizationWindowsFirmware }},
		{name: "wrong encryption", mutate: func(input *ObservationInput) { input.Encryption = EncryptionBitLocker }},
		{name: "no ports", mutate: func(input *ObservationInput) { input.AvailablePorts = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.AvailablePorts = append([]LoopbackEndpoint(nil), base.AvailablePorts...)
			test.mutate(&input)
			if _, err := NewObservation(input); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("NewObservation() error = %v", err)
			}
		})
	}
}

func TestPF001HostObservationExposesOnlyImmutableVerifiedFacts(t *testing.T) {
	t.Parallel()
	plan := hostPlanFixture(t)
	input := observationInput(plan)
	observation, err := NewObservation(input)
	if err != nil {
		t.Fatal(err)
	}
	ports := observation.AvailablePorts()
	if observation.Platform() != input.Platform || observation.CPUCores() != input.CPUCores ||
		observation.MemoryBytes() != input.MemoryBytes || observation.FreeDiskBytes() != input.FreeDiskBytes ||
		observation.StorageTarget() != input.StorageTarget ||
		observation.Virtualization() != input.Virtualization || observation.Encryption() != input.Encryption ||
		len(ports) != len(input.AvailablePorts) || observation.Digest().IsZero() {
		t.Fatalf("observation facts=%+v", observation)
	}
	ports[0].Port++
	if ports[0] == observation.AvailablePorts()[0] {
		t.Fatal("observation exposed mutable port evidence")
	}
}

func TestPF001HostProbeResultCannotManufactureSuccess(t *testing.T) {
	t.Parallel()
	plan := hostPlanFixture(t)
	observation, err := NewObservation(observationInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := NewObservedResult(observation)
	if err != nil || !observed.Valid() || observed.Failure() != FailureNone {
		t.Fatalf("observed = %+v, %v", observed, err)
	}
	copyObservation, ok := observed.Observation()
	if !ok || !copyObservation.Digest().Equal(observation.Digest()) {
		t.Fatal("positive probe did not preserve observation")
	}
	for _, reason := range []FailureReason{FailurePlatformProofUnavailable, FailureTargetNotOwnerControlled, FailureEncryptionUnavailable, FailureLoopbackPortUnavailable} {
		rejected, rejectErr := NewRejectedResult(reason)
		if rejectErr != nil || !rejected.Valid() || rejected.Failure() != reason {
			t.Fatalf("NewRejectedResult(%q) = %+v, %v", reason, rejected, rejectErr)
		}
		if _, ok := rejected.Observation(); ok {
			t.Fatal("negative probe exposed an observation")
		}
	}
	if _, err := NewRejectedResult(FailureNone); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("none rejection error = %v", err)
	}
	if (ProbeResult{}).Valid() {
		t.Fatal("zero probe result is valid")
	}
}

func observationInput(plan Plan) ObservationInput {
	return ObservationInput{
		Platform: plan.Platform(), CPUCores: plan.MinimumCPUCores(), MemoryBytes: plan.MinimumMemoryBytes(),
		FreeDiskBytes: plan.MinimumFreeDiskBytes(), StorageTarget: plan.StorageTarget(),
		Virtualization: VirtualizationKVM, Encryption: EncryptionDMcrypt, AvailablePorts: plan.RequiredPorts(),
	}
}
