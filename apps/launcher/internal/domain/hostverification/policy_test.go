package hostverification

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPF001HostPlanCanonicalRoundTripAndDefensiveCopies(t *testing.T) {
	t.Parallel()
	plan := hostPlanFixture(t)
	decoded, err := DecodePlan(plan.CanonicalBytes())
	if err != nil || !decoded.Digest().Equal(plan.Digest()) {
		t.Fatalf("DecodePlan() = %+v, %v", decoded, err)
	}
	bytesCopy := plan.CanonicalBytes()
	bytesCopy[0] ^= 0xff
	portsCopy := plan.RequiredPorts()
	portsCopy[0].Port++
	if !plan.Valid() || bytes.Equal(bytesCopy, plan.CanonicalBytes()) || portsCopy[0] == plan.RequiredPorts()[0] {
		t.Fatal("plan exposed mutable authority")
	}
	signed, err := NewSignedPlan(plan, plan.SigningKeyID(), []byte("signature"))
	if err != nil || !signed.Valid() {
		t.Fatalf("NewSignedPlan() = %+v, %v", signed, err)
	}
	signature := signed.Signature()
	signature[0] ^= 0xff
	if bytes.Equal(signature, signed.Signature()) || !bytes.Equal(signed.SignaturePayload(), plan.CanonicalBytes()) {
		t.Fatal("signed plan exposed mutable bytes")
	}
	if signed.Plan().PolicyID() != plan.PolicyID() || signed.SigningKeyID() != plan.SigningKeyID() {
		t.Fatal("signed plan identity projection drifted")
	}
}

func TestPF001HostPlanRejectsUnsafeAndNonCanonicalAuthority(t *testing.T) {
	t.Parallel()
	base := hostPlanInput(t)
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "policy", mutate: func(input *Input) { input.PolicyID = "Latest" }},
		{name: "key", mutate: func(input *Input) { input.SigningKeyID = "" }},
		{name: "os", mutate: func(input *Input) { input.Platform.OperatingSystem = "freebsd" }},
		{name: "architecture", mutate: func(input *Input) { input.Platform.Architecture = "386" }},
		{name: "latest", mutate: func(input *Input) { input.Platform.Version = "latest" }},
		{name: "build wildcard", mutate: func(input *Input) { input.Platform.Build = "6.*" }},
		{name: "cpu", mutate: func(input *Input) { input.MinimumCPUCores = 0 }},
		{name: "memory", mutate: func(input *Input) { input.MinimumMemoryBytes = 0 }},
		{name: "disk", mutate: func(input *Input) { input.MinimumFreeDiskBytes = 0 }},
		{name: "relative target", mutate: func(input *Input) { input.StorageTarget = "var/lib/agentmemory" }},
		{name: "traversal", mutate: func(input *Input) { input.StorageTarget = "/var/../tmp" }},
		{name: "no ports", mutate: func(input *Input) { input.RequiredPorts = nil }},
		{name: "zero port", mutate: func(input *Input) { input.RequiredPorts[0].Port = 0 }},
		{name: "family", mutate: func(input *Input) { input.RequiredPorts[0].Family = "host" }},
		{name: "duplicate", mutate: func(input *Input) { input.RequiredPorts = append(input.RequiredPorts, input.RequiredPorts[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.RequiredPorts = append([]LoopbackEndpoint(nil), base.RequiredPorts...)
			test.mutate(&input)
			if _, err := NewPlan(input); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("NewPlan() error = %v", err)
			}
		})
	}

	plan := hostPlanFixture(t)
	raw := plan.CanonicalBytes()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["unknown"] = true
	unknown, _ := json.Marshal(document)
	if _, err := DecodePlan(unknown); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown error = %v", err)
	}
	nonCanonical := append([]byte(" "), raw...)
	if _, err := DecodePlan(nonCanonical); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("noncanonical error = %v", err)
	}
	duplicate := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
	if _, err := DecodePlan(duplicate); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := DecodePlan(append(raw, []byte("{}")...)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing error = %v", err)
	}
	unsupported := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
	if _, err := DecodePlan(unsupported); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("schema error = %v", err)
	}
	if _, err := DecodePlan(make([]byte, maximumPlanSize+1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestPF001HostTargetValidationIsPlatformExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		os     OperatingSystem
		target string
		want   bool
	}{
		{OperatingSystemLinux, "/home/user/.agentmemory", true},
		{OperatingSystemMacOS, "/Users/user/Library/Application Support/AgentMemory", true},
		{OperatingSystemLinux, "//tmp/x", false},
		{OperatingSystemMacOS, "/tmp/x/", false},
		{OperatingSystemWindows, `C:\Users\user\AgentMemory`, true},
		{OperatingSystemWindows, `C:\Users\..\Windows`, false},
		{OperatingSystemWindows, `\\server\share`, false},
		{OperatingSystemWindows, `C:/Users/user`, false},
	}
	for _, test := range tests {
		if got := validTarget(test.os, test.target); got != test.want {
			t.Errorf("validTarget(%q, %q) = %v", test.os, test.target, got)
		}
	}
}

func TestPF001ReleasePolicyAllowsParentBoundOwnerStorageSelection(t *testing.T) {
	t.Parallel()
	input := hostPlanInput(t)
	input.StorageTargetMode = StorageTargetOwnerSelected
	input.StorageTarget = ""
	plan, err := NewPlan(input)
	if err != nil || plan.StorageTargetMode() != StorageTargetOwnerSelected || plan.StorageTarget() != "" {
		t.Fatalf("owner-selected plan=%+v,%v", plan, err)
	}
	decoded, err := DecodePlan(plan.CanonicalBytes())
	if err != nil || !decoded.Digest().Equal(plan.Digest()) {
		t.Fatalf("owner-selected decode=%+v,%v", decoded, err)
	}
	observationInput := observationInput(plan)
	observationInput.StorageTarget = "/home/another-user/.agentmemory"
	observation, err := NewObservation(observationInput)
	if err != nil || plan.Evaluate(observation) != FailureNone {
		t.Fatalf("owner-selected observation=%v reason=%s", err, plan.Evaluate(observation))
	}
	input.StorageTarget = "/release-builder/path"
	if _, err := NewPlan(input); err == nil {
		t.Fatal("owner-selected policy accepted a release-machine path")
	}
}

func TestPF001HostPlanCanonicalizationIsDeterministicProperty(t *testing.T) {
	t.Parallel()
	base := hostPlanInput(t)
	seed := uint32(0x9e3779b9)
	for iteration := 0; iteration < 512; iteration++ {
		seed = seed*1664525 + 1013904223
		first := uint16(seed%60000 + 1024)
		seed = seed*1664525 + 1013904223
		second := uint16(seed%60000 + 1024)
		if first == second {
			second++
		}
		left := base
		left.RequiredPorts = []LoopbackEndpoint{{Family: LoopbackIPv6, Port: second}, {Family: LoopbackIPv4, Port: first}}
		right := base
		right.RequiredPorts = []LoopbackEndpoint{{Family: LoopbackIPv4, Port: first}, {Family: LoopbackIPv6, Port: second}}
		leftPlan, leftErr := NewPlan(left)
		rightPlan, rightErr := NewPlan(right)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftPlan.CanonicalBytes(), rightPlan.CanonicalBytes()) {
			t.Fatalf("canonicalization diverged at iteration %d: %v, %v", iteration, leftErr, rightErr)
		}
	}
}

func hostPlanFixture(t *testing.T) Plan {
	t.Helper()
	plan, err := NewPlan(hostPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func hostPlanInput(t *testing.T) Input {
	t.Helper()
	return Input{
		PolicyID: "host-policy-2026-07", SigningKeyID: "host-root-1",
		Platform:        PlatformTuple{OperatingSystem: OperatingSystemLinux, Product: "ubuntu", Architecture: ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic"},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: "/home/user/.agentmemory",
		RequiredPorts: []LoopbackEndpoint{{Family: LoopbackIPv6, Port: 4318}, {Family: LoopbackIPv4, Port: 4317}},
	}
}

func TestPF001HostPlanDecodeRejectsMalformedStrings(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{"), []byte(strings.Repeat("x", maximumPlanSize+1))} {
		if _, err := DecodePlan(raw); err == nil {
			t.Fatalf("DecodePlan(%q) succeeded", raw[:min(len(raw), 32)])
		}
	}
}
