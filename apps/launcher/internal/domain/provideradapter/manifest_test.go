package provideradapter

import (
	"strings"
	"testing"
)

func TestPRO002ManifestProducesClosedLeastPrivilegeDeploymentPlan(t *testing.T) {
	t.Parallel()
	manifest, err := NewManifest(validManifestInput())
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	plan, err := manifest.DeploymentPlan("018f0000-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatalf("deployment plan: %v", err)
	}
	if plan.Image() != "registry.example/custom/python@sha256:"+digestOf("image").Hex() ||
		plan.User() != "65532:65532" || !plan.ReadOnlyRootFS() || !plan.NoNewPrivileges() ||
		plan.Privileged() || plan.HostNetwork() || plan.PublishPort() ||
		plan.Network() != "am_internal" || plan.ScratchTarget() != "/tmp" ||
		plan.CapabilitySecret() != "agentmemory_018f0000000070008000000000000711_provider-adapter-egress" {
		t.Fatalf("unsafe or incomplete closed plan: %#v", plan)
	}
	if plan.CPUsMilli() != 500 || plan.MemoryBytes() != 536870912 || plan.PIDs() != 64 ||
		plan.TimeoutMilliseconds() != 30000 || plan.Digest().IsZero() {
		t.Fatalf("resource or digest binding lost: %#v", plan)
	}
	if manifest.Protocol().Minimum() != 1 || manifest.Protocol().Maximum() != 1 ||
		!manifest.Supports(OperationEmbedDocuments) || !manifest.Supports(OperationCancel) ||
		manifest.Supports(OperationListModels) {
		t.Fatalf("protocol capability contract lost")
	}
}

func TestPRO002ManifestRejectsMutableImagesEvidenceGapsAndExcessPermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ManifestInput)
	}{
		{"tagged image", func(input *ManifestInput) { input.Image = "registry.example/custom:latest" }},
		{"digest disagreement", func(input *ManifestInput) { input.ImageDigest = digestOf("other") }},
		{"missing signature", func(input *ManifestInput) { input.Evidence.SignatureBundle = Digest{} }},
		{"missing cyclone dx", func(input *ManifestInput) { input.Evidence.CycloneDXSBOM = Digest{} }},
		{"missing spdx", func(input *ManifestInput) { input.Evidence.SPDXSBOM = Digest{} }},
		{"missing provenance", func(input *ManifestInput) { input.Evidence.Provenance = Digest{} }},
		{"missing license", func(input *ManifestInput) { input.Evidence.License = Digest{} }},
		{"missing vulnerability", func(input *ManifestInput) { input.Evidence.Vulnerability = Digest{} }},
		{"host network", func(input *ManifestInput) { input.Permissions.HostNetwork = true }},
		{"host listener", func(input *ManifestInput) { input.Permissions.PublishPort = true }},
		{"docker socket", func(input *ManifestInput) { input.Permissions.DockerSocket = true }},
		{"project mount", func(input *ManifestInput) { input.Permissions.ProjectMount = true }},
		{"writable mount", func(input *ManifestInput) { input.Permissions.WritableMount = true }},
		{"extra secret", func(input *ManifestInput) { input.Permissions.AdditionalSecrets = true }},
		{"direct egress", func(input *ManifestInput) { input.Permissions.DirectEgress = true }},
		{"privileged", func(input *ManifestInput) { input.Permissions.Privileged = true }},
		{"incompatible protocol", func(input *ManifestInput) { input.Protocol = ProtocolRangeInput{2, 3} }},
		{"missing shutdown", func(input *ManifestInput) { input.Operations = without(input.Operations, OperationShutdown) }},
		{"missing cancellation", func(input *ManifestInput) { input.Operations = without(input.Operations, OperationCancel) }},
		{"duplicate operation", func(input *ManifestInput) { input.Operations = append(input.Operations, OperationHealth) }},
		{"unbounded cpu", func(input *ManifestInput) { input.Limits.CPUsMilli = 0 }},
		{"oversized memory", func(input *ManifestInput) { input.Limits.MemoryBytes = maximumMemoryBytes + 1 }},
		{"unknown transport", func(input *ManifestInput) { input.Transport = "grpc" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validManifestInput()
			test.mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid custom-adapter manifest accepted")
			}
		})
	}
}

func TestPRO002ManifestAndPlanAreImmutableAndDeterministic(t *testing.T) {
	t.Parallel()
	input := validManifestInput()
	manifest, err := NewManifest(input)
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	input.Operations[0] = OperationListModels
	if !manifest.Supports(OperationGetManifest) || manifest.Supports(OperationListModels) {
		t.Fatal("manifest retained caller-owned operation storage")
	}
	second, err := NewManifest(validManifestInput())
	if err != nil || !manifest.Digest().Equal(second.Digest()) {
		t.Fatal("canonical manifest digest is not deterministic")
	}
	firstPlan, _ := manifest.DeploymentPlan("018f0000-0000-7000-8000-000000000711")
	secondPlan, _ := second.DeploymentPlan("018f0000-0000-7000-8000-000000000711")
	if !firstPlan.Digest().Equal(secondPlan.Digest()) ||
		!strings.HasPrefix(firstPlan.ServiceName(), "custom-provider-") {
		t.Fatal("closed deployment plan is not deterministic")
	}
	if _, err := manifest.DeploymentPlan("user-controlled-project-name"); err == nil {
		t.Fatal("untrusted installation identity entered a service name")
	}
}

func validManifestInput() ManifestInput {
	digest := digestOf("image")
	return ManifestInput{
		AdapterID: "python-reference", Image: "registry.example/custom/python@sha256:" + digest.Hex(),
		ImageDigest: digest, Protocol: ProtocolRangeInput{Minimum: 1, Maximum: 1},
		Transport: TransportAuthenticatedHTTP,
		Operations: []Operation{
			OperationGetManifest, OperationValidateConfiguration, OperationProbe, OperationHealth,
			OperationEmbedDocuments, OperationEmbedQueries, OperationRerank, OperationEstimateCost,
			OperationCancel, OperationShutdown,
		},
		Permissions: PermissionInput{GatewayAccess: true},
		Limits:      LimitInput{CPUsMilli: 500, MemoryBytes: 536870912, PIDs: 64, TimeoutMilliseconds: 30000, ScratchBytes: 67108864},
		Evidence: EvidenceInput{
			SignatureBundle: digestOf("signature"), CycloneDXSBOM: digestOf("cyclonedx"),
			SPDXSBOM: digestOf("spdx"), Provenance: digestOf("provenance"),
			License: digestOf("license"), Vulnerability: digestOf("vulnerability"),
		},
	}
}

func digestOf(value string) Digest {
	return DigestBytes([]byte(value))
}

func without(values []Operation, target Operation) []Operation {
	result := make([]Operation, 0, len(values))
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
