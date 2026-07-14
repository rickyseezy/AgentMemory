package runtimeinstall

import (
	"testing"
)

const gib = uint64(1024 * 1024 * 1024)

func TestPF001RuntimePlanPolicySelectsOnlySafeClosedActions(t *testing.T) {
	t.Parallel()

	supported := supportedHost(t)
	catalog := certifiedCatalog(t)

	tests := []struct {
		name      string
		discovery RuntimeDiscovery
		want      PlanAction
		wantCode  DecisionCode
	}{
		{
			name:      "pristine host installs certified runtime",
			discovery: NewAbsentRuntimeDiscovery(),
			want:      PlanActionInstallCertified,
		},
		{
			name:      "compatible running local runtime is adopted",
			discovery: compatibleRuntime(t, RuntimeConditionRunning),
			want:      PlanActionAdoptCompatible,
		},
		{
			name:      "compatible stopped local runtime is started",
			discovery: compatibleRuntime(t, RuntimeConditionStopped),
			want:      PlanActionStartCompatible,
		},
		{
			name:      "managed damaged runtime may be repaired",
			discovery: managedDamagedRuntime(t),
			want:      PlanActionRepairManaged,
		},
		{
			name:      "remote endpoint is blocked",
			discovery: remoteRuntime(t),
			want:      PlanActionBlock,
			wantCode:  DecisionRuntimeRemote,
		},
		{
			name:      "untrusted binary is blocked",
			discovery: untrustedRuntime(t),
			want:      PlanActionBlock,
			wantCode:  DecisionRuntimeUntrusted,
		},
		{
			name:      "external incompatible runtime is blocked",
			discovery: externalIncompatibleRuntime(t),
			want:      PlanActionBlock,
			wantCode:  DecisionRuntimeConflict,
		},
	}

	policy := NewPlanPolicy()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			plan := policy.Decide(supported, test.discovery, catalog)
			if plan.Action() != test.want {
				t.Fatalf("action = %s, want %s", plan.Action(), test.want)
			}
			if plan.DecisionCode() != test.wantCode {
				t.Fatalf("decision code = %s, want %s", plan.DecisionCode(), test.wantCode)
			}
			if plan.Digest().IsZero() {
				t.Fatal("plan digest must be bound to every decision, including Block")
			}
		})
	}
}

func TestPF001RuntimePlanPolicyBlocksEveryUncertifiedHostInvariant(t *testing.T) {
	t.Parallel()

	catalog := certifiedCatalog(t)
	absent := NewAbsentRuntimeDiscovery()
	tests := []struct {
		name string
		host HostCapabilities
		code DecisionCode
	}{
		{name: "unsupported platform", host: hostWith(t, false, true, true, true, 4, 16*gib, 12*gib, 30*gib), code: DecisionUnsupportedPlatform},
		{name: "virtualization disabled", host: hostWith(t, true, false, true, true, 4, 16*gib, 12*gib, 30*gib), code: DecisionVirtualizationUnavailable},
		{name: "nonlocal filesystem", host: hostWith(t, true, true, false, true, 4, 16*gib, 12*gib, 30*gib), code: DecisionNonLocalFilesystem},
		{name: "disk encryption not attested", host: hostWith(t, true, true, true, false, 4, 16*gib, 12*gib, 30*gib), code: DecisionEncryptionUnattested},
		{name: "too few CPUs", host: hostWith(t, true, true, true, true, 3, 16*gib, 12*gib, 30*gib), code: DecisionInsufficientCPU},
		{name: "too little total memory", host: hostWith(t, true, true, true, true, 4, 15*gib, 12*gib, 30*gib), code: DecisionInsufficientMemory},
		{name: "too little available memory", host: hostWith(t, true, true, true, true, 4, 16*gib, 11*gib, 30*gib), code: DecisionInsufficientMemory},
		{name: "too little disk", host: hostWith(t, true, true, true, true, 4, 16*gib, 12*gib, 30*gib-1), code: DecisionInsufficientDisk},
	}

	policy := NewPlanPolicy()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			plan := policy.Decide(test.host, absent, catalog)
			if plan.Action() != PlanActionBlock || plan.DecisionCode() != test.code {
				t.Fatalf("decision = %s/%s, want block/%s", plan.Action(), plan.DecisionCode(), test.code)
			}
		})
	}
}

func TestPF001RuntimePlanDigestChangesForMaterialInputAndIsDeterministic(t *testing.T) {
	t.Parallel()

	policy := NewPlanPolicy()
	host := supportedHost(t)
	discovery := NewAbsentRuntimeDiscovery()
	catalog := certifiedCatalog(t)

	first := policy.Decide(host, discovery, catalog)
	second := policy.Decide(host, discovery, catalog)
	if first.Digest() != second.Digest() {
		t.Fatal("identical inputs produced different plan digests")
	}

	changed, err := NewCertifiedRuntime(
		catalog.Platform(),
		catalog.Architecture(),
		"docker-desktop",
		"4.99.1",
		"stable",
		catalog.CatalogSequence()+1,
		mustHash(t, "changed-catalog"),
		runtimeTermsFixture(catalog.Platform(), catalog.TermsDigest()),
		catalog.DownloadBytes(),
		catalog.ExpandedBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() == policy.Decide(host, discovery, changed).Digest() {
		t.Fatal("material catalog change did not change plan digest")
	}
}

func supportedHost(t *testing.T) HostCapabilities {
	t.Helper()
	return hostWith(t, true, true, true, true, 8, 32*gib, 24*gib, 100*gib)
}

func hostWith(
	t *testing.T,
	certified bool,
	virtualization bool,
	localFilesystem bool,
	encrypted bool,
	cpus uint16,
	totalMemory uint64,
	availableMemory uint64,
	freeDisk uint64,
) HostCapabilities {
	t.Helper()
	host, err := NewHostCapabilities(
		PlatformDarwin,
		ArchitectureARM64,
		"26.0",
		certified,
		virtualization,
		localFilesystem,
		encrypted,
		cpus,
		totalMemory,
		availableMemory,
		freeDisk,
	)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func certifiedCatalog(t *testing.T) CertifiedRuntime {
	t.Helper()
	catalog, err := NewCertifiedRuntime(
		PlatformDarwin,
		ArchitectureARM64,
		"docker-desktop",
		"4.99.0",
		"stable",
		42,
		mustHash(t, "catalog"),
		runtimeTermsFixture(PlatformDarwin, mustHash(t, "terms")),
		2*gib,
		8*gib,
	)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func compatibleRuntime(t *testing.T, condition RuntimeCondition) RuntimeDiscovery {
	t.Helper()
	discovery, err := NewRuntimeDiscovery(
		condition,
		"docker-desktop",
		"4.99.0",
		"unix:///local/docker.sock",
		true,
		true,
		true,
		OwnershipReusedExternal,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return discovery
}

func managedDamagedRuntime(t *testing.T) RuntimeDiscovery {
	t.Helper()
	discovery, err := NewRuntimeDiscovery(
		RuntimeConditionDamaged,
		"docker-desktop",
		"4.99.0",
		"unix:///local/docker.sock",
		true,
		true,
		false,
		OwnershipProvisionedByAgentMemory,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return discovery
}

func remoteRuntime(t *testing.T) RuntimeDiscovery {
	t.Helper()
	discovery, err := NewRuntimeDiscovery(
		RuntimeConditionRunning,
		"docker",
		"27.0.0",
		"tcp://example.invalid:2375",
		false,
		true,
		true,
		OwnershipReusedExternal,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	return discovery
}

func untrustedRuntime(t *testing.T) RuntimeDiscovery {
	t.Helper()
	discovery, err := NewRuntimeDiscovery(
		RuntimeConditionRunning,
		"docker",
		"27.0.0",
		"unix:///local/docker.sock",
		true,
		false,
		true,
		OwnershipReusedExternal,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return discovery
}

func externalIncompatibleRuntime(t *testing.T) RuntimeDiscovery {
	t.Helper()
	discovery, err := NewRuntimeDiscovery(
		RuntimeConditionIncompatible,
		"docker",
		"20.0.0",
		"unix:///local/docker.sock",
		true,
		true,
		false,
		OwnershipReusedExternal,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	return discovery
}

func mustHash(t *testing.T, value string) Hash {
	t.Helper()
	return Sum([]byte(value))
}
