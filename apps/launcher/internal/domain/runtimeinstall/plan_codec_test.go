package runtimeinstall

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalPlanV1RoundTripsEveryDecisionInput(t *testing.T) {
	t.Parallel()
	plan, err := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePlanV1(plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Action() != PlanActionInstallCertified || decoded.DecisionCode() != DecisionOK ||
		decoded.Digest() != Sum(plan.CanonicalBytes()) || decoded.Digest() != plan.Digest() ||
		decoded.CatalogDigest() != certifiedCatalog(t).CatalogDigest() {
		t.Fatal("decoded runtime plan lost an exact derived binding")
	}
	mutable := decoded.CanonicalBytes()
	mutable[0] ^= 0xff
	if bytes.Equal(mutable, decoded.CanonicalBytes()) {
		t.Fatal("CanonicalBytes exposed mutable storage")
	}
}

func TestDecodePlanV1RejectsUnsignedNormalizationAndContradictions(t *testing.T) {
	t.Parallel()
	plan, err := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := plan.CanonicalBytes()
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrPlanMalformed},
		{name: "whitespace", raw: append([]byte(" "), canonical...), want: ErrPlanNonCanonical},
		{name: "duplicate nested", raw: bytes.Replace(canonical, []byte(`"architecture":`), []byte(`"architecture":"arm64","architecture":`), 1), want: ErrPlanDuplicateKey},
		{name: "unknown nested", raw: bytes.Replace(canonical, []byte(`"architecture":`), []byte(`"ambient_path":"docker","architecture":`), 1), want: ErrPlanUnknownField},
		{name: "unsupported schema", raw: bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1), want: ErrPlanUnsupportedSchema},
		{name: "contradictory action", raw: bytes.Replace(canonical, []byte(`"action":"install_certified"`), []byte(`"action":"block"`), 1), want: ErrPlanIntegrity},
		{name: "unsafe integer", raw: bytes.Replace(canonical, []byte(`"catalog_sequence":42`), []byte(`"catalog_sequence":9007199254740992`), 1), want: ErrPlanIntegrity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, decodeError := DecodePlanV1(test.raw); !errors.Is(decodeError, test.want) {
				t.Fatalf("DecodePlanV1() error = %v, want %v", decodeError, test.want)
			}
		})
	}
}

func TestNewPlanV1RejectsInvalidZeroFacts(t *testing.T) {
	t.Parallel()
	if _, err := NewPlanV1(HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("NewPlanV1() error = %v, want integrity", err)
	}
	fallback := NewPlanPolicy().Decide(HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{})
	if fallback.Action() != PlanActionBlock || fallback.Digest().IsZero() || len(fallback.CanonicalBytes()) != 0 {
		t.Fatal("total policy did not fail closed for invalid zero facts")
	}
}

func TestNewPlanV1RejectsOutOfVocabularyTypedFacts(t *testing.T) {
	t.Parallel()
	host, err := NewHostCapabilities(
		Platform(255), ArchitectureARM64, "1.0", true, true, true, true,
		8, 32*gib, 24*gib, 100*gib,
	)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := NewRuntimeDiscovery(
		RuntimeCondition(255), "docker", "28.0.0", "unix:///local/docker.sock",
		true, true, true, OwnershipDisposition(255), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCertifiedRuntime(
		Platform(255), ArchitectureAMD64, "docker", "28.0.0", "stable", 42,
		Sum([]byte("catalog")), Sum([]byte("terms")), 1024, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		host      HostCapabilities
		discovery RuntimeDiscovery
		catalog   CertifiedRuntime
	}{
		{host: host, discovery: NewAbsentRuntimeDiscovery(), catalog: certifiedCatalog(t)},
		{host: supportedHost(t), discovery: discovery, catalog: certifiedCatalog(t)},
		{host: supportedHost(t), discovery: NewAbsentRuntimeDiscovery(), catalog: catalog},
	} {
		if _, err := NewPlanV1(input.host, input.discovery, input.catalog); !errors.Is(err, ErrPlanIntegrity) {
			t.Fatalf("NewPlanV1() error = %v, want integrity", err)
		}
	}
}

func TestDecodePlanV1CoversEveryClosedPlatformAndDiscoveryToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		platform     Platform
		architecture Architecture
		condition    RuntimeCondition
		ownership    OwnershipDisposition
	}{
		{name: "darwin absent", platform: PlatformDarwin, architecture: ArchitectureARM64, condition: RuntimeConditionAbsent},
		{name: "linux running", platform: PlatformLinux, architecture: ArchitectureAMD64, condition: RuntimeConditionRunning, ownership: OwnershipReusedExternal},
		{name: "windows stopped", platform: PlatformWindows, architecture: ArchitectureAMD64, condition: RuntimeConditionStopped, ownership: OwnershipReusedExternal},
		{name: "linux incompatible", platform: PlatformLinux, architecture: ArchitectureARM64, condition: RuntimeConditionIncompatible, ownership: OwnershipReusedExternal},
		{name: "windows damaged", platform: PlatformWindows, architecture: ArchitectureARM64, condition: RuntimeConditionDamaged, ownership: OwnershipProvisionedByAgentMemory},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host, err := NewHostCapabilities(
				test.platform, test.architecture, "1.0", true, true, true, true,
				8, 32*gib, 24*gib, 100*gib,
			)
			if err != nil {
				t.Fatal(err)
			}
			discovery := NewAbsentRuntimeDiscovery()
			if test.condition != RuntimeConditionAbsent {
				discovery, err = NewRuntimeDiscovery(
					test.condition, "docker", "28.0.0", "unix:///local/docker.sock",
					true, true, test.condition != RuntimeConditionDamaged, test.ownership, 1,
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			catalog, err := NewCertifiedRuntime(
				test.platform, test.architecture, "docker", "28.0.0", "stable", 42,
				Sum([]byte("catalog:"+test.name)), Sum([]byte("terms")), 1024, 4096,
			)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewPlanV1(host, discovery, catalog)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodePlanV1(plan.CanonicalBytes())
			if err != nil || decoded.Digest() != plan.Digest() {
				t.Fatalf("DecodePlanV1() = %+v/%v", decoded, err)
			}
		})
	}
}

func TestDecodePlanV1RejectsInvalidClosedTokensDepthAndHashes(t *testing.T) {
	t.Parallel()
	plan, err := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := plan.CanonicalBytes()
	invalid := [][]byte{
		append(append([]byte(nil), canonical...), 'x'),
		[]byte(`[]`),
		[]byte(strings.Repeat(`{"x":`, maximumPlanJSONDepth+2) + `0` + strings.Repeat(`}`, maximumPlanJSONDepth+2)),
		bytes.Replace(canonical, []byte(`"platform":"darwin"`), []byte(`"platform":"freebsd"`), 1),
		bytes.Replace(canonical, []byte(`"architecture":"arm64"`), []byte(`"architecture":"riscv64"`), 1),
		bytes.Replace(canonical, []byte(`"condition":"absent"`), []byte(`"condition":"unknown"`), 1),
		bytes.Replace(canonical, []byte(`"decision_code":"ok"`), []byte(`"decision_code":"unknown"`), 1),
		bytes.Replace(canonical, []byte(`"action":"install_certified"`), []byte(`"action":"unknown"`), 1),
	}
	for _, raw := range invalid {
		if _, err := DecodePlanV1(raw); err == nil {
			t.Fatal("DecodePlanV1 accepted invalid closed runtime authority")
		}
	}
	for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("G", 64), strings.ToUpper(Sum([]byte("hash")).String())} {
		if _, err := ParseHash(value); !errors.Is(err, ErrPlanIntegrity) {
			t.Fatalf("ParseHash(%q) error = %v", value, err)
		}
	}
}

func FuzzDecodePlanV1(f *testing.F) {
	host, err := NewHostCapabilities(
		PlatformDarwin, ArchitectureARM64, "26.0", true, true, true, true,
		8, 32*gib, 24*gib, 100*gib,
	)
	if err != nil {
		f.Fatal(err)
	}
	catalog, err := NewCertifiedRuntime(
		PlatformDarwin, ArchitectureARM64, "docker-desktop", "4.40.0", "stable", 42,
		Sum([]byte("catalog")), Sum([]byte("terms")), 1024, 2048,
	)
	if err != nil {
		f.Fatal(err)
	}
	plan, err := NewPlanV1(host, NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(plan.CanonicalBytes())
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		plan, decodeError := DecodePlanV1(raw)
		if decodeError != nil {
			return
		}
		if !bytes.Equal(raw, plan.CanonicalBytes()) || plan.Digest() != Sum(raw) {
			t.Fatal("successful decode normalized or rebound unsigned runtime plan bytes")
		}
	})
}
