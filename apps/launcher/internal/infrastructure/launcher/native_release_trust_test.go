package launcher

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	releaseverifyadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001NativeReleaseTrustDecodesOnlyCompleteEmbeddedPublicAuthority(t *testing.T) {
	t.Parallel()
	document := nativeReleaseTrustFixture()
	trust, err := decodeNativeReleaseTrust(encodeNativeReleaseTrust(t, document))
	if err != nil || len(trust.ManifestKeys) != 1 || len(trust.HostPolicyKeys) != 1 ||
		len(trust.RuntimeCatalogKeys) != 1 || len(trust.RuntimePublishers) != 1 ||
		len(trust.Offline.RevocationAuthorities) != 1 || len(trust.Offline.TimeAuthorities) != 1 ||
		trust.Offline.TrustDomain != "agentmemory.release" || trust.Offline.MaximumFutureSkew.Seconds() != 300 ||
		len(trust.Provenance.BuildIdentities) != 1 || len(trust.Provenance.RecipeDigests) != 1 ||
		len(trust.Qualification.PublicKeys) != 1 || len(trust.Qualification.LicensePolicySigners) != 1 ||
		len(trust.Qualification.VulnerabilityPolicySigners) != 1 || len(trust.Publishers) != 1 {
		t.Fatalf("trust=%+v error=%v", trust, err)
	}
	manifest := trust.ManifestKeys["release-root"]
	manifest[0] ^= 0xff
	again, err := decodeNativeReleaseTrust(encodeNativeReleaseTrust(t, document))
	if err != nil || again.ManifestKeys["release-root"][0] != 1 {
		t.Fatalf("decoded trust aliases prior output: key=%v error=%v", again.ManifestKeys, err)
	}
}

func TestPF001NativeReleaseTrustRejectsEveryIncompleteSemanticAuthority(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*nativeReleaseTrustDocument){
		"schema":               func(document *nativeReleaseTrustDocument) { document.SchemaVersion++ },
		"manifest keys":        func(document *nativeReleaseTrustDocument) { document.ManifestKeys = nil },
		"host policy keys":     func(document *nativeReleaseTrustDocument) { document.HostPolicyKeys = nil },
		"runtime catalog keys": func(document *nativeReleaseTrustDocument) { document.RuntimeCatalogKeys = nil },
		"runtime publishers":   func(document *nativeReleaseTrustDocument) { document.RuntimePublishers = nil },
		"duplicate runtime publisher": func(document *nativeReleaseTrustDocument) {
			document.RuntimePublishers = append(document.RuntimePublishers, document.RuntimePublishers[0])
		},
		"invalid runtime publisher": func(document *nativeReleaseTrustDocument) {
			document.RuntimePublishers[0].PackageIdentity = "foreign?package"
		},
		"manifest key bytes": func(document *nativeReleaseTrustDocument) {
			document.ManifestKeys["release-root"] = base64.StdEncoding.EncodeToString([]byte("short"))
		},
		"revocation keys":  func(document *nativeReleaseTrustDocument) { document.Offline.RevocationAuthorities = nil },
		"time keys":        func(document *nativeReleaseTrustDocument) { document.Offline.TimeAuthorities = nil },
		"time policy":      func(document *nativeReleaseTrustDocument) { document.Offline.MaximumFutureSkewSeconds = 601 },
		"trust domain":     func(document *nativeReleaseTrustDocument) { document.Offline.TrustDomain = "" },
		"build identities": func(document *nativeReleaseTrustDocument) { document.Provenance.BuildIdentities = nil },
		"recipe digests":   func(document *nativeReleaseTrustDocument) { document.Provenance.RecipeDigests = nil },
		"bad recipe":       func(document *nativeReleaseTrustDocument) { document.Provenance.RecipeDigests[0] = "invalid" },
		"duplicate recipe": func(document *nativeReleaseTrustDocument) {
			document.Provenance.RecipeDigests = append(document.Provenance.RecipeDigests, document.Provenance.RecipeDigests[0])
		},
		"qualification keys": func(document *nativeReleaseTrustDocument) { document.Qualification.PublicKeys = nil },
		"license policy":     func(document *nativeReleaseTrustDocument) { document.Qualification.LicensePolicySigners = nil },
		"vulnerability policy": func(document *nativeReleaseTrustDocument) {
			document.Qualification.VulnerabilityPolicySigners = nil
		},
		"foreign qualification signer": func(document *nativeReleaseTrustDocument) {
			for digest := range document.Qualification.LicensePolicySigners {
				document.Qualification.LicensePolicySigners[digest] = "foreign"
			}
		},
		"publisher policy": func(document *nativeReleaseTrustDocument) { document.Publishers = nil },
		"duplicate publisher": func(document *nativeReleaseTrustDocument) {
			document.Publishers["agentmemory-native-2026"] = []string{"agentmemory.publisher", "agentmemory.publisher"}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := nativeReleaseTrustFixture()
			mutate(&document)
			if trust, err := decodeNativeReleaseTrust(encodeNativeReleaseTrust(t, document)); !errors.Is(err, errNativeInstallerIntegrity) || len(trust.ManifestKeys) != 0 {
				t.Fatalf("decode=(%+v,%v)", trust, err)
			}
		})
	}
}

func TestPF001NativeReleaseTrustRejectsAmbiguousOrNoncanonicalTransport(t *testing.T) {
	t.Parallel()
	valid := encodeNativeReleaseTrust(t, nativeReleaseTrustFixture())
	raw, err := base64.StdEncoding.DecodeString(valid)
	if err != nil {
		t.Fatal(err)
	}
	wires := map[string]string{
		"empty":               "",
		"invalid base64":      "%%%",
		"noncanonical base64": valid + "=",
		"unknown field": base64.StdEncoding.EncodeToString(
			[]byte(strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"future":true`, 1)),
		),
		"duplicate field": base64.StdEncoding.EncodeToString(
			[]byte(strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
		),
		"trailing": base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), []byte(` {}`)...)),
		"scalar":   base64.StdEncoding.EncodeToString([]byte(`true`)),
		"broken":   base64.StdEncoding.EncodeToString([]byte(`{"schemaVersion":`)),
	}
	for name, wire := range wires {
		if trust, decodeError := decodeNativeReleaseTrust(wire); !errors.Is(decodeError, errNativeInstallerIntegrity) ||
			len(trust.ManifestKeys) != 0 {
			t.Fatalf("%s decode=(%+v,%v)", name, trust, decodeError)
		}
	}
}

func TestPF001NativeReleaseBuildHasNoDevelopmentTrustFallback(t *testing.T) {
	previous := embeddedNativeReleaseTrustBase64
	embeddedNativeReleaseTrustBase64 = ""
	t.Cleanup(func() { embeddedNativeReleaseTrustBase64 = previous })
	if trust, err := loadEmbeddedNativeReleaseTrust(); !errors.Is(err, errNativeInstallerIntegrity) ||
		len(trust.ManifestKeys) != 0 {
		t.Fatalf("source build trust=(%+v,%v)", trust, err)
	}
}

func nativeReleaseTrustFixture() nativeReleaseTrustDocument {
	key := base64.StdEncoding.EncodeToString(ed25519.PublicKey{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})
	license := releaseinventory.DigestBytes([]byte("license policy")).Hex()
	vulnerability := releaseinventory.DigestBytes([]byte("vulnerability policy")).Hex()
	return nativeReleaseTrustDocument{
		SchemaVersion:      nativeReleaseTrustSchemaVersion,
		ManifestKeys:       map[string]string{"release-root": key},
		HostPolicyKeys:     map[string]string{"host-policy-root": key},
		RuntimeCatalogKeys: map[string]string{"runtime-catalog-root": key},
		RuntimePublishers: []runtimeprovision.RuntimePublisherPolicyInput{{
			Verification:       runtimecatalog.NativeVerificationAppleNotarized,
			Identity:           "developer-id-application-docker-inc-9bnsxjn65r",
			SigningKeyIdentity: "apple-developer-id-9bnsxjn65r", PackageIdentity: "com.docker.docker",
			NativeTrustSHA256: releaseinventory.DigestBytes([]byte("docker native certificate")).Hex(),
		}},
		Offline: nativeOfflineTrustDocument{
			TrustDomain: "agentmemory.release", RevocationAuthorities: map[string]string{"revocation-root": key},
			TimeAuthorities: map[string]string{"time-root": key}, MaximumFutureSkewSeconds: 300,
		},
		Provenance: nativeProvenanceDocument{
			BuildIdentities: []releaseverifyadapter.ProvenanceBuildIdentity{{
				BuilderID: "https://github.com/actions/runner", BuildType: "https://agentmemory.dev/build/v1",
				SourceRepository: "https://github.com/rickyseezy/AgentMemory", WorkflowPath: ".github/workflows/release.yml",
			}},
			RecipeDigests: []string{releaseinventory.DigestBytes([]byte("release recipe")).Hex()},
		},
		Qualification: nativeQualificationDocument{
			PublicKeys:                 map[string]string{"qualification-root": key},
			LicensePolicySigners:       map[string]string{license: "qualification-root"},
			VulnerabilityPolicySigners: map[string]string{vulnerability: "qualification-root"},
		},
		Publishers: map[string][]string{"agentmemory-native-2026": {"agentmemory.publisher"}},
	}
}

func encodeNativeReleaseTrust(t testing.TB, document nativeReleaseTrustDocument) string {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
