package installplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestCanonicalPlanRoundTripsExactImmutableBindings(t *testing.T) {
	t.Parallel()
	input := validPlanInput(t)
	plan, err := NewV1(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeV1(plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Digest().Equal(plan.Digest()) || decoded.OperationID() != input.OperationID ||
		decoded.InstallationID() != input.InstallationID || decoded.GenerationID() != input.GenerationID ||
		decoded.RuntimeEndpoint() != input.RuntimeEndpoint || decoded.RuntimeOwnership() != input.RuntimeOwnership ||
		decoded.SecurityEpoch() != input.SecurityEpoch || decoded.RuntimeCatalogResourceID() != "runtime-catalog" ||
		decoded.RuntimeCatalogDigest().IsZero() || decoded.ComposeArtifactID() != "compose" ||
		!decoded.SignedHostPlan().Valid() ||
		!decoded.SignedHostPlan().Plan().Digest().Equal(input.SignedHostPlan.Plan().Digest()) ||
		decoded.Product().ReleaseDirectory() != input.Product.ReleaseDirectory ||
		decoded.Product().CoreEndpoint() != input.Product.CoreEndpoint ||
		decoded.Product().InitialBrainID() != input.Product.InitialBrainID ||
		decoded.Product().InitialBrainName() != input.Product.InitialBrainName ||
		decoded.Product().OwnerPrincipalID() != input.Product.OwnerPrincipalID ||
		decoded.Product().OwnerGrantID() != input.Product.OwnerGrantID ||
		!decoded.Product().OwnerSubjectDigest().Equal(input.Product.OwnerSubjectDigest) ||
		len(decoded.Product().SecretFiles()) != 7 {
		t.Fatal("decoded plan lost a required binding")
	}
	bound, err := install.BindPlan(plan.CanonicalBytes())
	if err != nil || !bound.Equal(plan.Digest()) {
		t.Fatal("plan digest is not SHA-256 bound to exact canonical bytes")
	}
	canonical := plan.CanonicalBytes()
	canonical[0] ^= 0xff
	if bytes.Equal(canonical, plan.CanonicalBytes()) {
		t.Fatal("CanonicalBytes exposed mutable storage")
	}
	artifacts := decoded.AcquisitionPlan().Artifacts()
	artifacts[0] = artifactacquisition.Artifact{}
	if len(decoded.AcquisitionPlan().Artifacts()) == 0 || decoded.AcquisitionPlan().Artifacts()[0].ID() == "" {
		t.Fatal("acquisition projection exposed mutable storage")
	}
	capacity := decoded.Capacity()
	network := decoded.Network()
	agent := decoded.AgentConfiguration()
	product := decoded.Product()
	secrets := product.SecretFiles()
	if capacity.HostCAS() == "" || capacity.DockerEngine() == "" || capacity.DockerDataVolume() == "" ||
		capacity.HostRelease() == "" ||
		network.InstallationID() != input.InstallationID || network.GenerationID() != input.GenerationID ||
		network.RuntimeEndpoint() != input.RuntimeEndpoint || agent.ConfigLocation() == "" || agent.EntryID() == "" ||
		agent.LauncherDigest().IsZero() || agent.LauncherPath() == "" ||
		!agent.ExpectedManagedEntryDigest().IsZero() || decoded.SignedRelease().TrustRootID() == "" ||
		product.ConfigurationDirectory() == "" || product.RuntimeDirectory() == "" ||
		product.SecretDirectory() == "" || product.BackupDirectory() == "" ||
		product.ComposeProjectDirectory() == "" || product.ComposeConfigurationPath() == "" ||
		product.EmptyEnvironmentPath() == "" || product.EgressAttestationPath() == "" ||
		secrets[0].Purpose() == "" || secrets[0].Path() == "" {
		t.Fatal("immutable projection accessor lost a binding")
	}
}

func TestDecodeRejectsDuplicateUnknownUnsupportedAndNonCanonicalJSON(t *testing.T) {
	t.Parallel()
	plan, err := NewV1(validPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := plan.CanonicalBytes()
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrMalformed},
		{name: "trailing JSON", raw: append(append([]byte(nil), canonical...), []byte("{}")...), want: ErrMalformed},
		{name: "whitespace", raw: append([]byte(" "), canonical...), want: ErrNonCanonical},
		{name: "duplicate nested", raw: bytes.Replace(canonical, []byte(`"entry_id":`), []byte(`"entry_id":"019f5f22-5678-7def-9123-abcdef012346","entry_id":`), 1), want: ErrDuplicateKey},
		{name: "unknown nested", raw: bytes.Replace(canonical, []byte(`"entry_id":`), []byte(`"extra":1,"entry_id":`), 1), want: ErrUnknownField},
		{name: "unsupported", raw: bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1), want: ErrUnsupportedSchema},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeV1(test.raw); !errors.Is(err, test.want) {
				t.Fatalf("DecodeV1() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPlanRejectsMissingCrossBindingsAndMutableReleaseReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "operation", mutate: func(input *Input) { input.OperationID = install.OperationID{} }},
		{name: "installation", mutate: func(input *Input) { input.InstallationID = "not-uuid" }},
		{name: "generation", mutate: func(input *Input) { input.GenerationID = "not-uuid" }},
		{name: "remote endpoint", mutate: func(input *Input) { input.RuntimeEndpoint = "tcp://remote:2375" }},
		{name: "unknown ownership", mutate: func(input *Input) { input.RuntimeOwnership = install.RuntimeOwnershipUnknown }},
		{name: "host policy", mutate: func(input *Input) { input.SignedHostPlan = hostverification.SignedPlan{} }},
		{name: "catalog binding", mutate: func(input *Input) { input.RuntimeCatalog.ResourceID = "compose" }},
		{name: "compose binding", mutate: func(input *Input) { input.Artifacts.ComposeArtifactID = "runtime-catalog" }},
		{name: "artifact digest", mutate: func(input *Input) {
			input.Artifacts.Artifacts[0].Digest = releaseinventory.DigestBytes([]byte("foreign"))
		}},
		{name: "source allowlist", mutate: func(input *Input) { input.Artifacts.Artifacts[0].Sources = []string{"https://example.com/foreign"} }},
		{name: "agent entry", mutate: func(input *Input) { input.AgentConfiguration.EntryID = "not-uuid" }},
		{name: "security epoch", mutate: func(input *Input) { input.SecurityEpoch = 0 }},
		{name: "unsafe JSON security epoch", mutate: func(input *Input) { input.SecurityEpoch = maximumSafeJSONInt + 1 }},
		{name: "relative product root", mutate: func(input *Input) { input.Product.RuntimeDirectory = "relative/runtime" }},
		{name: "remote core", mutate: func(input *Input) { input.Product.CoreEndpoint = "https://example.com" }},
		{name: "brain name", mutate: func(input *Input) { input.Product.InitialBrainName = "Not Local" }},
		{name: "owner principal", mutate: func(input *Input) { input.Product.OwnerPrincipalID = "not-uuid" }},
		{name: "owner grant", mutate: func(input *Input) { input.Product.OwnerGrantID = "not-uuid" }},
		{name: "owner subject", mutate: func(input *Input) { input.Product.OwnerSubjectDigest = install.Digest{} }},
		{name: "missing secret", mutate: func(input *Input) { input.Product.SecretFiles = input.Product.SecretFiles[1:] }},
		{name: "duplicate secret path", mutate: func(input *Input) { input.Product.SecretFiles[1].Path = input.Product.SecretFiles[0].Path }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPlanInput(t)
			test.mutate(&input)
			if _, err := NewV1(input); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("NewV1() error = %v, want integrity", err)
			}
		})
	}

	plan, err := NewV1(validPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(plan.CanonicalBytes(), &document); err != nil {
		t.Fatal(err)
	}
	release := document["release"].(map[string]any)
	manifestRaw, err := base64.StdEncoding.DecodeString(release["manifest"].(string))
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = bytes.Replace(manifestRaw,
		[]byte("registry.example/agentmemory/image@sha256:"),
		[]byte("registry.example/agentmemory/image:latest#"), 1)
	release["manifest"] = base64.StdEncoding.EncodeToString(manifestRaw)
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV1(mutated); err == nil {
		t.Fatal("DecodeV1 accepted a mutable OCI reference")
	}
}

func TestPlanAcceptsCanonicalWindowsEndpointAndOptionalDigests(t *testing.T) {
	t.Parallel()
	input := validPlanInput(t)
	input.RuntimeEndpoint = "npipe:////./pipe/docker_engine"
	input.SignedHostPlan = testSignedWindowsHostPlan(t)
	input.Product = testWindowsProductInput()
	input.Artifacts.Capacity.HostRelease = input.Product.ReleaseDirectory
	input.AgentConfiguration.ConfigLocation = `C:\Users\owner\.agent\config.json`
	input.AgentConfiguration.LauncherPath = `C:\Program Files\AgentMemory\agentmemory.exe`
	input.AgentConfiguration.ExpectedManagedEntryDigest = agentconfigdomain.DigestBytes([]byte("managed entry"))
	plan, err := NewV1(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeV1(plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RuntimeEndpoint() != input.RuntimeEndpoint ||
		decoded.AgentConfiguration().ExpectedManagedEntryDigest().IsZero() ||
		decoded.AcquisitionPlan().Artifacts()[0].ExpandedDigest().IsZero() {
		t.Fatal("optional exact bindings did not round trip")
	}
}

func testWindowsProductInput() ProductInput {
	root := `C:\Users\owner\AppData\Local\AgentMemory`
	secretRoot := root + `\secrets`
	return ProductInput{
		ReleaseDirectory: root + `\releases\1.0.0`, ConfigurationDirectory: root + `\config`,
		RuntimeDirectory: root + `\runtime`, SecretDirectory: secretRoot, BackupDirectory: root + `\backups`,
		ComposeProjectDirectory:  root + `\releases\1.0.0\compose`,
		ComposeConfigurationPath: root + `\releases\1.0.0\compose\compose.yaml`,
		EmptyEnvironmentPath:     root + `\releases\1.0.0\compose\empty.env`,
		EgressAttestationPath:    root + `\runtime\egress-attestation.json`,
		CoreEndpoint:             "http://127.0.0.1:9411", InitialBrainID: "019f5f23-5678-7def-9123-abcdef012347",
		InitialBrainName: "local", OwnerPrincipalID: "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID: "019f5f25-5678-7def-9123-abcdef012349", OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
		SecretFiles: []SecretFileInput{
			{Purpose: SecretInstallationRootKey, Path: secretRoot + `\installation-root-key`},
			{Purpose: SecretAPICredential, Path: secretRoot + `\api-credential`},
			{Purpose: SecretAttestationHMACKey, Path: secretRoot + `\attestation-hmac-key`},
			{Purpose: SecretNeo4jPassword, Path: secretRoot + `\neo4j-password`},
			{Purpose: SecretEmbeddingCapability, Path: secretRoot + `\embedding-capability`},
			{Purpose: SecretRerankerCapability, Path: secretRoot + `\reranker-capability`},
			{Purpose: SecretExtractorCapability, Path: secretRoot + `\extractor-capability`},
		},
	}
}

func TestDecodeRejectsInvalidEncodedEnvelopeAndOwnership(t *testing.T) {
	t.Parallel()
	plan, err := NewV1(validPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := plan.CanonicalBytes()
	tests := [][]byte{
		bytes.Replace(canonical, []byte(`"runtime_ownership":"provisioned_by_agentmemory"`), []byte(`"runtime_ownership":"unknown"`), 1),
		bytes.Replace(canonical, []byte(`"signature":"`), []byte(`"signature":"*`), 1),
		bytes.Replace(canonical, []byte(`"expected_managed_entry_digest":""`), []byte(`"expected_managed_entry_digest":"bad"`), 1),
		bytes.Replace(canonical, []byte(`"expanded_digest":""`), []byte(`"expanded_digest":"bad"`), 1),
	}
	for _, raw := range tests {
		if _, err := DecodeV1(raw); err == nil {
			t.Fatal("DecodeV1 accepted an invalid envelope or binding")
		}
	}
}

func TestPF001CanonicalInputDecoderExercisesEveryTrustEnvelopeRejection(t *testing.T) {
	t.Parallel()
	plan, err := NewV1(validPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	base := canonicalPlan{}
	if err := json.Unmarshal(plan.CanonicalBytes(), &base); err != nil {
		t.Fatal(err)
	}
	encode := func(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
	tests := map[string]func(*canonicalPlan){
		"operation":       func(d *canonicalPlan) { d.OperationID = "" },
		"manifest base64": func(d *canonicalPlan) { d.Release.Manifest = "*" },
		"manifest noncanonical": func(d *canonicalPlan) {
			raw, _ := base64.StdEncoding.DecodeString(d.Release.Manifest)
			d.Release.Manifest = encode(append([]byte(" "), raw...))
		},
		"manifest malformed":  func(d *canonicalPlan) { d.Release.Manifest = encode([]byte(`{}`)) },
		"signature base64":    func(d *canonicalPlan) { d.Release.Signature = "*" },
		"sigstore base64":     func(d *canonicalPlan) { d.Release.SigstoreBundle = "*" },
		"revocation base64":   func(d *canonicalPlan) { d.Release.RevocationSet = "*" },
		"trusted time base64": func(d *canonicalPlan) { d.Release.TrustedTimeEvidence = "*" },
		"signed release":      func(d *canonicalPlan) { d.Release.Signature = encode(nil) },
		"host plan base64":    func(d *canonicalPlan) { d.HostPolicy.Plan = "*" },
		"host plan noncanonical": func(d *canonicalPlan) {
			raw, _ := base64.StdEncoding.DecodeString(d.HostPolicy.Plan)
			d.HostPolicy.Plan = encode(append([]byte(" "), raw...))
		},
		"host plan malformed":   func(d *canonicalPlan) { d.HostPolicy.Plan = encode([]byte(`{}`)) },
		"host signature base64": func(d *canonicalPlan) { d.HostPolicy.Signature = "*" },
		"signed host":           func(d *canonicalPlan) { d.HostPolicy.SigningKeyID = "foreign-key" },
		"product":               func(d *canonicalPlan) { d.Product.SecretFiles = nil },
	}
	for name, mutate := range tests {
		document := base
		mutate(&document)
		if _, err := inputFromDocument(document); err == nil {
			t.Fatalf("%s trust-envelope mutation accepted", name)
		}
	}
}

func TestReleaseEnvelopeV2RejectsLegacySplitTransparencySchema(t *testing.T) {
	t.Parallel()
	plan, err := NewV1(validPlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(plan.CanonicalBytes(), &document); err != nil {
		t.Fatal(err)
	}
	release := document["release"].(map[string]any)
	if release["signature_bundle_schema_version"] != float64(releaseinventory.SupportedSignatureBundleSchemaMajor) {
		t.Fatal("canonical plan omitted signature-bundle schema v2")
	}
	if _, exists := release["sigstore_bundle"]; !exists {
		t.Fatal("canonical plan omitted the official Sigstore bundle field")
	}
	for _, legacy := range []string{"certificate_chain", "rekor_checkpoint", "rekor_inclusion_proof"} {
		legacyDocument := clonePlanDocument(t, document)
		legacyDocument["release"].(map[string]any)[legacy] = ""
		raw, marshalError := json.Marshal(legacyDocument)
		if marshalError != nil {
			t.Fatal(marshalError)
		}
		if _, decodeError := DecodeV1(raw); !errors.Is(decodeError, ErrUnknownField) {
			t.Fatalf("legacy field %q error = %v, want ErrUnknownField", legacy, decodeError)
		}
	}
	for _, version := range []any{nil, float64(1), float64(3)} {
		versionDocument := clonePlanDocument(t, document)
		versionRelease := versionDocument["release"].(map[string]any)
		if version == nil {
			delete(versionRelease, "signature_bundle_schema_version")
		} else {
			versionRelease["signature_bundle_schema_version"] = version
		}
		raw, marshalError := json.Marshal(versionDocument)
		if marshalError != nil {
			t.Fatal(marshalError)
		}
		if _, decodeError := DecodeV1(raw); !errors.Is(decodeError, ErrUnsupportedSchema) {
			t.Fatalf("signature bundle version %v error = %v, want ErrUnsupportedSchema", version, decodeError)
		}
	}
}

func clonePlanDocument(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func FuzzDecodeCanonicalPlanV1(f *testing.F) {
	plan, err := NewV1(validPlanInput(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(plan.CanonicalBytes())
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeV1(raw)
		if err != nil {
			return
		}
		if !bytes.Equal(decoded.CanonicalBytes(), raw) {
			t.Fatal("successful decode normalized unsigned bytes")
		}
		bound, bindError := install.BindPlan(raw)
		if bindError != nil || !bound.Equal(decoded.Digest()) {
			t.Fatal("successful decode returned a foreign digest")
		}
	})
}

func TestPF001InstallPlanStrictJSONScannerAndArithmeticRejectEveryStructuralEdge(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("[", maximumJSONDepth+2) + "0" + strings.Repeat("]", maximumJSONDepth+2)
	for name, document := range map[string]string{
		"deep": deep, "duplicate": `{"a":0,"a":1}`, "truncated object": `{"a":0`,
		"truncated array": `[0`, "trailing": `{} {}`, "invalid delimiter": `]`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectDuplicateJSONKeys([]byte(document)); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
	for _, document := range []string{`null`, `true`, `0`, `"value"`, `[]`, `[{},[1,2,3]]`, `{"a":[1,{"b":2}]}`} {
		if err := rejectDuplicateJSONKeys([]byte(document)); err != nil {
			t.Fatalf("valid structural JSON %s rejected: %v", document, err)
		}
	}
	if value, err := checkedAdd(maximumSafeJSONInt-1, 1); err != nil || value != maximumSafeJSONInt {
		t.Fatalf("checkedAdd boundary=%d,%v", value, err)
	}
	for _, values := range [][2]uint64{
		{maximumSafeJSONInt + 1, 0}, {0, maximumSafeJSONInt + 1}, {maximumSafeJSONInt, 1},
	} {
		if _, err := checkedAdd(values[0], values[1]); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("checkedAdd(%d,%d)=%v", values[0], values[1], err)
		}
	}
	if _, err := parseOptionalReleaseDigest("bad"); err == nil {
		t.Fatal("bad optional release digest accepted")
	}
}

func validPlanInput(t testing.TB) Input {
	t.Helper()
	operation, err := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	signed := testSignedManifest(t)
	launcherDigest := agentconfigdomain.DigestBytes([]byte("signed launcher"))
	return Input{
		OperationID:      operation,
		InstallationID:   "019f5f20-1234-7abc-8123-0123456789ab",
		GenerationID:     "019f5f21-5678-7def-9123-abcdef012345",
		RuntimeEndpoint:  "unix:///var/run/docker.sock",
		RuntimeOwnership: install.RuntimeOwnershipProvisionedByAgentMemory,
		SecurityEpoch:    1,
		SignedHostPlan:   testSignedHostPlan(t),
		SignedRelease:    signed,
		Product:          testProductInput(),
		RuntimeCatalog:   RuntimeCatalogInput{ResourceID: "runtime-catalog"},
		Artifacts: ArtifactInput{
			ComposeArtifactID:     "compose",
			Artifacts:             planArtifactInputs(signed.Manifest()),
			RollbackHeadroomBytes: 1024,
			SafetyHeadroomBytes:   2048,
			Capacity: CapacityInput{
				HostCAS:          "/var/lib/agentmemory/cas",
				HostRelease:      testProductInput().ReleaseDirectory,
				DockerEngine:     "unix:///var/run/docker.sock",
				DockerDataVolume: "agentmemory-core-data",
			},
		},
		AgentConfiguration: AgentConfigurationInput{
			ConfigLocation: "/home/user/.agent/config.json",
			EntryID:        "019f5f22-5678-7def-9123-abcdef012346",
			LauncherDigest: launcherDigest,
			LauncherPath:   "/opt/agentmemory/bin/agentmemory",
		},
	}
}

func TestPF001PlanBindsAgentHostAcrossCanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	input := validPlanInput(t)
	input.AgentConfiguration.AgentHost = agentconfigdomain.AgentHostCodex
	input.AgentConfiguration.ConfigLocation = "/home/user/.codex/config.toml"

	plan, err := NewV1(input)
	if err != nil {
		t.Fatalf("NewV1() error = %v", err)
	}
	if plan.AgentConfiguration().AgentHost() != agentconfigdomain.AgentHostCodex {
		t.Fatalf("agent host = %q", plan.AgentConfiguration().AgentHost())
	}
	decoded, err := DecodeV1(plan.CanonicalBytes())
	if err != nil {
		t.Fatalf("DecodeV1() error = %v", err)
	}
	if decoded.AgentConfiguration().AgentHost() != agentconfigdomain.AgentHostCodex ||
		decoded.AgentConfiguration().ConfigLocation() != input.AgentConfiguration.ConfigLocation {
		t.Fatal("canonical round trip lost the Codex host binding")
	}

	input.AgentConfiguration.AgentHost = agentconfigdomain.AgentHost("unknown")
	if _, err := NewV1(input); err == nil {
		t.Fatal("NewV1 accepted an unknown agent host")
	}
}

func TestPF001PlanBindsConcreteOwnerStorageOutsideReleasePolicy(t *testing.T) {
	t.Parallel()
	input := validPlanInput(t)
	policyInput := hostverification.Input{
		PolicyID: "host-policy-2026-07", SigningKeyID: "host-root-2026",
		Platform: input.SignedHostPlan.Plan().Platform(), MinimumCPUCores: 4,
		MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTargetMode: hostverification.StorageTargetOwnerSelected,
		RequiredPorts:     input.SignedHostPlan.Plan().RequiredPorts(),
	}
	policy, err := hostverification.NewPlan(policyInput)
	if err != nil {
		t.Fatal(err)
	}
	input.SignedHostPlan, err = hostverification.NewSignedPlan(
		policy, policy.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	input.HostStorageTarget = "/home/user/.agentmemory"
	input.RuntimeOwnership = install.RuntimeOwnershipUndetermined
	plan, err := NewV1(input)
	if err != nil || plan.HostStorageTarget() != input.HostStorageTarget ||
		plan.SignedHostPlan().Plan().StorageTarget() != "" ||
		plan.RuntimeOwnership() != install.RuntimeOwnershipUndetermined {
		t.Fatalf("owner-selected installation plan=%+v,%v", plan, err)
	}
	decoded, err := DecodeV1(plan.CanonicalBytes())
	if err != nil || decoded.HostStorageTarget() != input.HostStorageTarget {
		t.Fatalf("decoded target=%q error=%v", decoded.HostStorageTarget(), err)
	}
	input.HostStorageTarget = "/home/foreign/.agentmemory"
	if _, err := NewV1(input); err == nil {
		t.Fatal("plan accepted product paths outside its concrete storage target")
	}
}

func testProductInput() ProductInput {
	root := "/home/user/.agentmemory"
	secretRoot := root + "/secrets"
	return ProductInput{
		ReleaseDirectory:         root + "/releases/1.0.0",
		ConfigurationDirectory:   root + "/config",
		RuntimeDirectory:         root + "/runtime",
		SecretDirectory:          secretRoot,
		BackupDirectory:          root + "/backups",
		ComposeProjectDirectory:  root + "/releases/1.0.0/compose",
		ComposeConfigurationPath: root + "/releases/1.0.0/compose/compose.yaml",
		EmptyEnvironmentPath:     root + "/releases/1.0.0/compose/empty.env",
		EgressAttestationPath:    root + "/runtime/egress-attestation.json",
		CoreEndpoint:             "http://127.0.0.1:9411",
		InitialBrainID:           "019f5f23-5678-7def-9123-abcdef012347",
		InitialBrainName:         "local",
		OwnerPrincipalID:         "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID:             "019f5f25-5678-7def-9123-abcdef012349",
		OwnerSubjectDigest:       install.DigestBytes([]byte("owner subject")),
		SecretFiles: []SecretFileInput{
			{Purpose: SecretInstallationRootKey, Path: secretRoot + "/installation-root-key"},
			{Purpose: SecretAPICredential, Path: secretRoot + "/api-credential"},
			{Purpose: SecretAttestationHMACKey, Path: secretRoot + "/attestation-hmac-key"},
			{Purpose: SecretNeo4jPassword, Path: secretRoot + "/neo4j-password"},
			{Purpose: SecretEmbeddingCapability, Path: secretRoot + "/embedding-capability"},
			{Purpose: SecretRerankerCapability, Path: secretRoot + "/reranker-capability"},
			{Purpose: SecretExtractorCapability, Path: secretRoot + "/extractor-capability"},
		},
	}
}

func testSignedHostPlan(t testing.TB) hostverification.SignedPlan {
	t.Helper()
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-2026-07", SigningKeyID: "host-root-2026",
		Platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu",
			Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic",
		},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: "/home/user/.agentmemory",
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 9411}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testSignedWindowsHostPlan(t testing.TB) hostverification.SignedPlan {
	t.Helper()
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-2026-07", SigningKeyID: "host-root-2026",
		Platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemWindows, Product: "windows-11",
			Architecture: hostverification.ArchitectureAMD64, Version: "24H2", Build: "26100.4652",
		},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: `C:\Users\owner\AppData\Local\AgentMemory`,
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 9411}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func planArtifactInputs(manifest releaseinventory.Manifest) []artifactacquisition.ArtifactInput {
	result := make([]artifactacquisition.ArtifactInput, 0, len(manifest.Resources()))
	for _, resource := range manifest.Resources() {
		if resource.Kind() == releaseinventory.ResourceKindOCIImage || resource.Kind() == releaseinventory.ResourceKindOCIIndex {
			continue
		}
		result = append(result, artifactacquisition.ArtifactInput{
			ID: resource.ID(), Digest: resource.Digest(), Size: resource.Size(), Sources: resource.SourceAllowlist(),
			Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: resource.Size(), Digest: resource.Digest()}},
		})
		if target, exists := resource.ExpandedTarget(); exists {
			index := len(result) - 1
			result[index].ExpandedBytes = target.Bytes()
			result[index].ExpandedDigest = target.Digest()
			result[index].TargetKind = target.Kind()
			result[index].TargetStorageID = target.StorageID()
			result[index].TargetAuthorityDigest = target.AuthorityDigest()
		}
	}
	return result
}

func testSignedManifest(t testing.TB) releaseinventory.SignedManifest {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	compose := testSubject(t, "compose", releaseinventory.ResourceKindComposeBundle,
		releaseinventory.ResourcePurposeComposeLock, releaseinventory.MediaTypeComposeLock, platform, "bundle://compose")
	runtimeCatalog := testSubject(t, "runtime-catalog", releaseinventory.ResourceKindRuntimeCatalog,
		releaseinventory.ResourcePurposeRuntimeCatalog, releaseinventory.MediaTypeRuntimeCatalog, platform, "bundle://runtime-catalog")
	indexDigest := releaseinventory.DigestBytes([]byte("image-index"))
	index := testSubject(t, "image-index", releaseinventory.ResourceKindOCIIndex,
		releaseinventory.ResourcePurposeOCIIndex, releaseinventory.MediaTypeOCIIndex, releaseinventory.Platform{},
		"registry.example/agentmemory/image-index@sha256:"+indexDigest.Hex())
	imageDigest := releaseinventory.DigestBytes([]byte("image"))
	imageInput := testSubjectInput("image", releaseinventory.ResourceKindOCIImage,
		releaseinventory.ResourcePurposeOCIPlatformManifest, releaseinventory.MediaTypeOCIManifest, platform,
		"registry.example/agentmemory/image@sha256:"+imageDigest.Hex(), imageDigest)
	imageInput.OCIIndexDigest = indexDigest
	imageInput.OCIIndexResourceID = "image-index"
	image := mustResource(t, imageInput)
	resources := make([]releaseinventory.Resource, 0, 24)
	for _, subject := range []releaseinventory.Resource{compose, runtimeCatalog, index, image} {
		resources = append(resources, subject)
		resources = append(resources, testEvidence(t, subject)...)
	}
	protocol, _ := releaseinventory.NewProtocolRange(1, 3)
	versionRange, _ := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{Minimum: "1.0.0", Maximum: "1.0.0"})
	compatibility, _ := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange, Provider: versionRange,
		Schema: versionRange, Compose: versionRange, SQLite: versionRange, Neo4j: versionRange,
		RuntimeCatalog: versionRange,
	})
	revocations := []byte("signed revocation set")
	trust, _ := releaseinventory.NewTrustPolicy(releaseinventory.SignatureTrustModeKeyID,
		"release-root-2026", releaseinventory.DigestBytes(revocations), "")
	history, _ := releaseinventory.NewReleaseHistory(nil, nil)
	topology, err := releaseinventory.NewDockerTopology(testTopology())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: 1, ReleaseID: "agentmemory-1.0.0", Version: "1.0.0", BuildID: "build-20260701-1",
		SourceCommit:   strings.Repeat("a", 40),
		BuildTimestamp: time.Date(2026, time.June, 30, 23, 0, 0, 0, time.UTC),
		Channel:        releaseinventory.ReleaseChannelStable, Sequence: 42, DataGeneration: 6,
		ValidFrom:  time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC),
		Protocol:   protocol, Compatibility: compatibility, TrustPolicy: trust, ReleaseHistory: history,
		LicensePolicyDigest:       releaseinventory.DigestBytes([]byte("license-policy")),
		VulnerabilityPolicyDigest: releaseinventory.DigestBytes([]byte("vulnerability-policy")),
		DockerTopology:            topology, Resources: resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeKeyID, TrustRootID: "release-root-2026",
		Signature: bytes.Repeat([]byte{0x42}, releaseinventory.ManifestSignatureSize), RevocationSet: revocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testSubject(
	t testing.TB,
	id string,
	kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose,
	media string,
	platform releaseinventory.Platform,
	source string,
) releaseinventory.Resource {
	t.Helper()
	return mustResource(t, testSubjectInput(id, kind, purpose, media, platform, source,
		releaseinventory.DigestBytes([]byte(id))))
}

func testSubjectInput(
	id string,
	kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose,
	media string,
	platform releaseinventory.Platform,
	source string,
	digest releaseinventory.Digest,
) releaseinventory.ResourceInput {
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: media, Platform: platform,
		Digest: digest, Size: uint64(len(id) + 1), SourceRef: source, SourceAllowlist: []string{source},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-licenses",
		VulnerabilityResourceID: id + "-vulnerabilities",
	}
	if kind == releaseinventory.ResourceKindComposeBundle {
		input.ExpandedTarget = releaseinventory.ReleaseExpandedTargetInput{
			Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
			Digest: digest, Bytes: input.Size,
		}
	}
	return input
}

func testEvidence(t testing.TB, subject releaseinventory.Resource) []releaseinventory.Resource {
	t.Helper()
	types := []struct {
		suffix  string
		kind    releaseinventory.ResourceKind
		purpose releaseinventory.ResourcePurpose
		media   string
	}{
		{"cyclonedx", releaseinventory.ResourceKindCycloneDXSBOM, releaseinventory.ResourcePurposeCycloneDXSBOM, releaseinventory.MediaTypeCycloneDX},
		{"spdx", releaseinventory.ResourceKindSPDXSBOM, releaseinventory.ResourcePurposeSPDXSBOM, releaseinventory.MediaTypeSPDX},
		{"provenance", releaseinventory.ResourceKindProvenance, releaseinventory.ResourcePurposeSLSAProvenance, releaseinventory.MediaTypeSLSAProvenance},
		{"licenses", releaseinventory.ResourceKindLicense, releaseinventory.ResourcePurposeLicenseEvaluation, releaseinventory.MediaTypeLicenseEvaluation},
		{"vulnerabilities", releaseinventory.ResourceKindVulnerabilityReport, releaseinventory.ResourcePurposeVulnerabilityReport, releaseinventory.MediaTypeVulnerabilityEvaluation},
	}
	result := make([]releaseinventory.Resource, 0, len(types))
	for _, evidence := range types {
		id := subject.ID() + "-" + evidence.suffix
		input := releaseinventory.ResourceInput{
			ID: id, Kind: evidence.kind, Purpose: evidence.purpose, MediaType: evidence.media,
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: uint64(len(id)),
			SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
			SubjectResourceID: subject.ID(), SubjectDigest: subject.Digest(),
		}
		if evidence.kind == releaseinventory.ResourceKindLicense {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("license-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if evidence.kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("vulnerability-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
			input.QualificationExpiresAt = time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)
		}
		result = append(result, mustResource(t, input))
	}
	return result
}

func mustResource(t testing.TB, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(%q): %v", input.ID, err)
	}
	return resource
}

func testTopology() releaseinventory.DockerTopologyInput {
	labels := []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	return releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		Volumes:  []releaseinventory.DockerVolumeInput{{ID: "core-data", Purpose: "canonical-data", Labels: labels}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "core-ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"},
			NetworkIDs:    []string{"internal"},
			VolumeMounts:  []releaseinventory.VolumeMountInput{{VolumeID: "core-data", Target: "/var/lib/agentmemory"}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080}},
			Labels:         labels,
		}},
	}
}
