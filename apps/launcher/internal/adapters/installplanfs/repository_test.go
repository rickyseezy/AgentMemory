package installplanfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestRepositoryDurablyPublishesAndLoadsExactPlan(t *testing.T) {
	t.Parallel()
	root := filepath.Join(filesystemTestDirectory(t), "plans")
	repository, err := NewRepository(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	plan := filesystemPlan(t)
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	loaded, err := repository.Load(context.Background(), plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Digest().Equal(plan.Digest()) || !bytes.Equal(loaded.CanonicalBytes(), plan.CanonicalBytes()) {
		t.Fatal("repository changed canonical authority")
	}
	info, err := os.Stat(filepath.Join(root, planFilename(plan.Digest())))
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("published mode = %v/%v", info, err)
	}
	foreign, _ := install.BindPlan([]byte("foreign"))
	if _, err := repository.Load(context.Background(), foreign); !errors.Is(err, installplanapp.ErrPlanNotFound) {
		t.Fatalf("foreign load error = %v", err)
	}
}

func TestRepositoryConcurrentReplayNeverReplacesPlan(t *testing.T) {
	t.Parallel()
	repository, err := NewRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	plan := filesystemPlan(t)
	const workers = 12
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsFound <- repository.Save(context.Background(), plan)
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent replay: %v", err)
		}
	}
	if _, err := repository.Load(context.Background(), plan.Digest()); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryConcurrentCloseIsRaceFreeAndFailClosed(t *testing.T) {
	t.Parallel()
	repository, err := NewRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "plans-close"))
	if err != nil {
		t.Fatal(err)
	}
	plan := filesystemPlan(t)
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatal(err)
	}

	const workers = 12
	errorsFound := make(chan error, workers*2+1)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			errorsFound <- repository.Save(context.Background(), plan)
		}()
		go func() {
			defer group.Done()
			<-start
			_, loadError := repository.Load(context.Background(), plan.Digest())
			errorsFound <- loadError
		}()
	}
	close(start)
	errorsFound <- repository.Close()
	group.Wait()
	close(errorsFound)
	for operationError := range errorsFound {
		if operationError != nil && !errors.Is(operationError, installplanapp.ErrPlanIntegrity) {
			t.Fatalf("concurrent close operation: %v", operationError)
		}
	}
}

func TestRepositoryRejectsTamperUnsafeInputsAndClosedUse(t *testing.T) {
	t.Parallel()
	//lint:ignore SA1012 Intentionally verifies fail-closed handling of an absent context.
	if _, err := NewRepository(nil, "/absolute"); !errors.Is(err, installplanapp.ErrPlanIntegrity) { //nolint:staticcheck // Intentional absent-context boundary test.
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := NewRepository(context.Background(), "relative"); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("relative root error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewRepository(cancelled, filepath.Join(filesystemTestDirectory(t), "cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled constructor error = %v", err)
	}
	root := filepath.Join(filesystemTestDirectory(t), "plans")
	repository, err := NewRepository(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), installplan.Plan{}); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("zero plan error = %v", err)
	}
	plan := filesystemPlan(t)
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, planFilename(plan.Digest()))
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Load(context.Background(), plan.Digest()); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("tampered load error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Load(context.Background(), plan.Digest()); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("closed load error = %v", err)
	}
	if err := repository.Save(context.Background(), plan); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("closed save error = %v", err)
	}
	var nilRepository *Repository
	if err := nilRepository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := nilRepository.Save(context.Background(), plan); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("nil save error = %v", err)
	}
	if _, err := nilRepository.Load(context.Background(), plan.Digest()); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("nil load error = %v", err)
	}
}

func TestRepositoryMapsImmutableConflictAndMalformedDurableBytes(t *testing.T) {
	t.Parallel()
	plan := filesystemPlan(t)
	conflictRoot := filepath.Join(filesystemTestDirectory(t), "conflict-plans")
	conflictRepository, err := NewRepository(context.Background(), conflictRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conflictRepository.Close() }()
	conflictPath := filepath.Join(conflictRoot, planFilename(plan.Digest()))
	if err := os.WriteFile(conflictPath, []byte("foreign immutable bytes"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := conflictRepository.Save(context.Background(), plan); !errors.Is(err, installplanapp.ErrPlanConflict) {
		t.Fatalf("immutable conflict error = %v", err)
	}
	if _, err := conflictRepository.Load(context.Background(), plan.Digest()); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("malformed durable bytes error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := conflictRepository.Save(cancelled, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled repository save = %v", err)
	}
	if _, err := conflictRepository.Load(cancelled, plan.Digest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled repository load = %v", err)
	}
}

func TestRepositoryDurablyPublishesAuthenticatedRuntimeAuthority(t *testing.T) {
	t.Parallel()
	repository, err := NewRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "runtime-plans"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	parent := filesystemPlan(t)
	authority := filesystemRuntimeAuthority(t, parent, "discovery-1")
	if err := repository.SaveRuntimePlan(context.Background(), authority); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRuntimePlan(context.Background(), authority); err != nil {
		t.Fatalf("idempotent runtime save: %v", err)
	}
	const workers = 12
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsFound <- repository.SaveRuntimePlan(context.Background(), authority)
		}()
	}
	group.Wait()
	close(errorsFound)
	for saveError := range errorsFound {
		if saveError != nil {
			t.Fatalf("concurrent runtime replay = %v", saveError)
		}
	}
	loaded, err := repository.LoadRuntimePlan(context.Background(), parent.OperationID(), parent.Digest())
	if err != nil || !loaded.Equal(authority) {
		t.Fatalf("runtime load = %+v/%v", loaded, err)
	}
	conflicting := filesystemRuntimeAuthority(t, parent, "discovery-2")
	if err := repository.SaveRuntimePlan(context.Background(), conflicting); !errors.Is(err, installplanapp.ErrRuntimePlanConflict) {
		t.Fatalf("runtime conflict = %v", err)
	}
	foreign, _ := install.NewOperationID("019f5f9f-0000-7abc-8123-0123456789ab")
	if _, err := repository.LoadRuntimePlan(context.Background(), foreign, parent.Digest()); !errors.Is(err, installplanapp.ErrRuntimePlanNotFound) {
		t.Fatalf("foreign runtime load = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := repository.SaveRuntimePlan(cancelled, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled runtime save = %v", err)
	}
	if _, err := repository.LoadRuntimePlan(cancelled, parent.OperationID(), parent.Digest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled runtime load = %v", err)
	}
}

func TestRepositoryRejectsMalformedRuntimeAuthorityAndClosedUse(t *testing.T) {
	t.Parallel()
	root := filepath.Join(filesystemTestDirectory(t), "runtime-malformed")
	repository, err := NewRepository(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	parent := filesystemPlan(t)
	authority := filesystemRuntimeAuthority(t, parent, "discovery")
	path := filepath.Join(root, runtimeAuthorityFilename(parent.OperationID(), parent.Digest()))
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"schema_version":1}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LoadRuntimePlan(context.Background(), parent.OperationID(), parent.Digest()); !errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) {
		t.Fatalf("malformed runtime load = %v", err)
	}
	if err := repository.SaveRuntimePlan(context.Background(), authority); !errors.Is(err, installplanapp.ErrRuntimePlanConflict) {
		t.Fatalf("malformed immutable conflict = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRuntimePlan(context.Background(), authority); !errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) {
		t.Fatalf("closed runtime save = %v", err)
	}
	if _, err := repository.LoadRuntimePlan(context.Background(), parent.OperationID(), parent.Digest()); !errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) {
		t.Fatalf("closed runtime load = %v", err)
	}
	var nilRepository *Repository
	if err := nilRepository.SaveRuntimePlan(context.Background(), authority); !errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) {
		t.Fatalf("nil runtime save = %v", err)
	}
	if _, err := nilRepository.LoadRuntimePlan(context.Background(), parent.OperationID(), parent.Digest()); !errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) {
		t.Fatalf("nil runtime load = %v", err)
	}
}

func filesystemRuntimeAuthority(t testing.TB, parent installplan.Plan, discoveryEvidence string) installplanapp.RuntimePlanAuthority {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "6.8.0", true, true, true, true,
		8, 32*1024*1024*1024, 24*1024*1024*1024, 100*1024*1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalogHash, err := runtimeinstall.ParseHash(parent.RuntimeCatalogDigest().String())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker-engine", "28.0.0", "stable", 42,
		catalogHash, runtimeinstall.Sum([]byte("terms")), 1024, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := installplanapp.NewRuntimePlanAuthority(
		parent.OperationID(), parent.Digest(), plan, install.DigestBytes([]byte("host")),
		install.DigestBytes([]byte(discoveryEvidence)), parent.RuntimeCatalogDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func filesystemPlan(t testing.TB) installplan.Plan {
	t.Helper()
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	signed := filesystemSignedManifest(t)
	product := filesystemProductInput()
	plan, err := installplan.NewV1(installplan.Input{
		OperationID: operation, InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
		GenerationID:     "019f5f21-5678-7def-9123-abcdef012345",
		RuntimeEndpoint:  "unix:///var/run/docker.sock",
		RuntimeOwnership: install.RuntimeOwnershipProvisionedByAgentMemory,
		SecurityEpoch:    1, SignedHostPlan: filesystemSignedHostPlan(t), SignedRelease: signed,
		Product:        product,
		RuntimeCatalog: installplan.RuntimeCatalogInput{ResourceID: "runtime-catalog"},
		Artifacts: installplan.ArtifactInput{
			ComposeArtifactID:     "compose",
			Artifacts:             filesystemArtifactInputs(signed.Manifest()),
			RollbackHeadroomBytes: 1024, SafetyHeadroomBytes: 2048,
			Capacity: installplan.CapacityInput{HostCAS: "/var/lib/agentmemory/cas", HostRelease: product.ReleaseDirectory,
				DockerEngine: "unix:///var/run/docker.sock", DockerDataVolume: "agentmemory-core-data"},
		},
		AgentConfiguration: installplan.AgentConfigurationInput{
			ConfigLocation: "/home/user/.agent/config.json",
			EntryID:        "019f5f22-5678-7def-9123-abcdef012346",
			LauncherDigest: agentconfigdomain.DigestBytes([]byte("signed launcher")),
			LauncherPath:   "/opt/agentmemory/bin/agentmemory",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func filesystemSignedHostPlan(t testing.TB) hostverification.SignedPlan {
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

func filesystemProductInput() installplan.ProductInput {
	root := "/home/user/.agentmemory"
	secretRoot := root + "/secrets"
	return installplan.ProductInput{
		ReleaseDirectory: root + "/releases/1.0.0", ConfigurationDirectory: root + "/config",
		RuntimeDirectory: root + "/runtime", SecretDirectory: secretRoot, BackupDirectory: root + "/backups",
		ComposeProjectDirectory:  root + "/releases/1.0.0/compose",
		ComposeConfigurationPath: root + "/releases/1.0.0/compose/compose.yaml",
		EmptyEnvironmentPath:     root + "/releases/1.0.0/compose/empty.env",
		EgressAttestationPath:    root + "/runtime/egress-attestation.json",
		CoreEndpoint:             "http://127.0.0.1:9411", InitialBrainID: "019f5f23-5678-7def-9123-abcdef012347",
		InitialBrainName: "local", OwnerPrincipalID: "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID: "019f5f25-5678-7def-9123-abcdef012349", OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
		SecretFiles: []installplan.SecretFileInput{
			{Purpose: installplan.SecretInstallationRootKey, Path: secretRoot + "/installation-root-key"},
			{Purpose: installplan.SecretAPICredential, Path: secretRoot + "/api-credential"},
			{Purpose: installplan.SecretAttestationHMACKey, Path: secretRoot + "/attestation-hmac-key"},
			{Purpose: installplan.SecretNeo4jPassword, Path: secretRoot + "/neo4j-password"},
			{Purpose: installplan.SecretEmbeddingCapability, Path: secretRoot + "/embedding-capability"},
			{Purpose: installplan.SecretRerankerCapability, Path: secretRoot + "/reranker-capability"},
			{Purpose: installplan.SecretExtractorCapability, Path: secretRoot + "/extractor-capability"},
		},
	}
}

func filesystemArtifactInputs(manifest releaseinventory.Manifest) []artifactacquisition.ArtifactInput {
	result := make([]artifactacquisition.ArtifactInput, 0, len(manifest.Resources()))
	for _, resource := range manifest.Resources() {
		if resource.Kind() == releaseinventory.ResourceKindOCIImage || resource.Kind() == releaseinventory.ResourceKindOCIIndex {
			continue
		}
		input := artifactacquisition.ArtifactInput{
			ID: resource.ID(), Digest: resource.Digest(), Size: resource.Size(), Sources: resource.SourceAllowlist(),
			Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: resource.Size(), Digest: resource.Digest()}},
		}
		if target, exists := resource.ExpandedTarget(); exists {
			input.ExpandedBytes, input.ExpandedDigest = target.Bytes(), target.Digest()
			input.TargetKind, input.TargetStorageID, input.TargetAuthorityDigest = target.Kind(), target.StorageID(), target.AuthorityDigest()
		}
		result = append(result, input)
	}
	return result
}

func filesystemSignedManifest(t testing.TB) releaseinventory.SignedManifest {
	t.Helper()
	platform, _ := releaseinventory.NewPlatform("linux", "amd64")
	compose := filesystemSubject(t, "compose", releaseinventory.ResourceKindComposeBundle,
		releaseinventory.ResourcePurposeComposeLock, releaseinventory.MediaTypeComposeLock, platform, "bundle://compose")
	runtimeCatalog := filesystemSubject(t, "runtime-catalog", releaseinventory.ResourceKindRuntimeCatalog,
		releaseinventory.ResourcePurposeRuntimeCatalog, releaseinventory.MediaTypeRuntimeCatalog, platform, "bundle://runtime-catalog")
	indexDigest := releaseinventory.DigestBytes([]byte("image-index"))
	index := filesystemSubject(t, "image-index", releaseinventory.ResourceKindOCIIndex,
		releaseinventory.ResourcePurposeOCIIndex, releaseinventory.MediaTypeOCIIndex, releaseinventory.Platform{},
		"registry.example/agentmemory/image-index@sha256:"+indexDigest.Hex())
	imageDigest := releaseinventory.DigestBytes([]byte("image"))
	imageInput := filesystemSubjectInput("image", releaseinventory.ResourceKindOCIImage,
		releaseinventory.ResourcePurposeOCIPlatformManifest, releaseinventory.MediaTypeOCIManifest, platform,
		"registry.example/agentmemory/image@sha256:"+imageDigest.Hex(), imageDigest)
	imageInput.OCIIndexDigest = indexDigest
	imageInput.OCIIndexResourceID = "image-index"
	image := filesystemMustResource(t, imageInput)
	resources := make([]releaseinventory.Resource, 0, 24)
	for _, subject := range []releaseinventory.Resource{compose, runtimeCatalog, index, image} {
		resources = append(resources, subject)
		resources = append(resources, filesystemEvidence(t, subject)...)
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
	topology, _ := releaseinventory.NewDockerTopology(filesystemTopology())
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

func filesystemSubject(t testing.TB, id string, kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose, media string, platform releaseinventory.Platform,
	source string) releaseinventory.Resource {
	t.Helper()
	return filesystemMustResource(t, filesystemSubjectInput(id, kind, purpose, media, platform, source,
		releaseinventory.DigestBytes([]byte(id))))
}

func filesystemSubjectInput(id string, kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose, media string, platform releaseinventory.Platform,
	source string, digest releaseinventory.Digest) releaseinventory.ResourceInput {
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

func filesystemEvidence(t testing.TB, subject releaseinventory.Resource) []releaseinventory.Resource {
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
		result = append(result, filesystemMustResource(t, input))
	}
	return result
}

func filesystemMustResource(t testing.TB, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func filesystemTopology() releaseinventory.DockerTopologyInput {
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
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"}, NetworkIDs: []string{"internal"},
			VolumeMounts:  []releaseinventory.VolumeMountInput{{VolumeID: "core-data", Target: "/var/lib/agentmemory"}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080}},
			Labels:         labels,
		}},
	}
}

func filesystemTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
