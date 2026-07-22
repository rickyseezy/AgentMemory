package launcher

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/testsupport/releasefixture"
)

func TestPF005NativeSessionAssemblyBuildsManagedRunnerFromResolvedAuthorities(t *testing.T) {
	t.Parallel()
	root, err := protectedSessionTestRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDirectory, err := createProtectedSessionTestDirectory(root, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	credentialDirectory, err := createProtectedSessionTestDirectory(root, "credentials")
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := protectedSessionTestFile(t, credentialDirectory, "api-credential", bytes.Repeat([]byte{0x42}, 32))
	rootKeyPath := protectedSessionTestFile(t, credentialDirectory, "installation-root-key", bytes.Repeat([]byte{0x24}, 32))
	receipts, err := installplanfs.NewReadinessRepository(
		t.Context(), filepath.Join(root, "readiness"), rootKeyPath,
		&sessionReadinessKeySource{value: bytes.Repeat([]byte{0x24}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	pointer := nativeSessionPointer(t)
	executors := nativeProductExecutors(t)
	canonical := []byte("canonical PF-005 session plan")
	digest, err := install.BindPlan(canonical)
	if err != nil {
		t.Fatal(err)
	}
	projection := runtimePlanProjection{
		digest:                   digest,
		operationID:              nativeGraphOperationID(t),
		installationID:           pointer.InstallationID(),
		host:                     agentconfig.AgentHostCodex,
		brainID:                  "019d2b4e-7a12-7def-8abc-0123456789ab",
		actorID:                  "019d2b4e-7a13-7def-8abc-0123456789ab",
		grantID:                  "019d2b4e-7a14-7def-8abc-0123456789ab",
		runtimeEndpoint:          pointer.RuntimeEndpoint(),
		runtimeDirectory:         runtimeDirectory,
		composeProjectDirectory:  filepath.Join(root, "compose"),
		composeConfigurationPath: filepath.Join(root, "compose", "compose.yaml"),
		emptyEnvironmentPath:     filepath.Join(root, "compose", "empty.env"),
		coreEndpoint:             "http://127.0.0.1:38765",
		credentialPath:           credentialPath,
		installationRootKeyPath:  rootKeyPath,
	}
	authorities := nativeSessionAuthorities{
		receipts:      receipts,
		ensurer:       &nativeGraphRuntime{},
		product:       nativeProductRuntime{executors: executors},
		pointer:       pointer,
		activeRelease: sessionActiveRelease{pointer: pointer},
		lock:          sessionInstallationLock{},
		image:         "registry.example/agentmemory/mcp-session@sha256:" + strings.Repeat("a", 64),
	}
	factory := &nativeProductSessionFactory{
		composition:      &nativeComposition{},
		runtimeEvidence:  &nativeRuntimeEvidenceResolver{},
		runtimeExecution: &nativeRuntimeExecutionVerifier{},
		runtimePlatform:  &nativePlatformRuntimeFactory{},
		sessionAuthorities: func(
			context.Context,
			runtimePlanProjection,
			installplan.Plan,
		) (nativeSessionAuthorities, error) {
			return authorities, nil
		},
		sessionPlan: func([]byte) (runtimePlanProjection, installplan.Plan, error) {
			return projection, installplan.Plan{}, nil
		},
		operationState: func(context.Context, install.OperationID) (install.State, error) {
			return install.StateReady, nil
		},
	}
	resolved, err := mcpbootstrapapp.NewResolvedBootstrap(
		projection.installationID, projection.operationID, digest, canonical,
	)
	if err != nil {
		t.Fatal(err)
	}
	factory.operationState = func(context.Context, install.OperationID) (install.State, error) {
		return install.StateRunning, nil
	}
	if pending, ready, pendingError := factory.BuildReadySession(
		t.Context(), agentconfig.AgentHostCodex, resolved,
	); pendingError != nil || ready || pending != nil {
		t.Fatalf("pending BuildReadySession()=%T/%v/%v", pending, ready, pendingError)
	}
	factory.operationState = func(context.Context, install.OperationID) (install.State, error) {
		return install.StateUnknown, errors.New("private operation failure")
	}
	if failed, ready, stateError := factory.BuildReadySession(
		t.Context(), agentconfig.AgentHostCodex, resolved,
	); stateError == nil || ready || failed != nil {
		t.Fatalf("failed BuildReadySession()=%T/%v/%v", failed, ready, stateError)
	}
	factory.sessionPlan = func([]byte) (runtimePlanProjection, installplan.Plan, error) {
		return runtimePlanProjection{}, installplan.Plan{}, errors.New("private decode failure")
	}
	if failed, ready, decodeError := factory.BuildReadySession(
		t.Context(), agentconfig.AgentHostCodex, resolved,
	); decodeError == nil || ready || failed != nil {
		t.Fatalf("decode BuildReadySession()=%T/%v/%v", failed, ready, decodeError)
	}
	factory.sessionPlan = func([]byte) (runtimePlanProjection, installplan.Plan, error) {
		return projection, installplan.Plan{}, nil
	}
	factory.operationState = func(context.Context, install.OperationID) (install.State, error) {
		return install.StateReady, nil
	}
	runner, ready, err := factory.BuildReadySession(t.Context(), agentconfig.AgentHostCodex, resolved)
	if err != nil || !ready || runner == nil {
		t.Fatalf("build()=%T/%v/%v", runner, ready, err)
	}
	lifecycle, ok := runner.(RuntimeLifecycle)
	if !ok {
		t.Fatalf("runner lacks lifecycle: %T", runner)
	}
	if err := lifecycle.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPF005NativeSessionFactoryComposesFromVerifiedReleaseAuthorities(t *testing.T) {
	t.Parallel()
	root, err := protectedSessionTestRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	journals := newNativeSharedJournalFactory()
	composition, err := composeNative(
		t.Context(), nativeTestRoots(root), journals.provider, pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = composition.resources.Close(context.Background()) })
	releaseFixture := nativeReleaseStackFixture(t)
	release, err := newNativeReleaseAuthority(t.Context(), nativeReleaseAuthorityDependencies{
		BundleRoot:   func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
		Trust:        func() (nativeReleaseTrustMaterial, error) { return releaseFixture.Trust, nil },
		Clock:        releaseFixture.Clock,
		AntiRollback: releaseFixture.AntiRollback,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close(context.Background()) })
	factory, err := newNativeProductSessionFactory(t.Context(), &composition, release)
	if err != nil || factory == nil || factory.sessionAuthorities == nil || factory.sessionPlan == nil ||
		factory.operationState == nil {
		t.Fatalf("newNativeProductSessionFactory()=%T/%v", factory, err)
	}
	missingArtifacts := composition
	missingArtifacts.artifacts = nil
	if candidate, buildError := newNativeProductSessionFactory(
		t.Context(), &missingArtifacts, release,
	); candidate != nil || buildError == nil {
		t.Fatalf("missing artifact repository factory=%T/%v", candidate, buildError)
	}
	missingRuntimeState := composition
	missingRuntimeState.runtimeState = nil
	if candidate, buildError := newNativeProductSessionFactory(
		t.Context(), &missingRuntimeState, release,
	); candidate != nil || buildError == nil {
		t.Fatalf("missing runtime state factory=%T/%v", candidate, buildError)
	}
	publisher := release.runtimeCatalogPublisher
	release.runtimeCatalogPublisher = nil
	if candidate, buildError := newNativeProductSessionFactory(
		t.Context(), &composition, release,
	); candidate != nil || buildError == nil {
		t.Fatalf("missing runtime publisher factory=%T/%v", candidate, buildError)
	}
	release.runtimeCatalogPublisher = publisher
	signature := release.runtimeCatalogSignature
	release.runtimeCatalogSignature = nil
	if candidate, buildError := newNativeProductSessionFactory(
		t.Context(), &composition, release,
	); candidate != nil || buildError == nil {
		t.Fatalf("missing runtime signature factory=%T/%v", candidate, buildError)
	}
	release.runtimeCatalogSignature = signature
	credentialDirectory, err := createProtectedSessionTestDirectory(root, "session-authority-credentials")
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := protectedSessionTestFile(
		t, credentialDirectory, "api-credential", bytes.Repeat([]byte{0x42}, 32),
	)
	projection := runtimePlanProjection{
		operationID:    nativeGraphOperationID(t),
		credentialPath: credentialPath,
	}
	if authorities, resolveError := factory.resolveSessionAuthorities(
		t.Context(), projection, installplan.Plan{},
	); resolveError == nil || authorities.receipts != nil {
		t.Fatalf("incomplete authority resolution=%+v/%v", authorities, resolveError)
	}
}

func TestPF005NativeSessionAssemblyFailsClosedAtEveryCompositionBoundary(t *testing.T) {
	t.Parallel()
	root, err := protectedSessionTestRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	credentialDirectory, err := createProtectedSessionTestDirectory(root, "credentials")
	if err != nil {
		t.Fatal(err)
	}
	runtimeDirectory, err := createProtectedSessionTestDirectory(root, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := protectedSessionTestFile(t, credentialDirectory, "api", bytes.Repeat([]byte{0x42}, 32))
	rootKeyPath := protectedSessionTestFile(t, credentialDirectory, "root", bytes.Repeat([]byte{0x24}, 32))
	pointer := nativeSessionPointer(t)
	executors := nativeProductExecutors(t)
	projection := runtimePlanProjection{
		operationID: nativeGraphOperationID(t), installationID: pointer.InstallationID(),
		brainID:         "019d2b4e-7a12-7def-8abc-0123456789ab",
		actorID:         "019d2b4e-7a13-7def-8abc-0123456789ab",
		grantID:         "019d2b4e-7a14-7def-8abc-0123456789ab",
		runtimeEndpoint: pointer.RuntimeEndpoint(), runtimeDirectory: runtimeDirectory,
		composeProjectDirectory:  filepath.Join(root, "compose"),
		composeConfigurationPath: filepath.Join(root, "compose", "compose.yaml"),
		emptyEnvironmentPath:     filepath.Join(root, "compose", "empty.env"),
		coreEndpoint:             "http://127.0.0.1:38765", credentialPath: credentialPath,
		installationRootKeyPath: rootKeyPath,
	}
	sequence := 0
	newAuthorities := func() nativeSessionAuthorities {
		sequence++
		receipts, receiptError := installplanfs.NewReadinessRepository(
			t.Context(), filepath.Join(root, "readiness-"+strconv.Itoa(sequence)), rootKeyPath,
			&sessionReadinessKeySource{value: bytes.Repeat([]byte{0x24}, 32)},
		)
		if receiptError != nil {
			t.Fatal(receiptError)
		}
		return nativeSessionAuthorities{
			receipts: receipts, ensurer: &nativeGraphRuntime{},
			product: nativeProductRuntime{executors: executors}, pointer: pointer,
			activeRelease: sessionActiveRelease{pointer: pointer}, lock: sessionInstallationLock{},
			image: "registry.example/agentmemory/mcp-session@sha256:" + strings.Repeat("a", 64),
		}
	}
	tests := []struct {
		name       string
		projection func(runtimePlanProjection) runtimePlanProjection
		authority  func() (nativeSessionAuthorities, error)
	}{
		{name: "resolver error", authority: func() (nativeSessionAuthorities, error) {
			return nativeSessionAuthorities{}, errors.New("private authority failure")
		}},
		{name: "empty authority", authority: func() (nativeSessionAuthorities, error) {
			return nativeSessionAuthorities{}, nil
		}},
		{name: "missing executors", authority: func() (nativeSessionAuthorities, error) {
			value := newAuthorities()
			value.product = nativeProductRuntime{}
			return value, nil
		}},
		{name: "foreign compose root", projection: func(value runtimePlanProjection) runtimePlanProjection {
			value.composeProjectDirectory = "relative"
			return value
		}},
		{name: "remote Core", projection: func(value runtimePlanProjection) runtimePlanProjection {
			value.coreEndpoint = "https://remote.example"
			return value
		}},
		{name: "missing root key", projection: func(value runtimePlanProjection) runtimePlanProjection {
			value.installationRootKeyPath = filepath.Join(root, "missing", "root")
			return value
		}},
		{name: "uncreatable credential root", projection: func(value runtimePlanProjection) runtimePlanProjection {
			value.runtimeDirectory = filepath.Join(root, "missing", "runtime")
			return value
		}},
		{name: "invalid brain authority", projection: func(value runtimePlanProjection) runtimePlanProjection {
			value.brainID = ""
			return value
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			selected := projection
			if test.projection != nil {
				selected = test.projection(selected)
			}
			factory := &nativeProductSessionFactory{
				composition: &nativeComposition{},
				sessionAuthorities: func(
					context.Context, runtimePlanProjection, installplan.Plan,
				) (nativeSessionAuthorities, error) {
					if test.authority != nil {
						return test.authority()
					}
					return newAuthorities(), nil
				},
			}
			if runner, ready, buildError := factory.build(
				t.Context(), agentconfig.AgentHostCodex, selected, installplan.Plan{},
			); buildError == nil || runner != nil || ready {
				t.Fatalf("build()=%T/%v/%v", runner, ready, buildError)
			}
		})
	}
	invalidHostAuthorities := newAuthorities()
	invalidHostFactory := &nativeProductSessionFactory{
		composition: &nativeComposition{},
		sessionAuthorities: func(
			context.Context, runtimePlanProjection, installplan.Plan,
		) (nativeSessionAuthorities, error) {
			return invalidHostAuthorities, nil
		},
	}
	if runner, ready, buildError := invalidHostFactory.build(
		t.Context(), agentconfig.AgentHost(""), projection, installplan.Plan{},
	); buildError == nil || runner != nil || ready {
		t.Fatalf("invalid host build()=%T/%v/%v", runner, ready, buildError)
	}
}

func TestPF005SessionImageComesOnlyFromSignedLeastPrivilegeTopology(t *testing.T) {
	t.Parallel()
	raw, err := releasefixture.CanonicalManifest()
	if err != nil {
		t.Fatal(err)
	}
	base, err := releaseinventory.DecodeManifestV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if image, err := sessionImageForArchitecture(base, "amd64"); err == nil || image != "" {
		t.Fatalf("missing service image=%q/%v", image, err)
	}

	manifest, err := manifestWithSessionService(base)
	if err != nil {
		t.Fatal(err)
	}
	image, err := sessionImageForArchitecture(manifest, "amd64")
	if err != nil || image == "" || !strings.Contains(image, "@sha256:") {
		t.Fatalf("session image=%q/%v", image, err)
	}
	if image, err := sessionImageForArchitecture(manifest, "arm64"); err == nil || image != "" {
		t.Fatalf("wrong architecture image=%q/%v", image, err)
	}
	runtimeImage, runtimeError := sessionImage(manifest)
	if runtime.GOARCH == "amd64" && (runtimeError != nil || runtimeImage != image) {
		t.Fatalf("runtime session image=%q/%v", runtimeImage, runtimeError)
	}
	if runtime.GOARCH != "amd64" && (runtimeError == nil || runtimeImage != "") {
		t.Fatalf("unsupported runtime session image=%q/%v", runtimeImage, runtimeError)
	}
}

func manifestWithSessionService(base releaseinventory.Manifest) (releaseinventory.Manifest, error) {
	topology := base.DockerTopology()
	network := topology.Networks()[0]
	volume := topology.Volumes()[0]
	probe := topology.HealthProbes()[0]
	core := topology.Services()[0]
	labels := topologyLabelInputs(core.Labels())
	updated, err := releaseinventory.NewDockerTopology(releaseinventory.DockerTopologyInput{
		Profiles: topology.Profiles(),
		Networks: []releaseinventory.DockerNetworkInput{{
			ID: network.ID(), Internal: network.Internal(), Labels: topologyLabelInputs(network.Labels()),
		}},
		Volumes: []releaseinventory.DockerVolumeInput{{
			ID: volume.ID(), Purpose: volume.Purpose(), Labels: topologyLabelInputs(volume.Labels()),
		}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: probe.ID(), Kind: probe.Kind(), HTTPPath: probe.HTTPPath(), Arguments: probe.Arguments(),
			Port: probe.Port(), IntervalSeconds: probe.IntervalSeconds(),
			TimeoutSeconds: probe.TimeoutSeconds(), Retries: probe.Retries(),
		}},
		Services: []releaseinventory.DockerServiceInput{
			{
				ID: core.ID(), ImageResourceIDs: core.ImageResourceIDs(), Profiles: core.Profiles(),
				NetworkIDs: core.NetworkIDs(), VolumeMounts: []releaseinventory.VolumeMountInput{{
					VolumeID: core.VolumeMounts()[0].VolumeID(), Target: core.VolumeMounts()[0].Target(),
					ReadOnly: core.VolumeMounts()[0].ReadOnly(),
				}},
				HealthProbeID: core.HealthProbeID(), UserID: core.UserID(), GroupID: core.GroupID(),
				ReadOnlyRootFilesystem: core.ReadOnlyRootFilesystem(),
				NoNewPrivileges:        core.NoNewPrivileges(), PublishedPorts: []releaseinventory.PortBindingInput{{
					Host: core.PublishedPorts()[0].Host(), HostPort: core.PublishedPorts()[0].HostPort(),
					ContainerPort: core.PublishedPorts()[0].ContainerPort(),
				}}, Labels: labels,
			},
			{
				ID: sessionServiceID, ImageResourceIDs: core.ImageResourceIDs(), Profiles: core.Profiles(),
				NetworkIDs: core.NetworkIDs(), HealthProbeID: core.HealthProbeID(),
				UserID: 10001, GroupID: 10001, ReadOnlyRootFilesystem: true,
				NoNewPrivileges: true, Labels: labels,
			},
		},
	})
	if err != nil {
		return releaseinventory.Manifest{}, err
	}
	history, err := releaseinventory.NewReleaseHistory(nil, nil)
	if err != nil {
		return releaseinventory.Manifest{}, err
	}
	return releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: base.SchemaVersion(), ReleaseID: base.ReleaseID(), Version: base.Version(),
		BuildID: base.BuildID(), SourceCommit: base.SourceCommit(), BuildTimestamp: base.BuildTimestamp(),
		Channel: base.Channel(), Sequence: base.Sequence(), DataGeneration: base.DataGeneration(),
		ValidFrom: base.ValidFrom(), ValidUntil: base.ValidUntil(), Protocol: base.Protocol(),
		Compatibility: base.Compatibility(), TrustPolicy: base.TrustPolicy(), ReleaseHistory: history,
		LicensePolicyDigest:       base.LicensePolicyDigest(),
		VulnerabilityPolicyDigest: base.VulnerabilityPolicyDigest(),
		DockerTopology:            updated, Resources: base.Resources(),
	})
}

func topologyLabelInputs(labels []releaseinventory.TopologyLabel) []releaseinventory.TopologyLabelInput {
	result := make([]releaseinventory.TopologyLabelInput, 0, len(labels))
	for _, label := range labels {
		result = append(result, releaseinventory.TopologyLabelInput{Key: label.Key(), Value: label.Value()})
	}
	return result
}

func TestPF005SessionIdentityKeysArePurposeSeparated(t *testing.T) {
	t.Parallel()
	root := []byte(strings.Repeat("k", 32))
	path := deriveSessionKey(root, pathIdentityKeyPurpose)
	git := deriveSessionKey(root, gitIdentityKeyPurpose)
	if len(path) != 32 || len(git) != 32 || string(path) == string(git) ||
		string(path) == string(root) || string(git) == string(root) {
		t.Fatalf("invalid derived keys: path=%x git=%x", path, git)
	}
}

func TestPF005NativeSessionCompositionGuardsAndLifecycleFailClosed(t *testing.T) {
	t.Parallel()
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if factory, err := newNativeProductSessionFactory(nil, nil, nil); factory != nil || err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatalf("newNativeProductSessionFactory(nil)=%+v/%v", factory, err)
	}
	var nilFactory *nativeProductSessionFactory
	if runner, ready, err := nilFactory.BuildReadySession(
		t.Context(), agentconfig.AgentHostCodex, mcpbootstrapapp.ResolvedBootstrap{},
	); runner != nil || ready || err == nil {
		t.Fatalf("nil BuildReadySession()=%+v/%v/%v", runner, ready, err)
	}
	partial := &nativeProductSessionFactory{}
	if runner, ready, err := partial.BuildReadySession(
		t.Context(), agentconfig.AgentHostCodex, mcpbootstrapapp.ResolvedBootstrap{},
	); runner != nil || ready || err == nil {
		t.Fatalf("partial BuildReadySession()=%+v/%v/%v", runner, ready, err)
	}
	var nilActivator *nativeSessionRuntimeActivator
	if err := nilActivator.EnsureEndpoint(t.Context(), activerelease.Pointer{}); err == nil {
		t.Fatal("nil runtime activator accepted")
	}
	pointer := nativeSessionPointer(t)
	activator := &nativeSessionRuntimeActivator{
		ensurer: &nativeGraphRuntime{}, endpoint: pointer.RuntimeEndpoint(),
	}
	if err := activator.EnsureEndpoint(t.Context(), pointer); err == nil {
		t.Fatal("incomplete runtime result accepted")
	}
	var nilLifecycle *nativeProductSessionLifecycle
	if err := nilLifecycle.Close(t.Context()); err == nil {
		t.Fatal("nil product lifecycle accepted")
	}
	lifecycle := &nativeProductSessionLifecycle{}
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if err := lifecycle.Close(nil); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("nil lifecycle context accepted")
	}
	if err := lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("empty lifecycle Close()=%v", err)
	}
	resourceLifecycle := &nativeProductSessionLifecycle{resources: &nativeResources{}}
	if err := resourceLifecycle.Close(context.Background()); err != nil {
		t.Fatalf("resource lifecycle Close()=%v", err)
	}
	if _, _, err := decodeNativeSessionPlan([]byte("not a canonical plan")); err == nil {
		t.Fatal("invalid native session plan decoded")
	}
}

func protectedSessionTestFile(t testing.TB, root, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := writeProtectedSessionTestFile(path, value); err != nil {
		t.Fatal(err)
	}
	return path
}

func nativeSessionPointer(t testing.TB) activerelease.Pointer {
	t.Helper()
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID:           "019d2b4e-7a11-7def-8abc-0123456789ab",
		ReleaseID:                "agentmemory-1.0.0",
		GenerationID:             "019d2b4e-7a15-7def-8abc-0123456789ab",
		ManifestDigest:           install.DigestBytes([]byte("manifest")),
		ComposeDigest:            install.DigestBytes([]byte("compose")),
		ReadinessReceiptDigest:   install.DigestBytes([]byte("readiness")),
		RuntimeEndpoint:          "unix:///var/run/docker.sock",
		ReleaseSequence:          1,
		ResourceInventoryVersion: 1,
		ResourceInventoryDigest:  install.DigestBytes([]byte("inventory")),
		SecurityEpoch:            1,
		ActivatedAt:              time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}

type sessionReadinessKeySource struct{ value []byte }

func (s *sessionReadinessKeySource) ReadCredential(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.value...), nil
}

type sessionActiveRelease struct{ pointer activerelease.Pointer }

func (s sessionActiveRelease) LoadActive(context.Context) (activerelease.Pointer, error) {
	return s.pointer, nil
}

type sessionInstallationLock struct{}

func (sessionInstallationLock) Acquire(context.Context) (mcpsessionapp.InstallationLock, error) {
	return sessionHeldLock{}, nil
}

type sessionHeldLock struct{}

func (sessionHeldLock) Release(context.Context) error { return nil }
