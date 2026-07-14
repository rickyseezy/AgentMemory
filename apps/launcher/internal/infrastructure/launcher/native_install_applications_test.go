package launcher

import (
	"context"
	"reflect"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
)

func TestPF001NativeInstallApplicationsDeriveReleaseBoundCapabilities(t *testing.T) {
	t.Parallel()
	composition, err := composeNative(
		t.Context(), nativeTestRoots(t.TempDir()),
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = composition.resources.Close(context.Background()) })
	dependencies := nativeInstallGraphFixture()
	builder, err := newNativeInstallApplicationsBuilderWithDecoder(
		&composition, nativeInstallCapabilitiesFixture(dependencies),
		func([]byte) (runtimePlanProjection, error) {
			return runtimePlanProjection{
				operationID: nativeGraphOperationID(t), digest: nativeGraphPlanDigest(t),
				coreEndpoint: "http://127.0.0.1:9411", credentialPath: "/owner/credential",
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseFixture := nativeReleaseStackFixture(t)
	release, err := newNativeReleaseAuthority(t.Context(), nativeReleaseAuthorityDependencies{
		BundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
		Trust:      func() (nativeReleaseTrustMaterial, error) { return releaseFixture.Trust, nil },
		Clock:      releaseFixture.Clock, AntiRollback: releaseFixture.AntiRollback,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close(context.Background()) })
	factory, err := builder(t.Context(), release)
	if err != nil || factory == nil {
		t.Fatalf("factory=(%v,%v)", factory, err)
	}
	application, err := factory(t.Context(), nativeInstallAuthority{
		OperationID: nativeGraphOperationID(t), PlanDigest: nativeGraphPlanDigest(t),
		CanonicalPlan: []byte("canonical"),
	})
	if err != nil || application == nil {
		t.Fatalf("application=(%v,%v)", application, err)
	}
	closer, managed := application.(nativeInstallApplicationCloser)
	if !managed {
		t.Fatalf("operation-scoped application is not managed: %T", application)
	}
	if err := closer.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(t.Context()); err != nil {
		t.Fatalf("idempotent close error=%v", err)
	}
}

func TestPF001NativeInstallApplicationsRejectEveryMissingRemainingCapability(t *testing.T) {
	t.Parallel()
	composition := &nativeComposition{}
	if builder, err := newNativeInstallApplicationsBuilder(composition, nativeInstallPhaseCapabilities{}); builder != nil || err == nil {
		t.Fatalf("incomplete composition accepted: builder=%v error=%v", builder, err)
	}
	complete, err := composeNative(
		t.Context(), nativeTestRoots(t.TempDir()),
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = complete.resources.Close(context.Background()) })

	base := nativeInstallCapabilitiesFixture(nativeInstallGraphFixture())
	value := reflect.ValueOf(&base).Elem()
	for index := 0; index < value.NumField(); index++ {
		candidate := base
		field := reflect.ValueOf(&candidate).Elem().Field(index)
		field.Set(reflect.Zero(field.Type()))
		if builder, err := newNativeInstallApplicationsBuilder(&complete, candidate); builder != nil || err == nil {
			t.Fatalf("missing capability %s accepted", value.Type().Field(index).Name)
		}
	}
}

func nativeInstallCapabilitiesFixture(dependencies nativeInstallGraphDependencies) nativeInstallPhaseCapabilities {
	return nativeInstallPhaseCapabilities{
		RuntimeEvidence: dependencies.RuntimeEvidence,
		RuntimeEnsurer:  dependencies.RuntimeEnsurer, Capacity: dependencies.Capacity,
		ManagedResources: dependencies.ManagedResources, ProductStack: dependencies.ProductStack,
		AgentConfiguration: dependencies.AgentConfiguration,
	}
}
