package launcher

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
)

func TestPF001NativeProductionReadyFactoryRequiresAndReverifiesCompleteAuthority(t *testing.T) {
	t.Parallel()
	if factory, err := newNativeProductionReadySurfaceFactory(nil, nil); factory != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil factory=%v error=%v", factory, err)
	}
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
	fixture := nativeReleaseStackFixture(t)
	release, err := newNativeReleaseAuthority(t.Context(), nativeReleaseAuthorityDependencies{
		BundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
		Trust:      func() (nativeReleaseTrustMaterial, error) { return fixture.Trust, nil },
		Clock:      fixture.Clock, AntiRollback: fixture.AntiRollback,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close(context.Background()) })
	factory, err := newNativeProductionReadySurfaceFactory(&composition, release)
	if err != nil || factory == nil {
		t.Fatalf("factory=%v error=%v", factory, err)
	}
	request, _, _ := nativeRuntimeExecutionFixture(t)
	projection := runtimePlanProjection{
		operationID: request.OperationID, digest: request.ParentPlanDigest,
		installationID: "019f5f23-5678-7def-9123-abcdef012348",
		coreEndpoint:   "http://127.0.0.1:9471", credentialPath: filepath.Join(t.TempDir(), "credential"),
	}
	if provider, err := factory(nil, projection); provider != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil context provider=%T error=%v", provider, err)
	}
	if provider, err := factory(t.Context(), runtimePlanProjection{}); provider != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("empty projection provider=%T error=%v", provider, err)
	}
	remote := projection
	remote.coreEndpoint = "https://example.com"
	if provider, err := factory(t.Context(), remote); provider != nil || err == nil {
		t.Fatalf("remote endpoint provider=%T error=%v", provider, err)
	}
	// No canonical parent operation was published into this isolated fixture;
	// the complete release/catalog reconstruction must therefore fail closed.
	if provider, err := factory(t.Context(), projection); provider != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("missing parent authority provider=%T error=%v", provider, err)
	}
}

func TestPF001NativeRuntimeRemovalCommandUsesVerifiedNestedPlanAndChildUUID(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	verified := nativeVerifiedRuntimeExecution{authority: authority, runtime: catalog, request: request}
	command, err := nativeRuntimeRemovalCommand(verified)
	if err != nil || command.SourceOperationID != authority.OperationID().String() ||
		command.OperationID == command.SourceOperationID || len(command.CanonicalRuntimePlan) == 0 {
		t.Fatalf("command=%+v error=%v", command, err)
	}
	command.CanonicalRuntimePlan[0] ^= 0xff
	if authority.Plan().CanonicalBytes()[0] == command.CanonicalRuntimePlan[0] {
		t.Fatal("removal command aliases verified runtime plan bytes")
	}
	if command, err := nativeRuntimeRemovalCommand(nativeVerifiedRuntimeExecution{}); command.OperationID != "" || err == nil {
		t.Fatalf("empty command=%+v error=%v", command, err)
	}
}
