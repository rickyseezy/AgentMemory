package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006VerifiedLinuxCatalogProductionProjectorsPreserveExactAuthorityAndArtifacts(t *testing.T) {
	t.Parallel()
	catalog, plan, binding, authority := verifiedLinuxCatalogProjectionFixture(t)

	projected, err := (verifiedCatalogLinuxProjector{catalog: catalog}).ProjectLinuxAuthority(
		plan.CanonicalBytes(), binding,
	)
	if err != nil || projected.Digest() != authority.Digest() {
		t.Fatalf("projected authority=%s error=%v", projected.Digest(), err)
	}
	resolver, err := NewCatalogLinuxAuthorityResolver(
		catalog, &linuxHostBindingProviderFake{binding: binding},
	)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveLinuxAuthority(t.Context(), plan.CanonicalBytes())
	if err != nil || resolved.Digest() != authority.Digest() {
		t.Fatalf("resolved authority=%s error=%v", resolved.Digest(), err)
	}

	artifactPlan, err := (verifiedCatalogArtifactProjector{catalog: catalog}).ProjectLinuxArtifactPlan(authority)
	if err != nil || len(artifactPlan.Artifacts()) == 0 {
		t.Fatalf("projected artifacts=%d error=%v", len(artifactPlan.Artifacts()), err)
	}
	cas := successfulLinuxArtifactCAS(artifactPlan)
	cas.acquireResult.CompletedArtifacts = uint32(len(artifactPlan.Artifacts())) // #nosec G115 -- catalog caps artifacts at 4096.
	cas.acquireResult.VerifiedArtifacts = make([]artifactapp.VerifiedArtifact, 0, len(artifactPlan.Artifacts()))
	for _, artifact := range artifactPlan.Artifacts() {
		cas.acquireResult.VerifiedArtifacts = append(cas.acquireResult.VerifiedArtifacts, artifactapp.VerifiedArtifact{
			ID: artifact.ID(), Digest: artifact.Digest(), Size: artifact.Size(), ContentKey: artifact.ContentKey(),
		})
	}
	acquirer, err := NewCatalogLinuxArtifactAcquirer(catalog, cas)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := acquirer.AcquireLinuxArtifacts(t.Context(), authority)
	if err != nil || !evidence.AcquiredFor(authority) || evidence.VerifiedFor(authority) {
		t.Fatalf("acquired=%t verified=%t error=%v", evidence.AcquiredFor(authority), evidence.VerifiedFor(authority), err)
	}

	materializer := &desktopArtifactMaterializerFake{}
	stager, err := NewCatalogPrivilegeArtifactStager(catalog, materializer, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := stager.StagePrivilegeArtifacts(t.Context(), authority)
	if err != nil || len(bindings) != len(artifactPlan.Artifacts()) || materializer.calls != len(bindings) {
		t.Fatalf("bindings=%d artifacts=%d materialized=%d error=%v",
			len(bindings), len(artifactPlan.Artifacts()), materializer.calls, err)
	}
}

func TestPF006VerifiedLinuxCatalogProductionTrustAdapterReopensCompleteCASSet(t *testing.T) {
	t.Parallel()
	catalog, _, _, authority := verifiedLinuxCatalogProjectionFixture(t)
	reader := &sizedVerifiedFinalReader{}
	clock := &fakeClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)}
	verifier, err := NewCatalogLinuxArtifactVerifier(catalog, reader, clock)
	if err != nil {
		t.Fatal(err)
	}
	if evidence, verifyError := verifier.VerifyLinuxArtifacts(t.Context(), authority); !errors.Is(verifyError, runtimeport.ErrLinuxArtifactIntegrity) || evidence.VerifiedFor(authority) {
		t.Fatalf("untrusted repository evidence=%+v error=%v", evidence, verifyError)
	}
	plan, err := catalog.LinuxArtifactPlan(authority)
	if err != nil {
		t.Fatal(err)
	}
	if reader.opens != len(plan.Artifacts()) {
		t.Fatalf("CAS opens=%d want=%d", reader.opens, len(plan.Artifacts()))
	}
	execution, present := catalog.Manifest().LinuxExecution()
	if !present {
		t.Fatal("verified Linux execution projection disappeared")
	}
	index, found := repositoryArtifactByRole(
		execution.Repository(), runtimecatalog.LinuxRepositoryArtifactPackageIndex,
	)
	if !found || index.DownloadBytes() == 0 {
		t.Fatal("signed package index was not selected")
	}
	if len(aptPackageExpectations(execution.Packages())) != len(execution.Packages()) ||
		len(dnfPackageExpectations(execution.Packages())) != len(execution.Packages()) {
		t.Fatal("package trust expectations omitted signed packages")
	}
	if candidate, constructError := NewCatalogLinuxArtifactVerifierWithRPMKeys(
		catalog, reader, clock, &rpmSignatureVerifierStub{},
	); candidate != nil || !errors.Is(constructError, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("APT catalog accepted by RPM verifier=%T error=%v", candidate, constructError)
	}
}

func TestPF006RPMPackageVerificationReopensEveryCatalogBoundPackage(t *testing.T) {
	t.Parallel()
	catalog, _, _, authority := verifiedLinuxCatalogProjectionFixture(t)
	plan, err := catalog.LinuxArtifactPlan(authority)
	if err != nil {
		t.Fatal(err)
	}
	execution, present := catalog.Manifest().LinuxExecution()
	if !present {
		t.Fatal("verified Linux execution projection disappeared")
	}
	packages := linuxPackagesForRepository(execution.Packages(), execution.Repository().ID())
	reader := &sizedVerifiedFinalReader{}
	rpm := &recordingRPMVerifier{}
	verifier := &CatalogLinuxArtifactVerifier{reader: reader, rpm: rpm}
	if err := verifier.verifyRPMPackages(
		t.Context(), plan, execution.Repository(), packages, []byte("key"),
	); err != nil || rpm.calls != len(packages) || reader.opens != len(packages) {
		t.Fatalf("rpm calls=%d opens=%d packages=%d error=%v", rpm.calls, reader.opens, len(packages), err)
	}

	missingPlan, _ := trustReaderPlan(t)
	if err := verifier.verifyRPMPackages(
		t.Context(), missingPlan, execution.Repository(), packages, []byte("key"),
	); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("missing RPM artifact error=%v", err)
	}
	for name, candidate := range map[string]*CatalogLinuxArtifactVerifier{
		"open":      {reader: &verifiedFinalReaderStub{openErr: artifactapp.ErrArtifactNotFound}, rpm: &recordingRPMVerifier{}},
		"signature": {reader: &verifiedFinalReaderStub{}, rpm: &recordingRPMVerifier{err: errors.New("signature")}},
		"close":     {reader: &verifiedFinalReaderStub{closeErr: errors.New("close")}, rpm: &recordingRPMVerifier{}},
	} {
		if verifyError := candidate.verifyRPMPackages(
			t.Context(), plan, execution.Repository(), packages[:1], []byte("key"),
		); verifyError == nil {
			t.Fatalf("%s RPM failure accepted", name)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (&CatalogLinuxArtifactVerifier{
		reader: &verifiedFinalReaderStub{}, rpm: &recordingRPMVerifier{err: errors.New("signature")},
	}).verifyRPMPackages(cancelled, plan, execution.Repository(), packages[:1], []byte("key")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RPM verification error=%v", err)
	}
	if err := (&CatalogLinuxArtifactVerifier{}).verifyLinuxRepositories(
		t.Context(), artifactacquisition.Plan{}, runtimecatalog.LinuxExecutionPolicy{}, nil, time.Now().UTC(),
	); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("unbound repository verification error=%v", err)
	}
	if artifact, found := repositoryArtifactByRole(
		runtimecatalog.LinuxRepository{}, runtimecatalog.LinuxRepositoryArtifactPackageIndex,
	); found || artifact.DownloadBytes() != 0 {
		t.Fatalf("zero repository artifact=%+v found=%t", artifact, found)
	}
}

func verifiedLinuxCatalogProjectionFixture(
	t testing.TB,
) (runtimecatalogapp.VerifiedCatalog, runtimeinstall.Plan, runtimecatalogapp.LinuxHostBinding, runtimeport.LinuxAuthority) {
	t.Helper()
	raw, err := os.ReadFile("testdata/runtime-catalog-linux.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindLinux, Architecture: runtimecatalog.ArchitectureX8664,
		Edition: "workstation", Distribution: "ubuntu", OSVersion: "24.4.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30, Virtualization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := &observationCatalogPorts{
		host: host, now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: ports, Host: ports, Signature: ports, NativePublisher: ports, AntiRollback: ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(
		manifest, manifest.SigningKeyID(), []byte("detached signature"),
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := application.Verify(t.Context(), runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: manifest.Digest(),
		SourceMode: runtimecatalog.SourceModeOfflineUserSelected,
	})
	if err != nil {
		t.Fatal(err)
	}
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	hostCapabilities, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(
		hostCapabilities, runtimeinstall.NewAbsentRuntimeDiscovery(), certified,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := runtimecatalogapp.NewLinuxHostBinding(runtimecatalogapp.LinuxHostBindingInput{
		VersionID: "24.04", InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := catalog.LinuxAuthority(plan.CanonicalBytes(), binding)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, plan, binding, authority
}

type sizedVerifiedFinalReader struct{ opens int }

func (r *sizedVerifiedFinalReader) OpenFinal(
	_ context.Context,
	artifact artifactacquisition.Artifact,
) (io.ReadCloser, error) {
	r.opens++
	return io.NopCloser(io.LimitReader(zeroReader{}, int64(artifact.Size()))), nil
}

type zeroReader struct{}

func (zeroReader) Read(target []byte) (int, error) {
	clear(target)
	return len(target), nil
}

type recordingRPMVerifier struct {
	err   error
	calls int
}

func (v *recordingRPMVerifier) VerifyRPMPackage(
	context.Context,
	[]byte,
	string,
	artifactacquisition.Artifact,
	io.Reader,
) error {
	v.calls++
	return v.err
}

var _ artifactapp.VerifiedFinalReader = (*sizedVerifiedFinalReader)(nil)
