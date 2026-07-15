package nativepackageinstallapp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001NativePackageInstallVerifiesEveryAuthorityInOrder(t *testing.T) {
	t.Parallel()
	publication := publicationFixture(t)
	ports := &installationPorts{}
	application := newApplication(t, ports)
	request := validRequest(t, publication)
	result, err := application.Install(context.Background(), request)
	if err != nil || result.ReleaseID != publication.ReleaseID() || result.Version != publication.Version() ||
		result.PackageID != "agentmemory-linux-amd64-deb" ||
		strings.Join(ports.calls, ",") != "signature,candidate,install,installed" {
		t.Fatalf("Install() = %+v, %v calls=%v", result, err, ports.calls)
	}
	request.PublicationJSON[0] ^= 0xff
	request.PublicationSigstoreBundle[0] ^= 0xff
	if ports.publication.ReleaseID() != publication.ReleaseID() || ports.signature[0] != '{' {
		t.Fatal("application exposed caller-owned authority storage to a port")
	}
}

func TestPF001NativePackageInstallFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	private := errors.New("private adapter failure")
	for name, test := range map[string]struct {
		mutate func(*Request, *installationPorts)
		want   error
		calls  string
	}{
		"noncanonical publication": {mutate: func(request *Request, _ *installationPorts) {
			request.PublicationJSON = append(request.PublicationJSON, '\n')
		}, want: ErrPublicationIntegrity},
		"signature": {mutate: func(_ *Request, ports *installationPorts) {
			ports.signatureError = private
		}, want: ErrPublicationIntegrity, calls: "signature"},
		"unsupported": {mutate: func(request *Request, _ *installationPorts) {
			request.Format = releasepublication.FormatPKG
		}, want: ErrUnsupportedTarget, calls: "signature"},
		"candidate": {mutate: func(_ *Request, ports *installationPorts) {
			ports.candidateError = private
		}, want: ErrCandidateIntegrity, calls: "signature,candidate"},
		"installer": {mutate: func(_ *Request, ports *installationPorts) {
			ports.installError = private
		}, want: ErrInstallationFailed, calls: "signature,candidate,install"},
		"postcondition": {mutate: func(_ *Request, ports *installationPorts) {
			ports.installedError = private
		}, want: ErrPostconditionFailed, calls: "signature,candidate,install,installed"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ports := &installationPorts{}
			application := newApplication(t, ports)
			request := validRequest(t, publicationFixture(t))
			test.mutate(&request, ports)
			result, err := application.Install(context.Background(), request)
			if !errors.Is(err, test.want) || result != (Result{}) || strings.Join(ports.calls, ",") != test.calls {
				t.Fatalf("Install() = %+v, %v calls=%v want=%v/%q", result, err, ports.calls, test.want, test.calls)
			}
		})
	}
}

func TestPF001NativePackageInstallRejectsPartialCompositionAndInvocation(t *testing.T) {
	t.Parallel()
	ports := &installationPorts{}
	valid := Dependencies{Signature: ports, Candidate: ports, Installer: ports, Installed: ports}
	for name, mutate := range map[string]func(*Dependencies){
		"signature": func(value *Dependencies) { value.Signature = nil },
		"candidate": func(value *Dependencies) { value.Candidate = nil },
		"installer": func(value *Dependencies) { value.Installer = nil },
		"installed": func(value *Dependencies) { value.Installed = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			mutate(&dependencies)
			if application, err := New(dependencies); application != nil || !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("New() = %T, %v", application, err)
			}
		})
	}
	application := newApplication(t, ports)
	request := validRequest(t, publicationFixture(t))
	request.PublicationSigstoreBundle = nil
	if _, err := application.Install(context.Background(), request); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing bundle error = %v", err)
	}
	var absent *Application
	if _, err := absent.Install(context.Background(), validRequest(t, publicationFixture(t))); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil application error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := application.Install(cancelled, validRequest(t, publicationFixture(t))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves fail-closed behavior.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if _, err := application.Install(nil, validRequest(t, publicationFixture(t))); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil-context error = %v", err)
	}
}

type installationPorts struct {
	calls          []string
	signature      []byte
	publication    releasepublication.Publication
	signatureError error
	candidateError error
	installError   error
	installedError error
}

func (p *installationPorts) VerifyArtifactSignature(
	_ context.Context,
	_ releaseinventory.Digest,
	bundle []byte,
) error {
	p.calls = append(p.calls, "signature")
	p.signature = append([]byte(nil), bundle...)
	return p.signatureError
}

func (p *installationPorts) VerifyCandidate(_ context.Context, _ releasepublication.Artifact) error {
	p.calls = append(p.calls, "candidate")
	return p.candidateError
}

func (p *installationPorts) Install(_ context.Context, _ releasepublication.Artifact) error {
	p.calls = append(p.calls, "install")
	return p.installError
}

func (p *installationPorts) VerifyInstalled(
	_ context.Context,
	publication releasepublication.Publication,
	_ releasepublication.Artifact,
) error {
	p.calls = append(p.calls, "installed")
	p.publication = publication
	return p.installedError
}

func newApplication(t testing.TB, ports *installationPorts) *Application {
	t.Helper()
	application, err := New(Dependencies{Signature: ports, Candidate: ports, Installer: ports, Installed: ports})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func validRequest(t testing.TB, publication releasepublication.Publication) Request {
	t.Helper()
	raw, err := releasepublication.EncodeV1(publication)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		PublicationJSON: raw, PublicationSigstoreBundle: []byte(`{"signed":"publication"}`),
		OperatingSystem: "linux", Architecture: "amd64", Format: releasepublication.FormatDEB,
	}
}

func publicationFixture(t testing.TB) releasepublication.Publication {
	t.Helper()
	digest := func(value string) releaseinventory.Digest { return releaseinventory.DigestBytes([]byte(value)) }
	artifact := func(id, operatingSystem, architecture string, format releasepublication.Format,
		policy releasepublication.NativePublisherPolicy,
	) releasepublication.ArtifactInput {
		return releasepublication.ArtifactInput{
			ID: id, Kind: releasepublication.ArtifactKindNativePackage,
			OperatingSystem: operatingSystem, Architecture: architecture, Format: format,
			FileName: id + "." + string(format), MediaType: "application/vnd.agentmemory.package",
			Digest: digest(id), Size: 4096, CycloneDXSBOMDigest: digest(id + "-sbom"),
			ProvenanceDigest: digest(id + "-provenance"), SignatureBundleDigest: digest(id + "-signature"),
			NativePublisherPolicy: policy,
		}
	}
	artifacts := []releasepublication.ArtifactInput{
		artifact("agentmemory-darwin-amd64-pkg", "darwin", "amd64", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized),
		artifact("agentmemory-darwin-arm64-pkg", "darwin", "arm64", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized),
		artifact("agentmemory-linux-amd64-deb", "linux", "amd64", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-amd64-rpm", "linux", "amd64", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-arm64-deb", "linux", "arm64", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-arm64-rpm", "linux", "arm64", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage),
		artifact("agentmemory-windows-amd64-msi", "windows", "amd64", releasepublication.FormatMSI, releasepublication.PublisherPolicyMicrosoftAuthenticode),
		{
			ID: "agentmemory-offline-bundle", Kind: releasepublication.ArtifactKindOfflineBundle,
			Format: releasepublication.FormatTarZstd, FileName: "agentmemory-offline-bundle.tar.zst",
			MediaType: "application/vnd.agentmemory.offline-bundle", Digest: digest("offline"), Size: 8192,
			CycloneDXSBOMDigest: digest("offline-sbom"), ProvenanceDigest: digest("offline-provenance"),
			SignatureBundleDigest: digest("offline-signature"),
			NativePublisherPolicy: releasepublication.PublisherPolicyManifestOnly,
		},
	}
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: releasepublication.SupportedSchemaMajor, ReleaseID: "release-2026-07",
		Version: "1.2.3", BuildID: "build-17", SourceCommit: strings.Repeat("a", 40),
		BuildTimestamp: timeFixture(), DistributionEnvelopeDigest: digest("manifest"),
		DistributionEnvelopeSize: 4096, ReleaseTrustDigest: digest("trust"), ReleaseTrustSize: 2048,
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publication
}

func timeFixture() time.Time { return time.Unix(1_784_073_600, 0).UTC() }
