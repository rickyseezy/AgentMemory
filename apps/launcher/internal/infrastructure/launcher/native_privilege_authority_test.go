package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativePrivilegeAuthorityIndependentlyJoinsReleaseCatalogPlanAndSelf(t *testing.T) {
	t.Parallel()
	plan, authority := launcherLinuxPrivilegePlan(t)
	catalogRaw := []byte(`{"catalog":"signed"}`)
	catalog := nativeRuntimeCatalogResource(t, catalogRaw)
	helper := nativeDesktopHelperResource(t, "linux", "amd64")
	releaseAuthority, err := newNativePrivilegeReleaseAuthority(
		releaseinventory.DigestBytes([]byte("release manifest")), catalog, helper,
	)
	if err != nil {
		t.Fatal(err)
	}
	releases := &nativePrivilegeReleaseAuthorityStub{authority: releaseAuthority}
	catalogs := &nativePrivilegeCatalogAuthorityStub{authority: authority}
	self := &nativePrivilegeHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}
	verifier, err := newNativePrivilegeAuthorityVerifier(releases, catalogs, self)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &nativePrivilegeEnvelopeStub{
		release: []byte(`{"release":"signed"}`), catalog: catalogRaw,
		plan: plan.CanonicalBytes(), catalogID: catalog.ID(), helperID: helper.ID(),
	}
	evidence, err := verifier.VerifyPrivilegeAuthority(t.Context(), envelope)
	if err != nil || evidence.Authority().Digest() != authority.Digest() ||
		evidence.HelperDigest() != runtimeinstall.Hash(helper.Digest()) ||
		releases.calls != 1 || catalogs.calls != 1 || self.calls != 1 ||
		catalogs.catalog.ID() != catalog.ID() || self.helper.ID() != helper.ID() {
		t.Fatalf(
			"evidence=%+v error=%v release=%d catalog=%d self=%d",
			evidence, err, releases.calls, catalogs.calls, self.calls,
		)
	}
}

func TestPF006NativePrivilegeAuthorityFailsClosedAtEveryIndependentGate(t *testing.T) {
	t.Parallel()
	plan, authority := launcherLinuxPrivilegePlan(t)
	catalogRaw := []byte(`{"catalog":"signed"}`)
	catalog := nativeRuntimeCatalogResource(t, catalogRaw)
	helper := nativeDesktopHelperResource(t, "linux", "amd64")
	releaseAuthority, err := newNativePrivilegeReleaseAuthority(
		releaseinventory.DigestBytes([]byte("release manifest")), catalog, helper,
	)
	if err != nil {
		t.Fatal(err)
	}
	validEnvelope := func() *nativePrivilegeEnvelopeStub {
		return &nativePrivilegeEnvelopeStub{
			release: []byte(`{"release":"signed"}`), catalog: catalogRaw,
			plan: plan.CanonicalBytes(), catalogID: catalog.ID(), helperID: helper.ID(),
		}
	}
	for name, configure := range map[string]func(
		*nativePrivilegeReleaseAuthorityStub,
		*nativePrivilegeCatalogAuthorityStub,
		*nativePrivilegeHelperSelfStub,
		*nativePrivilegeEnvelopeStub,
	){
		"release": func(release *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, _ *nativePrivilegeHelperSelfStub, _ *nativePrivilegeEnvelopeStub) {
			release.err = errors.New("release rejected")
		},
		"catalog": func(_ *nativePrivilegeReleaseAuthorityStub, catalog *nativePrivilegeCatalogAuthorityStub, _ *nativePrivilegeHelperSelfStub, _ *nativePrivilegeEnvelopeStub) {
			catalog.err = errors.New("catalog rejected")
		},
		"helper self": func(_ *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, self *nativePrivilegeHelperSelfStub, _ *nativePrivilegeEnvelopeStub) {
			self.err = errors.New("self rejected")
		},
		"zero helper digest": func(_ *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, self *nativePrivilegeHelperSelfStub, _ *nativePrivilegeEnvelopeStub) {
			self.digest = runtimeinstall.Hash{}
		},
		"empty release": func(_ *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, _ *nativePrivilegeHelperSelfStub, envelope *nativePrivilegeEnvelopeStub) {
			envelope.release = nil
		},
		"empty catalog": func(_ *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, _ *nativePrivilegeHelperSelfStub, envelope *nativePrivilegeEnvelopeStub) {
			envelope.catalog = nil
		},
		"empty plan": func(_ *nativePrivilegeReleaseAuthorityStub, _ *nativePrivilegeCatalogAuthorityStub, _ *nativePrivilegeHelperSelfStub, envelope *nativePrivilegeEnvelopeStub) {
			envelope.plan = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			releases := &nativePrivilegeReleaseAuthorityStub{authority: releaseAuthority}
			catalogs := &nativePrivilegeCatalogAuthorityStub{authority: authority}
			self := &nativePrivilegeHelperSelfStub{digest: runtimeinstall.Hash(helper.Digest())}
			envelope := validEnvelope()
			configure(releases, catalogs, self, envelope)
			verifier, constructError := newNativePrivilegeAuthorityVerifier(releases, catalogs, self)
			if constructError != nil {
				t.Fatal(constructError)
			}
			if evidence, verifyError := verifier.VerifyPrivilegeAuthority(t.Context(), envelope); !errors.Is(
				verifyError, runtimeport.ErrPrivilegeIntegrity,
			) || evidence.Authority().Valid() {
				t.Fatalf("evidence=%+v error=%v", evidence, verifyError)
			}
		})
	}
	if verifier, err := newNativePrivilegeAuthorityVerifier(nil, &nativePrivilegeCatalogAuthorityStub{}, &nativePrivilegeHelperSelfStub{}); verifier != nil || err == nil {
		t.Fatal("missing release verifier accepted")
	}
	if verifier, err := newNativePrivilegeAuthorityVerifier(&nativePrivilegeReleaseAuthorityStub{}, nil, &nativePrivilegeHelperSelfStub{}); verifier != nil || err == nil {
		t.Fatal("missing catalog verifier accepted")
	}
	if verifier, err := newNativePrivilegeAuthorityVerifier(&nativePrivilegeReleaseAuthorityStub{}, &nativePrivilegeCatalogAuthorityStub{}, nil); verifier != nil || err == nil {
		t.Fatal("missing helper verifier accepted")
	}
	if _, err := newNativePrivilegeReleaseAuthority(releaseinventory.Digest{}, catalog, helper); err == nil {
		t.Fatal("zero release manifest accepted")
	}
	var absent *nativePrivilegeAuthorityVerifier
	if evidence, err := absent.VerifyPrivilegeAuthority(t.Context(), validEnvelope()); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) || evidence.Authority().Valid() {
		t.Fatalf("absent verifier evidence=%+v error=%v", evidence, err)
	}
}

func TestPF006VerifiedPrivilegeAuthorityAdaptersRejectUnverifiedTransportBeforeProjection(t *testing.T) {
	t.Parallel()
	if adapter, err := newNativeVerifiedPrivilegeReleaseAuthority(nil); adapter != nil || err == nil {
		t.Fatal("missing complete release verifier accepted")
	}
	releases := &nativePrivilegeReleaseInventoryStub{}
	releaseAdapter, err := newNativeVerifiedPrivilegeReleaseAuthority(releases)
	if err != nil {
		t.Fatal(err)
	}
	if authority, verifyError := releaseAdapter.VerifyPrivilegeReleaseAuthority(
		t.Context(), []byte(`{"not":"a signed release"}`), "runtime-catalog", "runtime-helper",
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.valid() || releases.calls != 0 {
		t.Fatalf("authority=%+v error=%v calls=%d", authority, verifyError, releases.calls)
	}
	if authority, verifyError := releaseAdapter.VerifyPrivilegeReleaseAuthority(
		t.Context(), nil, "runtime-catalog", "runtime-helper",
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.valid() {
		t.Fatalf("empty release authority=%+v error=%v", authority, verifyError)
	}
	if resource, found := releaseResourceByID(releaseinventory.Manifest{}, "missing"); found || resource.ID() != "" {
		t.Fatalf("zero manifest resource=%+v found=%t", resource, found)
	}
	if resource, found := releaseResourceByID(releaseinventory.Manifest{}, ""); found || resource.ID() != "" {
		t.Fatalf("empty resource ID=%+v found=%t", resource, found)
	}

	if adapter, err := newNativeVerifiedPrivilegeCatalogAuthority(nil, &nativePrivilegeLinuxHostStub{}); adapter != nil || err == nil {
		t.Fatal("missing catalog application accepted")
	}
	if adapter, err := newNativeVerifiedPrivilegeCatalogAuthority(&nativePrivilegeCatalogApplicationStub{}, nil); adapter != nil || err == nil {
		t.Fatal("missing protected host accepted")
	}
	catalogs := &nativePrivilegeCatalogApplicationStub{}
	host := &nativePrivilegeLinuxHostStub{}
	catalogAdapter, err := newNativeVerifiedPrivilegeCatalogAuthority(catalogs, host)
	if err != nil {
		t.Fatal(err)
	}
	resource := nativeRuntimeCatalogResource(t, []byte(`{"signed":"catalog"}`))
	if authority, verifyError := catalogAdapter.VerifyPrivilegeCatalogAuthority(
		t.Context(), []byte(`{"foreign":"catalog"}`), resource, []byte(`{"plan":true}`),
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.Valid() || catalogs.calls != 0 || host.calls != 0 {
		t.Fatalf("authority=%+v error=%v catalog=%d host=%d", authority, verifyError, catalogs.calls, host.calls)
	}
	malformed := []byte(`{}`)
	malformedResource := nativeRuntimeCatalogResource(t, malformed)
	if authority, verifyError := catalogAdapter.VerifyPrivilegeCatalogAuthority(
		t.Context(), malformed, malformedResource, []byte(`{"plan":true}`),
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.Valid() || catalogs.calls != 0 {
		t.Fatalf("malformed authority=%+v error=%v catalog=%d", authority, verifyError, catalogs.calls)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(nativePrivilegeContextOrIntegrity(cancelled), context.Canceled) ||
		!errors.Is(nativePrivilegeContextOrIntegrity(t.Context()), runtimeport.ErrPrivilegeIntegrity) {
		t.Fatal("privilege context mapping did not fail closed")
	}
}

func TestPF006VerifiedPrivilegeCatalogAdapterReachesOnlyVerifiedProjectionAfterExactBytes(t *testing.T) {
	t.Parallel()
	manifestRaw, err := os.ReadFile("testdata/runtime-catalog-macos.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(manifestRaw))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(
		manifest, manifest.SigningKeyID(), []byte("detached catalog signature"),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := runtimecatalog.EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	resource := nativeRuntimeCatalogResource(t, raw)
	binding, err := runtimecatalogapp.NewLinuxHostBinding(runtimecatalogapp.LinuxHostBindingInput{
		VersionID: "24.04", InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	catalogs := &nativePrivilegeCatalogApplicationStub{}
	host := &nativePrivilegeLinuxHostStub{binding: binding}
	adapter, err := newNativeVerifiedPrivilegeCatalogAuthority(catalogs, host)
	if err != nil {
		t.Fatal(err)
	}
	if authority, verifyError := adapter.VerifyPrivilegeCatalogAuthority(
		t.Context(), raw, resource, []byte(`{"plan":"untrusted"}`),
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.Valid() ||
		catalogs.calls != 1 || host.calls != 1 {
		t.Fatalf("authority=%+v error=%v catalog=%d host=%d", authority, verifyError, catalogs.calls, host.calls)
	}
	catalogs.err = errors.New("catalog trust failed")
	if authority, verifyError := adapter.VerifyPrivilegeCatalogAuthority(
		t.Context(), raw, resource, []byte(`{"plan":"untrusted"}`),
	); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || authority.Valid() ||
		catalogs.calls != 2 || host.calls != 1 {
		t.Fatalf("failed catalog authority=%+v error=%v catalog=%d host=%d", authority, verifyError, catalogs.calls, host.calls)
	}
}

type nativePrivilegeEnvelopeStub struct {
	release   []byte
	catalog   []byte
	plan      []byte
	catalogID string
	helperID  string
}

func (*nativePrivilegeEnvelopeStub) BindAuthority(runtimeport.LinuxAuthority) (runtimeport.PrivilegeRequest, error) {
	return runtimeport.PrivilegeRequest{}, errors.New("not used")
}
func (*nativePrivilegeEnvelopeStub) Artifacts() []runtimeprovision.PrivilegeArtifactBinding {
	return nil
}
func (s *nativePrivilegeEnvelopeStub) SignedRelease() []byte {
	return append([]byte(nil), s.release...)
}
func (s *nativePrivilegeEnvelopeStub) SignedRuntimeCatalog() []byte {
	return append([]byte(nil), s.catalog...)
}
func (s *nativePrivilegeEnvelopeStub) CanonicalPlan() []byte            { return append([]byte(nil), s.plan...) }
func (s *nativePrivilegeEnvelopeStub) RuntimeCatalogResourceID() string { return s.catalogID }
func (s *nativePrivilegeEnvelopeStub) HelperResourceID() string         { return s.helperID }

type nativePrivilegeReleaseAuthorityStub struct {
	authority nativePrivilegeReleaseAuthority
	err       error
	calls     int
}

type nativePrivilegeReleaseInventoryStub struct{ calls int }

func (s *nativePrivilegeReleaseInventoryStub) Verify(
	context.Context,
	releaseinventory.SignedManifest,
) (appreleaseverify.VerifiedInventory, error) {
	s.calls++
	return appreleaseverify.VerifiedInventory{}, errors.New("not used")
}

func (s *nativePrivilegeReleaseAuthorityStub) VerifyPrivilegeReleaseAuthority(
	context.Context,
	[]byte,
	string,
	string,
) (nativePrivilegeReleaseAuthority, error) {
	s.calls++
	return s.authority, s.err
}

type nativePrivilegeCatalogAuthorityStub struct {
	authority runtimeport.LinuxAuthority
	catalog   releaseinventory.Resource
	err       error
	calls     int
}

type nativePrivilegeCatalogApplicationStub struct {
	verified runtimecatalogapp.VerifiedCatalog
	err      error
	calls    int
}

func (s *nativePrivilegeCatalogApplicationStub) Verify(
	context.Context,
	runtimecatalogapp.Request,
) (runtimecatalogapp.VerifiedCatalog, error) {
	s.calls++
	return s.verified, s.err
}

type nativePrivilegeLinuxHostStub struct {
	binding runtimecatalogapp.LinuxHostBinding
	err     error
	calls   int
}

func (s *nativePrivilegeLinuxHostStub) CurrentLinuxHostBinding(
	context.Context,
) (runtimecatalogapp.LinuxHostBinding, error) {
	s.calls++
	return s.binding, s.err
}

func (s *nativePrivilegeCatalogAuthorityStub) VerifyPrivilegeCatalogAuthority(
	_ context.Context,
	_ []byte,
	catalog releaseinventory.Resource,
	_ []byte,
) (runtimeport.LinuxAuthority, error) {
	s.calls++
	s.catalog = catalog
	return s.authority, s.err
}

type nativePrivilegeHelperSelfStub struct {
	digest runtimeinstall.Hash
	helper releaseinventory.Resource
	err    error
	calls  int
}

func (s *nativePrivilegeHelperSelfStub) VerifyPrivilegeHelperSelf(
	_ context.Context,
	helper releaseinventory.Resource,
	_ runtimeport.LinuxAuthority,
) (runtimeinstall.Hash, error) {
	s.calls++
	s.helper = helper
	return s.digest, s.err
}
