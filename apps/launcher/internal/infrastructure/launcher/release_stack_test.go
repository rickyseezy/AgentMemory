package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	releaseverifyadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001NativeReleaseStackComposesEveryTrustGateIntoVerifiedTemplates(t *testing.T) {
	t.Parallel()
	dependencies := nativeReleaseStackFixture(t)
	stack, err := newNativeReleaseStack(dependencies)
	if err != nil || stack.application == nil || stack.templates == nil {
		t.Fatalf("release stack=%+v error=%v", stack, err)
	}
	platform, err := (nativeReleasePlatform{}).CurrentPlatform(t.Context())
	if err != nil || !platform.Valid() || platform.IsAny() {
		t.Fatalf("platform=%+v error=%v", platform, err)
	}
	protocol, err := (nativeReleaseProtocol{}).CurrentProtocol(t.Context())
	if err != nil || protocol != nativeReleaseProtocolVersion {
		t.Fatalf("protocol=%d error=%v", protocol, err)
	}
}

func TestPF001NativeReleaseStackRejectsEveryMissingOrInvalidTrustAuthority(t *testing.T) {
	t.Parallel()
	base := nativeReleaseStackFixture(t)
	var nilSource *nativeReleaseSourceStub
	var nilClock *nativeReleaseClock
	var nilAnchor *nativeReleasePorts
	for _, test := range []struct {
		name   string
		mutate func(*nativeReleaseStackDependencies)
	}{
		{name: "source", mutate: func(d *nativeReleaseStackDependencies) { d.Source = nilSource }},
		{name: "clock", mutate: func(d *nativeReleaseStackDependencies) { d.Clock = nilClock }},
		{name: "anchor", mutate: func(d *nativeReleaseStackDependencies) { d.AntiRollback = nilAnchor }},
		{name: "manifest keys", mutate: func(d *nativeReleaseStackDependencies) { d.Trust.ManifestKeys = nil }},
		{name: "offline policy", mutate: func(d *nativeReleaseStackDependencies) { d.Trust.Offline.TrustDomain = "" }},
		{name: "provenance policy", mutate: func(d *nativeReleaseStackDependencies) { d.Trust.Provenance.BuildIdentities = nil }},
		{name: "qualification policy", mutate: func(d *nativeReleaseStackDependencies) { d.Trust.Qualification.PublicKeys = nil }},
		{name: "publisher policy", mutate: func(d *nativeReleaseStackDependencies) { d.Trust.Publishers = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			stack, err := newNativeReleaseStack(candidate)
			if stack.application != nil || stack.templates != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
				t.Fatalf("stack=%+v error=%v", stack, err)
			}
		})
	}
}

func TestPF001NativeReleasePlatformAndProtocolRespectCancellation(t *testing.T) {
	t.Parallel()
	//lint:ignore SA1012 Deliberate absent-context composition boundary.
	if _, err := (nativeReleasePlatform{}).CurrentPlatform(nil); err == nil { //nolint:staticcheck
		t.Fatal("nil platform context accepted")
	}
	//lint:ignore SA1012 Deliberate absent-context composition boundary.
	if _, err := (nativeReleaseProtocol{}).CurrentProtocol(nil); err == nil { //nolint:staticcheck
		t.Fatal("nil protocol context accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (nativeReleasePlatform{}).CurrentPlatform(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("platform cancellation error=%v", err)
	}
	if _, err := (nativeReleaseProtocol{}).CurrentProtocol(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("protocol cancellation error=%v", err)
	}
}

func nativeReleaseStackFixture(t testing.TB) nativeReleaseStackDependencies {
	t.Helper()
	manifestPublic, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	evidencePublic, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	qualificationPublic, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x33}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	license := releaseinventory.DigestBytes([]byte("license-policy"))
	vulnerability := releaseinventory.DigestBytes([]byte("vulnerability-policy"))
	ports := &nativeReleasePorts{}
	return nativeReleaseStackDependencies{
		Source: &nativeReleaseSourceStub{}, Clock: &nativeReleaseClock{now: time.Now().UTC()}, AntiRollback: ports,
		Trust: nativeReleaseTrustMaterial{
			ManifestKeys:       map[string]ed25519.PublicKey{"release-root": manifestPublic},
			HostPolicyKeys:     map[string]ed25519.PublicKey{"host-policy-root": manifestPublic},
			RuntimeCatalogKeys: map[string]ed25519.PublicKey{"runtime-catalog-root": manifestPublic},
			Offline: releaseverifyadapter.OfflineTrustPolicyInput{
				TrustDomain: "agentmemory.release", RevocationAuthorities: map[string]ed25519.PublicKey{"revocations": evidencePublic},
				TimeAuthorities: map[string]ed25519.PublicKey{"trusted-time": evidencePublic}, MaximumFutureSkew: time.Minute,
			},
			Provenance: releaseverifyadapter.ProvenanceTrustPolicyInput{
				BuildIdentities: []releaseverifyadapter.ProvenanceBuildIdentity{{
					BuilderID: "https://github.com/actions/runner", BuildType: "https://slsa.dev/container-based-build/v0.1",
					SourceRepository: "https://github.com/rickyseezy/AgentMemory", WorkflowPath: ".github/workflows/release.yml",
				}},
				RecipeDigests: []releaseinventory.Digest{releaseinventory.DigestBytes([]byte("release-recipe"))},
			},
			Qualification: releaseverifyadapter.QualificationTrustPolicyInput{
				PublicKeys:                 map[string]ed25519.PublicKey{"qualification": qualificationPublic},
				LicensePolicySigners:       map[releaseinventory.Digest]string{license: "qualification"},
				VulnerabilityPolicySigners: map[releaseinventory.Digest]string{vulnerability: "qualification"},
			},
			Publishers: releaseverifyadapter.NativePublisherPolicyInput{
				"agentmemory-native-2026": {"agentmemory.publisher"},
			},
		},
	}
}

type nativeReleaseSourceStub struct{}

func (*nativeReleaseSourceStub) ReadDistributionEnvelope(context.Context) ([]byte, error) {
	return nil, errors.New("not read during composition")
}

func (*nativeReleaseSourceStub) OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error) {
	return nil, errors.New("not read during composition")
}

type nativeReleaseClock struct{ now time.Time }

func (c *nativeReleaseClock) Now() time.Time { return c.now }

type nativeReleasePorts struct{}

func (*nativeReleasePorts) LoadReleaseAnchor(context.Context, releaseinventory.ReleaseChannel) (appreleaseverify.ReleaseAnchor, error) {
	return appreleaseverify.ReleaseAnchor{}, appreleaseverify.ErrReleaseAnchorNotFound
}

func (*nativeReleasePorts) CompareAndSwapReleaseAnchor(context.Context, *appreleaseverify.ReleaseAnchor, appreleaseverify.ReleaseAnchor) error {
	return nil
}
