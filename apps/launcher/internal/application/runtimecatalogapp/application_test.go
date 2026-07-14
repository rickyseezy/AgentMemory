package runtimecatalogapp

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestVerifyReturnsAuthorityOnlyAfterEveryGateAndAnchorCAS(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	events := make([]string, 0, 5)
	application := mustApplication(t, Dependencies{
		Clock:           fixedClock{value: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
		Host:            hostProvider{host: supportedHost(t), events: &events},
		Signature:       signatureVerifier{events: &events},
		NativePublisher: publisherVerifier{events: &events},
		AntiRollback:    &anchorRepository{loadErr: ErrCatalogAnchorNotFound, events: &events},
	})

	verified, err := application.Verify(context.Background(), Request{
		SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
		SourceMode: runtimecatalog.SourceModeOnline, OnlineSource: source,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.CatalogID() != signed.Manifest().CatalogID() ||
		verified.Sequence() != signed.Manifest().CatalogSequence() ||
		!verified.ManifestDigest().Equal(signed.Manifest().Digest()) || verified.AlreadyAccepted() {
		t.Fatalf("verified catalog projection is incomplete: %#v", verified)
	}
	if verified.Manifest().Runtime().ComposeVersion() != "2.39.1" ||
		verified.VerifiedAt() != time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatal("verified execution authority lost catalog or time binding")
	}
	wantOrder := []string{"signature", "host", "publisher", "anchor_load", "anchor_cas"}
	if !reflect.DeepEqual(events, wantOrder) {
		t.Fatalf("verification order = %v, want %v", events, wantOrder)
	}
}

func TestVerifyIsIdempotentForExactAcceptedCatalog(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	anchor := mustAnchor(t, signed.Manifest())
	repository := &anchorRepository{anchor: anchor}
	application := mustApplication(t, validDependencies(t, repository))

	verified, err := application.Verify(context.Background(), Request{
		SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
		SourceMode: runtimecatalog.SourceModeOnline, OnlineSource: source,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verified.AlreadyAccepted() || repository.casCalls != 0 {
		t.Fatalf("idempotent verification = (%t, %d CAS calls)", verified.AlreadyAccepted(), repository.casCalls)
	}
}

func TestVerifyPersistsMonotonicUpgradeAndProjectsSourceDefensively(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	prior := mustAnchorValues(
		t,
		signed.Manifest().CatalogID(),
		signed.Manifest().CatalogSequence()-1,
		runtimecatalog.DigestBytes([]byte("prior catalog")),
	)
	repository := &anchorRepository{anchor: prior}
	verified, err := mustApplication(t, validDependencies(t, repository)).Verify(
		context.Background(),
		validRequest(signed, source),
	)
	if err != nil {
		t.Fatalf("Verify(upgrade) error = %v", err)
	}
	if repository.expected == nil || repository.expected.Sequence() != prior.Sequence() ||
		repository.next.Sequence() != signed.Manifest().CatalogSequence() ||
		verified.SourceMode() != runtimecatalog.SourceModeOnline {
		t.Fatal("upgrade CAS or verified source binding is incomplete")
	}
	selected := verified.OnlineSource()
	if selected == nil || selected.Host() != "desktop.docker.com" {
		t.Fatal("verified online source is missing")
	}
	other := mustSource(t, "https", "mirror.example.com", "/docker/")
	*selected = other
	if verified.OnlineSource().Host() != "desktop.docker.com" {
		t.Fatal("verified online source leaked mutable storage")
	}

	offlineRepository := &anchorRepository{loadErr: ErrCatalogAnchorNotFound}
	offline, err := mustApplication(t, validDependencies(t, offlineRepository)).Verify(
		context.Background(),
		Request{
			SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
			SourceMode: runtimecatalog.SourceModeOfflineBundle,
		},
	)
	if err != nil || offline.SourceMode() != runtimecatalog.SourceModeOfflineBundle || offline.OnlineSource() != nil {
		t.Fatalf("Verify(offline bundle) = (%#v, %v)", offline, err)
	}
}

func TestVerifiedCatalogProjectsOnlyVerifiedAuthorityIntoRuntimePlanner(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	verified, err := mustApplication(
		t,
		validDependencies(t, &anchorRepository{loadErr: ErrCatalogAnchorNotFound}),
	).Verify(context.Background(), validRequest(signed, source))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	certified, err := verified.CertifiedRuntime()
	if err != nil {
		t.Fatalf("CertifiedRuntime() error = %v", err)
	}
	if certified.Platform() != runtimeinstall.PlatformDarwin ||
		certified.Architecture() != runtimeinstall.ArchitectureARM64 ||
		certified.CatalogSequence() != signed.Manifest().CatalogSequence() ||
		certified.DownloadBytes() != signed.Manifest().Artifact().DownloadBytes() ||
		certified.ExpandedBytes() != signed.Manifest().Artifact().ExpandedBytes() ||
		certified.TermsDigest().IsZero() {
		t.Fatal("certified runtime projection omitted verified catalog authority")
	}
	if _, err := (VerifiedCatalog{}).CertifiedRuntime(); err == nil {
		t.Fatal("zero verified catalog created runtime planning authority")
	}
}

func TestCatalogAnchorContractRejectsInvalidStateAndProjectsValidState(t *testing.T) {
	t.Parallel()

	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	anchor := mustAnchorValues(t, "docker-macos-arm64", 7, digest)
	if anchor.CatalogID() != "docker-macos-arm64" || anchor.Sequence() != 7 ||
		!anchor.ManifestDigest().Equal(digest) {
		t.Fatal("catalog anchor projection is incomplete")
	}
	for _, input := range []struct {
		id       string
		sequence uint64
		digest   runtimecatalog.Digest
	}{
		{id: "", sequence: 1, digest: digest},
		{id: "INVALID", sequence: 1, digest: digest},
		{id: "valid", sequence: 0, digest: digest},
		{id: "valid", sequence: 1},
	} {
		if _, err := NewCatalogAnchor(input.id, input.sequence, input.digest); err == nil {
			t.Fatalf("NewCatalogAnchor(%q, %d) error = nil", input.id, input.sequence)
		}
	}
}

func TestVerifyFailsClosedAtEveryTrustAndPolicyBoundary(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	differentDigest := runtimecatalog.DigestBytes([]byte("different"))
	expiredClock := fixedClock{value: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}
	unsupported := mustHost(t, runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: runtimecatalog.ArchitectureX8664,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 16_000_000_000, FreeDiskBytes: 100_000_000_000, Virtualization: true,
	})
	unofficial := mustSource(t, "https", "mirror.example.com", "/docker/")
	older := mustAnchorValues(t, signed.Manifest().CatalogID(), signed.Manifest().CatalogSequence()+1, differentDigest)
	equivocation := mustAnchorValues(t, signed.Manifest().CatalogID(), signed.Manifest().CatalogSequence(), differentDigest)

	tests := []struct {
		name       string
		request    Request
		configure  func(*Dependencies)
		wantReason FailureReason
	}{
		{name: "missing envelope", request: Request{}, wantReason: FailureReasonCatalogIntegrity},
		{name: "release digest mismatch", request: Request{SignedManifest: signed, ExpectedManifestDigest: differentDigest, SourceMode: runtimecatalog.SourceModeOnline, OnlineSource: source}, wantReason: FailureReasonReleaseBinding},
		{name: "untrusted signer", request: validRequest(signed, source), configure: func(d *Dependencies) { d.Signature = signatureVerifier{err: ErrUntrustedSigner} }, wantReason: FailureReasonUntrustedSigner},
		{name: "invalid signature", request: validRequest(signed, source), configure: func(d *Dependencies) { d.Signature = signatureVerifier{err: ErrSignatureInvalid} }, wantReason: FailureReasonSignatureInvalid},
		{name: "expired", request: validRequest(signed, source), configure: func(d *Dependencies) { d.Clock = expiredClock }, wantReason: FailureReasonSupportExpired},
		{name: "unsupported host", request: validRequest(signed, source), configure: func(d *Dependencies) { d.Host = hostProvider{host: unsupported} }, wantReason: FailureReasonUnsupportedHost},
		{name: "source denied", request: Request{SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(), SourceMode: runtimecatalog.SourceModeOnline, OnlineSource: unofficial}, wantReason: FailureReasonSourceDenied},
		{name: "publisher invalid", request: validRequest(signed, source), configure: func(d *Dependencies) { d.NativePublisher = publisherVerifier{err: ErrNativePublisherInvalid} }, wantReason: FailureReasonNativePublisher},
		{name: "rollback", request: validRequest(signed, source), configure: func(d *Dependencies) { d.AntiRollback = &anchorRepository{anchor: older} }, wantReason: FailureReasonCatalogRollback},
		{name: "equivocation", request: validRequest(signed, source), configure: func(d *Dependencies) { d.AntiRollback = &anchorRepository{anchor: equivocation} }, wantReason: FailureReasonSequenceEquivocation},
		{name: "anchor integrity", request: validRequest(signed, source), configure: func(d *Dependencies) { d.AntiRollback = &anchorRepository{loadErr: ErrCatalogAnchorIntegrity} }, wantReason: FailureReasonAnchorIntegrity},
		{name: "CAS conflict", request: validRequest(signed, source), configure: func(d *Dependencies) {
			d.AntiRollback = &anchorRepository{loadErr: ErrCatalogAnchorNotFound, casErr: ErrCatalogAnchorConflict}
		}, wantReason: FailureReasonAnchorConflict},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dependencies := validDependencies(t, &anchorRepository{loadErr: ErrCatalogAnchorNotFound})
			if test.configure != nil {
				test.configure(&dependencies)
			}
			application := mustApplication(t, dependencies)
			_, err := application.Verify(context.Background(), test.request)
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) || verificationError.Reason() != test.wantReason {
				t.Fatalf("Verify() error = %v, want reason %q", err, test.wantReason)
			}
		})
	}
}

func TestVerifyMapsCancellationAndDependencyFailuresWithoutRawDetails(t *testing.T) {
	t.Parallel()

	signed, source := signedCatalog(t)
	tests := []struct {
		name      string
		configure func(*Dependencies)
		context   func() context.Context
		wantCode  ErrorCode
	}{
		{name: "pre-cancelled", context: cancelledContext, wantCode: ErrorCodeCancelled},
		{name: "nil context", context: func() context.Context { return nil }, wantCode: ErrorCodeCancelled},
		{name: "zero policy clock", configure: func(d *Dependencies) { d.Clock = fixedClock{} }, wantCode: ErrorCodeDependencyUnavailable},
		{name: "signature unavailable", configure: func(d *Dependencies) { d.Signature = signatureVerifier{err: ErrDependencyUnavailable} }, wantCode: ErrorCodeDependencyUnavailable},
		{name: "host unavailable", configure: func(d *Dependencies) { d.Host = hostProvider{err: errors.New("secret raw host error")} }, wantCode: ErrorCodeDependencyUnavailable},
		{name: "publisher unavailable", configure: func(d *Dependencies) { d.NativePublisher = publisherVerifier{err: ErrDependencyUnavailable} }, wantCode: ErrorCodeDependencyUnavailable},
		{name: "anchor unavailable", configure: func(d *Dependencies) { d.AntiRollback = &anchorRepository{loadErr: ErrDependencyUnavailable} }, wantCode: ErrorCodeDependencyUnavailable},
		{name: "invalid stored anchor", configure: func(d *Dependencies) { d.AntiRollback = &anchorRepository{} }, wantCode: ErrorCodeIntegrity},
		{name: "CAS integrity", configure: func(d *Dependencies) {
			d.AntiRollback = &anchorRepository{loadErr: ErrCatalogAnchorNotFound, casErr: ErrCatalogAnchorIntegrity}
		}, wantCode: ErrorCodeIntegrity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dependencies := validDependencies(t, &anchorRepository{loadErr: ErrCatalogAnchorNotFound})
			if test.configure != nil {
				test.configure(&dependencies)
			}
			ctx := backgroundContext()
			if test.context != nil {
				ctx = test.context()
			}
			_, err := mustApplication(t, dependencies).Verify(ctx, validRequest(signed, source))
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) || verificationError.Code() != test.wantCode {
				t.Fatalf("Verify() error = %v, want code %q", err, test.wantCode)
			}
			if !errors.Is(verificationError, ErrVerificationFailed) || verificationError.Reason() == "" ||
				verificationError.Error() == "" {
				t.Fatal("verification error lost stable classification")
			}
			if stringsContain(verificationError.Error(), "secret raw") {
				t.Fatal("verification error exposed raw dependency detail")
			}
		})
	}
}

func TestNewApplicationRejectsMissingAndTypedNilPorts(t *testing.T) {
	t.Parallel()

	base := validDependencies(t, &anchorRepository{})
	tests := []struct {
		name string
		edit func(*Dependencies)
	}{
		{name: "clock", edit: func(d *Dependencies) { d.Clock = nil }},
		{name: "host", edit: func(d *Dependencies) { d.Host = nil }},
		{name: "signature", edit: func(d *Dependencies) { d.Signature = nil }},
		{name: "publisher", edit: func(d *Dependencies) { d.NativePublisher = nil }},
		{name: "anti-rollback", edit: func(d *Dependencies) { d.AntiRollback = nil }},
		{name: "typed nil", edit: func(d *Dependencies) { var repository *anchorRepository; d.AntiRollback = repository }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dependencies := base
			test.edit(&dependencies)
			if _, err := NewApplication(dependencies); err == nil {
				t.Fatal("NewApplication() error = nil")
			}
		})
	}
}

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type hostProvider struct {
	host   runtimecatalog.Host
	err    error
	events *[]string
}

func (p hostProvider) CurrentHost(context.Context) (runtimecatalog.Host, error) {
	appendEvent(p.events, "host")
	return p.host, p.err
}

type signatureVerifier struct {
	err    error
	events *[]string
}

func (v signatureVerifier) VerifyManifestSignature(context.Context, runtimecatalog.SignedManifest) error {
	appendEvent(v.events, "signature")
	return v.err
}

type publisherVerifier struct {
	err    error
	events *[]string
}

func (v publisherVerifier) VerifyNativePublisherPolicy(context.Context, runtimecatalog.PublisherPolicy) error {
	appendEvent(v.events, "publisher")
	return v.err
}

type anchorRepository struct {
	anchor   CatalogAnchor
	loadErr  error
	casErr   error
	casCalls int
	events   *[]string
	expected *CatalogAnchor
	next     CatalogAnchor
}

func (r *anchorRepository) LoadCatalogAnchor(context.Context, string) (CatalogAnchor, error) {
	appendEvent(r.events, "anchor_load")
	return r.anchor, r.loadErr
}

func (r *anchorRepository) CompareAndSwapCatalogAnchor(
	_ context.Context,
	expected *CatalogAnchor,
	next CatalogAnchor,
) error {
	appendEvent(r.events, "anchor_cas")
	r.casCalls++
	if expected != nil {
		expectedCopy := *expected
		r.expected = &expectedCopy
	}
	r.next = next
	return r.casErr
}

func appendEvent(events *[]string, event string) {
	if events != nil {
		*events = append(*events, event)
	}
}

func validDependencies(t *testing.T, repository AntiRollbackRepository) Dependencies {
	t.Helper()
	return Dependencies{
		Clock: fixedClock{value: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
		Host:  supportedHostProvider(t), Signature: signatureVerifier{},
		NativePublisher: publisherVerifier{}, AntiRollback: repository,
	}
}

func supportedHostProvider(t *testing.T) HostProvider {
	t.Helper()
	return hostProvider{host: supportedHost(t)}
}

func supportedHost(t *testing.T) runtimecatalog.Host {
	t.Helper()
	return mustHost(t, runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: runtimecatalog.ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 16_000_000_000, FreeDiskBytes: 100_000_000_000, Virtualization: true,
	})
}

func signedCatalog(t *testing.T) (runtimecatalog.SignedManifest, runtimecatalog.SourceLocation) {
	t.Helper()
	manifest := mustCatalogManifest(t)
	signed, err := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("signature"))
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	return signed, mustSource(t, "https", "desktop.docker.com", "/mac/main/arm64/docker.dmg")
}

func mustCatalogManifest(t *testing.T) runtimecatalog.Manifest {
	t.Helper()
	manifest, err := runtimecatalog.DecodeManifestV1(canonicalFixture(t))
	if err != nil {
		t.Fatalf("DecodeManifestV1() error = %v", err)
	}
	return manifest
}

func canonicalFixture(t *testing.T) []byte {
	t.Helper()
	// Generated by the domain package's canonical schema-v1 constructor fixture.
	return []byte(`{"artifact":{"download_bytes":700000000,"expanded_bytes":2000000000,"offline_policy":"bundled","proxy_mode":"system_proxy","publisher":{"identity":"developer-id-application-docker-inc-9bnsxjn65r","package_identity":"com.docker.docker","signing_key_identity":"apple-developer-id-9bnsxjn65r","verification":"apple_developer_id_notarized"},"redistribution_permitted":true,"reserve_bytes":3000000000,"sha256":"f9b04f64ff588edfd7b2ca52274aeb1ded968431fdd4f2464ec58e76f5dd39e2","sources":[{"host":"desktop.docker.com","path_prefix":"/mac/main/arm64/","scheme":"https"}]},"capability_probes":["bind_read_only","compose_version","engine_api","linux_containers","local_endpoint","network_isolation","no_tcp_listener","security_mode","volume_persistence"],"catalog_id":"docker-desktop-macos-arm64","catalog_sequence":42,"desktop_execution":{"acquisition_safety_bytes":100000000,"artifact_file_name":"Docker.dmg","capability_policy_digest":"f02358660cb228481d25e3c8975847afae97368c66517da53f498405428a0e1b","minimum_available_memory":4000000000,"minimum_wsl_version":"","probe_contract_version":"1","probe_image":"docker.io/rickyseezy/agentmemory-runtime-probe@sha256:bdd2f88588818fcb0dcf6e15f70c690a529e2517d0e3261eb2f823e7ea58c042","probe_image_digest":"bdd2f88588818fcb0dcf6e15f70c690a529e2517d0e3261eb2f823e7ea58c042","rollback_headroom_bytes":200000000},"install":{"arguments":[{"kind":"literal","value":"install"},{"kind":"artifact_path","value":""},{"kind":"plan_digest","value":""}],"executable":"macos_installer","ownership_changes":["application:com.docker.docker","service:com.docker.backend"],"reboot_exit_codes":null,"rollback_strategy":"preserve_runtime","service_identity":"com.docker.backend","vendor_ui_mandatory":false},"platform":{"architecture":"arm64","distribution":"macos","edition":"desktop","maximum_build":25000,"maximum_os_version":"15.9.9","minimum_build":23000,"minimum_cpu_cores":4,"minimum_free_disk_bytes":32212254720,"minimum_memory_bytes":8589934592,"minimum_os_version":"14.0.0","operating_system":"macos","virtualization_required":true},"prerequisites":[{"feature_id":"","operation":"install_verified_package","package_ids":["com.docker.docker"],"repository_id":"","service_id":"","subordinate_id_count":0}],"runtime":{"channel":"stable","components":[{"name":"engine","version":"28.3.2"},{"name":"cli","version":"28.3.2"},{"name":"containerd","version":"1.7.27"},{"name":"buildx","version":"0.25.0"},{"name":"compose","version":"2.39.1"}],"compose_version":"2.39.1","product":"docker_desktop","version":"28.3.2"},"schema_version":1,"signing_key_id":"agentmemory-runtime-root-2026","support_expires_at":1814400000000000,"terms":{"digest":"8e0049eb64e55e33cc6efffe478472ac3ca4585d7e2b05bfedb76e59de97fbce","id":"docker-subscription-service-agreement","presentation":"agentmemory","url":{"host":"www.docker.com","path_prefix":"/legal/docker-subscription-service-agreement","scheme":"https"},"version":"2025.07.02"}}`)
}

func validRequest(signed runtimecatalog.SignedManifest, source runtimecatalog.SourceLocation) Request {
	return Request{
		SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
		SourceMode: runtimecatalog.SourceModeOnline, OnlineSource: source,
	}
}

func mustApplication(t *testing.T, dependencies Dependencies) *Application {
	t.Helper()
	application, err := NewApplication(dependencies)
	if err != nil {
		t.Fatalf("NewApplication() error = %v", err)
	}
	return application
}

func mustAnchor(t *testing.T, manifest runtimecatalog.Manifest) CatalogAnchor {
	t.Helper()
	return mustAnchorValues(t, manifest.CatalogID(), manifest.CatalogSequence(), manifest.Digest())
}

func mustAnchorValues(t *testing.T, id string, sequence uint64, digest runtimecatalog.Digest) CatalogAnchor {
	t.Helper()
	anchor, err := NewCatalogAnchor(id, sequence, digest)
	if err != nil {
		t.Fatalf("NewCatalogAnchor() error = %v", err)
	}
	return anchor
}

func mustHost(t *testing.T, input runtimecatalog.HostInput) runtimecatalog.Host {
	t.Helper()
	host, err := runtimecatalog.NewHost(input)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	return host
}

func mustSource(t *testing.T, scheme string, host string, path string) runtimecatalog.SourceLocation {
	t.Helper()
	source, err := runtimecatalog.NewSourceLocation(runtimecatalog.OfficialSourceInput{
		Scheme: scheme, Host: host, PathPrefix: path,
	})
	if err != nil {
		t.Fatalf("NewSourceLocation() error = %v", err)
	}
	return source
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func backgroundContext() context.Context { return context.Background() }

func stringsContain(value string, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
