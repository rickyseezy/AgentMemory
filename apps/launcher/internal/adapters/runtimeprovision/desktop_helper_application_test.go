package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DesktopHelperApplicationVerifiesReplaysExecutesAndSignsInClosedOrder(t *testing.T) {
	t.Parallel()
	_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	binding, err := NewDesktopMutationArtifactBinding(
		authority.ArtifactPath(), authority.ArtifactSHA256(), authority.ArtifactBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	order := []string{}
	envelope := &desktopHelperEnvelopeStub{authority: authority, request: request, artifact: binding, present: true}
	decoder := &desktopHelperDecoderStub{envelope: envelope, order: &order}
	authorityVerifier := &desktopHelperAuthorityStub{authority: authority, order: &order}
	artifacts := &desktopHelperArtifactPreparerStub{set: desktopHelperArtifactSetStub{binding: binding, present: true}, order: &order}
	executor := &desktopHelperExecutorStub{order: &order, observation: DesktopMutationObservationInput{
		ExitCode: 0, PostState: request.ExpectedState(),
	}}
	replay := &desktopHelperReplayStub{order: &order}
	signer := &desktopHelperSignerStub{order: &order}
	encoder := &desktopHelperReceiptEncoderStub{order: &order}
	clock := &desktopHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	application, err := NewDesktopMutationHelperApplication(DesktopMutationHelperDependencies{
		Decoder: decoder, Authority: authorityVerifier, Artifacts: artifacts, Executor: executor,
		Replay: replay, Signer: signer, Clock: clock, Encoder: encoder,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := application.ExecuteDesktopMutationRequest(t.Context(), []byte(`{"signed":"request"}`))
	if err != nil || !bytes.Equal(raw, signer.receipt.CanonicalBytes()) ||
		!signer.receipt.BoundTo(request) || replay.begins != 1 || replay.completes != 1 ||
		!slices.Equal(order, []string{"decode", "authority", "replay.begin", "artifacts", "execute", "sign", "replay.complete", "encode"}) {
		t.Fatalf("receipt=%+v raw=%q order=%v replay=%d/%d error=%v", signer.receipt, raw, order, replay.begins, replay.completes, err)
	}
}

func TestPF001DesktopHelperApplicationReturnsAuthenticatedCompletedReplayWithoutMutation(t *testing.T) {
	t.Parallel()
	_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallPrerequisites)
	now := request.IssuedAt().Add(time.Second)
	cached := desktopHelperReceipt(t, request, now, 0, runtimeinstall.Hash{})
	order := []string{}
	application, err := NewDesktopMutationHelperApplication(DesktopMutationHelperDependencies{
		Decoder:   &desktopHelperDecoderStub{envelope: &desktopHelperEnvelopeStub{authority: authority, request: request}, order: &order},
		Authority: &desktopHelperAuthorityStub{authority: authority, order: &order},
		Artifacts: &desktopHelperArtifactPreparerStub{order: &order},
		Executor:  &desktopHelperExecutorStub{order: &order},
		Replay:    &desktopHelperReplayStub{cached: cached, completed: true, order: &order},
		Signer:    &desktopHelperSignerStub{order: &order}, Clock: &desktopHelperClockStub{now: now},
		Encoder: &desktopHelperReceiptEncoderStub{order: &order},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := application.ExecuteDesktopMutationRequest(t.Context(), []byte(`{}`))
	if err != nil || !bytes.Equal(raw, cached.CanonicalBytes()) ||
		!slices.Equal(order, []string{"decode", "authority", "replay.begin", "encode"}) {
		t.Fatalf("replay raw=%q order=%v error=%v", raw, order, err)
	}
}

func TestPF001DesktopHelperApplicationFailsClosedBeforeEverySideEffectBoundary(t *testing.T) {
	t.Parallel()
	_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	binding, err := NewDesktopMutationArtifactBinding(authority.ArtifactPath(), authority.ArtifactSHA256(), authority.ArtifactBytes())
	if err != nil {
		t.Fatal(err)
	}
	private := errors.New("private helper detail")
	for name, mutate := range map[string]func(*DesktopMutationHelperDependencies){
		"decode":    func(d *DesktopMutationHelperDependencies) { d.Decoder = &desktopHelperDecoderStub{err: private} },
		"authority": func(d *DesktopMutationHelperDependencies) { d.Authority = &desktopHelperAuthorityStub{err: private} },
		"replay":    func(d *DesktopMutationHelperDependencies) { d.Replay = &desktopHelperReplayStub{err: private} },
		"artifacts": func(d *DesktopMutationHelperDependencies) {
			d.Artifacts = &desktopHelperArtifactPreparerStub{err: private}
		},
		"execute": func(d *DesktopMutationHelperDependencies) { d.Executor = &desktopHelperExecutorStub{err: private} },
		"post state": func(d *DesktopMutationHelperDependencies) {
			d.Executor = &desktopHelperExecutorStub{observation: DesktopMutationObservationInput{PostState: runtimeinstall.Sum([]byte("foreign"))}}
		},
		"sign":     func(d *DesktopMutationHelperDependencies) { d.Signer = &desktopHelperSignerStub{err: private} },
		"complete": func(d *DesktopMutationHelperDependencies) { d.Replay = &desktopHelperReplayStub{completeErr: private} },
		"encode":   func(d *DesktopMutationHelperDependencies) { d.Encoder = &desktopHelperReceiptEncoderStub{err: private} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dependencies := DesktopMutationHelperDependencies{
				Decoder: &desktopHelperDecoderStub{envelope: &desktopHelperEnvelopeStub{
					authority: authority, request: request, artifact: binding, present: true,
				}},
				Authority: &desktopHelperAuthorityStub{authority: authority},
				Artifacts: &desktopHelperArtifactPreparerStub{set: desktopHelperArtifactSetStub{binding: binding, present: true}},
				Executor:  &desktopHelperExecutorStub{observation: DesktopMutationObservationInput{ExitCode: 0, PostState: request.ExpectedState()}},
				Replay:    &desktopHelperReplayStub{}, Signer: &desktopHelperSignerStub{},
				Clock:   &desktopHelperClockStub{now: request.IssuedAt().Add(time.Second)},
				Encoder: &desktopHelperReceiptEncoderStub{},
			}
			mutate(&dependencies)
			application, constructError := NewDesktopMutationHelperApplication(dependencies)
			if constructError != nil {
				t.Fatal(constructError)
			}
			if raw, executeError := application.ExecuteDesktopMutationRequest(t.Context(), []byte(`{}`)); executeError == nil || len(raw) != 0 || errors.Is(executeError, private) {
				t.Fatalf("raw=%q error=%v", raw, executeError)
			}
		})
	}

	if application, constructError := NewDesktopMutationHelperApplication(DesktopMutationHelperDependencies{}); application != nil || constructError == nil {
		t.Fatalf("empty dependencies accepted: application=%+v error=%v", application, constructError)
	}
	var absent *DesktopMutationHelperApplication
	if raw, executeError := absent.ExecuteDesktopMutationRequest(t.Context(), []byte(`{}`)); executeError == nil || len(raw) != 0 {
		t.Fatalf("nil application raw=%q error=%v", raw, executeError)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	valid, _ := NewDesktopMutationHelperApplication(DesktopMutationHelperDependencies{
		Decoder: &desktopHelperDecoderStub{}, Authority: &desktopHelperAuthorityStub{},
		Artifacts: &desktopHelperArtifactPreparerStub{}, Executor: &desktopHelperExecutorStub{},
		Replay: &desktopHelperReplayStub{}, Signer: &desktopHelperSignerStub{}, Clock: &desktopHelperClockStub{},
		Encoder: &desktopHelperReceiptEncoderStub{},
	})
	if _, executeError := valid.ExecuteDesktopMutationRequest(cancelled, []byte(`{}`)); !errors.Is(executeError, context.Canceled) {
		t.Fatalf("cancelled error=%v", executeError)
	}
}

func TestPF001CanonicalDesktopHelperBoundaryAdaptersRoundTripExactWire(t *testing.T) {
	t.Parallel()
	plan, _, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	codec, err := NewCanonicalDesktopMutationTransportCodec(DesktopMutationEnvelopeInput{
		SignedRelease:        []byte(`{"fixture":"release"}`),
		SignedRuntimeCatalog: []byte(`{"fixture":"catalog"}`),
		CanonicalPlan:        plan.CanonicalBytes(), RuntimeCatalogResourceID: "runtime-catalog-windows-amd64",
		HelperResourceID: "runtime-helper-windows-amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeDesktopMutationRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := (CanonicalDesktopMutationRequestDecoder{}).DecodeDesktopMutationRequest(raw)
	if err != nil || envelope == nil || envelope.HelperResourceID() != "runtime-helper-windows-amd64" {
		t.Fatalf("envelope=%+v error=%v", envelope, err)
	}
	if envelope, err := (CanonicalDesktopMutationRequestDecoder{}).DecodeDesktopMutationRequest([]byte(`{}`)); envelope != nil || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("malformed envelope=%+v error=%v", envelope, err)
	}
	receipt := desktopHelperReceipt(t, request, request.IssuedAt().Add(time.Second), 0, runtimeinstall.Hash{})
	encoded, err := (CanonicalDesktopMutationReceiptEncoder{}).EncodeDesktopMutationReceipt(receipt)
	if err != nil || !bytes.Equal(encoded, receipt.CanonicalBytes()) {
		t.Fatalf("encoded=%q error=%v", encoded, err)
	}
	if encoded, err := (CanonicalDesktopMutationReceiptEncoder{}).EncodeDesktopMutationReceipt(runtimeport.DesktopMutationReceipt{}); len(encoded) != 0 || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero receipt encoded=%q error=%v", encoded, err)
	}
}

func TestPF001DesktopHelperAuthorityEvidenceBindsExactOfflineWindowsPrerequisites(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	resources, certificates := desktopMutationPrerequisiteFixture(t, authority)
	evidence, err := NewDesktopMutationAuthorityEvidenceWithPrerequisites(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
		resources, certificates,
	)
	if err != nil || len(evidence.PrerequisiteResources()) != 2 ||
		evidence.PrerequisiteCertificate(resources[0].ID()).IsZero() {
		t.Fatalf("evidence=%+v error=%v", evidence, err)
	}
	returned := evidence.PrerequisiteResources()
	returned[0] = releaseinventory.Resource{}
	if evidence.PrerequisiteResources()[0].ID() == "" {
		t.Fatal("prerequisite resources alias caller memory")
	}
	for name, mutate := range map[string]func(*[]releaseinventory.Resource, map[string]runtimeinstall.Hash){
		"missing distribution": func(resources *[]releaseinventory.Resource, _ map[string]runtimeinstall.Hash) {
			*resources = (*resources)[:1]
		},
		"missing certificate": func(_ *[]releaseinventory.Resource, certificates map[string]runtimeinstall.Hash) {
			clear(certificates)
		},
		"duplicate installer": func(resources *[]releaseinventory.Resource, _ map[string]runtimeinstall.Hash) {
			(*resources)[1] = (*resources)[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateResources := append([]releaseinventory.Resource(nil), resources...)
			candidateCertificates := make(map[string]runtimeinstall.Hash, len(certificates))
			for id, digest := range certificates {
				candidateCertificates[id] = digest
			}
			mutate(&candidateResources, candidateCertificates)
			if evidence, err := NewDesktopMutationAuthorityEvidenceWithPrerequisites(
				authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
				candidateResources, candidateCertificates,
			); err == nil || !evidence.HelperDigest().IsZero() {
				t.Fatalf("evidence=%+v error=%v", evidence, err)
			}
		})
	}
	_, darwin := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	if evidence, err := NewDesktopMutationAuthorityEvidenceWithPrerequisites(
		darwin, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
		resources, certificates,
	); err == nil || !evidence.HelperDigest().IsZero() {
		t.Fatalf("mac evidence=%+v error=%v", evidence, err)
	}
}

func desktopMutationPrerequisiteFixture(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
) ([]releaseinventory.Resource, map[string]runtimeinstall.Hash) {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("windows", authority.Architecture().String())
	if err != nil {
		t.Fatal(err)
	}
	makeResource := func(
		id string, kind releaseinventory.ResourceKind, purpose releaseinventory.ResourcePurpose,
		media string, file string, publisher bool,
	) releaseinventory.Resource {
		input := releaseinventory.ResourceInput{
			ID: id, Kind: kind, Purpose: purpose, MediaType: media, Platform: platform,
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: 4096,
			SourceRef:               "bundle://runtime/windows/" + file,
			SourceAllowlist:         []string{"bundle://runtime/windows/" + file},
			CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
			ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
			VulnerabilityResourceID: id + "-vulnerability",
		}
		if publisher {
			input.NativePublisherIdentity = "microsoft.windows-subsystem-for-linux"
			input.NativePublisherPolicyID = "microsoft-wsl-native-2026"
		}
		resource, err := releaseinventory.NewResource(input)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	installer := makeResource(
		"wsl-msi", releaseinventory.ResourceKindRuntimeInstaller,
		releaseinventory.ResourcePurposeRuntimeInstaller, releaseinventory.MediaTypeRuntimeInstaller,
		"wsl.2.6.3.0.x64.msi", true,
	)
	distribution := makeResource(
		"ubuntu-wsl", releaseinventory.ResourceKindRuntimeDistribution,
		releaseinventory.ResourcePurposeRuntimeDistribution, releaseinventory.MediaTypeRuntimeDistribution,
		"ubuntu-24.04.wsl", false,
	)
	return []releaseinventory.Resource{installer, distribution}, map[string]runtimeinstall.Hash{
		installer.ID(): runtimeinstall.Sum([]byte("wsl signer certificate")),
	}
}

type desktopHelperEnvelopeStub struct {
	authority runtimeport.DesktopAuthority
	request   runtimeport.DesktopMutationRequest
	artifact  DesktopMutationArtifactBinding
	present   bool
	err       error
}

func (s *desktopHelperEnvelopeStub) BindAuthority(authority runtimeport.DesktopAuthority) (runtimeport.DesktopMutationRequest, error) {
	if s.err != nil || authority.Digest() != s.authority.Digest() {
		return runtimeport.DesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return s.request, nil
}
func (s *desktopHelperEnvelopeStub) Artifact() (DesktopMutationArtifactBinding, bool) {
	return s.artifact, s.present
}
func (*desktopHelperEnvelopeStub) SignedRelease() []byte            { return []byte(`{}`) }
func (*desktopHelperEnvelopeStub) SignedRuntimeCatalog() []byte     { return []byte(`{}`) }
func (*desktopHelperEnvelopeStub) CanonicalPlan() []byte            { return []byte(`{}`) }
func (*desktopHelperEnvelopeStub) RuntimeCatalogResourceID() string { return "catalog" }
func (*desktopHelperEnvelopeStub) HelperResourceID() string         { return "helper" }

type desktopHelperDecoderStub struct {
	envelope DesktopMutationRequestEnvelope
	err      error
	order    *[]string
}

func (s *desktopHelperDecoderStub) DecodeDesktopMutationRequest([]byte) (DesktopMutationRequestEnvelope, error) {
	appendDesktopHelperOrder(s.order, "decode")
	return s.envelope, s.err
}

type desktopHelperAuthorityStub struct {
	authority runtimeport.DesktopAuthority
	err       error
	order     *[]string
}

func (s *desktopHelperAuthorityStub) VerifyDesktopMutationAuthority(
	context.Context,
	DesktopMutationRequestEnvelope,
) (DesktopMutationAuthorityEvidence, error) {
	appendDesktopHelperOrder(s.order, "authority")
	if s.err != nil {
		return DesktopMutationAuthorityEvidence{}, s.err
	}
	return NewDesktopMutationAuthorityEvidence(
		s.authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
}

type desktopHelperArtifactSetStub struct {
	binding DesktopMutationArtifactBinding
	present bool
}

func (s desktopHelperArtifactSetStub) Installer() (DesktopMutationArtifactBinding, bool) {
	return s.binding, s.present
}

type desktopHelperArtifactPreparerStub struct {
	set   DesktopMutationArtifactSet
	err   error
	order *[]string
}

func (s *desktopHelperArtifactPreparerStub) PrepareDesktopMutationArtifact(
	context.Context,
	runtimeport.DesktopMutationRequest,
	DesktopMutationArtifactBinding,
	bool,
) (DesktopMutationArtifactSet, error) {
	appendDesktopHelperOrder(s.order, "artifacts")
	return s.set, s.err
}

type desktopHelperExecutorStub struct {
	observation DesktopMutationObservationInput
	err         error
	order       *[]string
}

func (s *desktopHelperExecutorStub) ExecuteDesktopMutation(
	context.Context,
	runtimeport.DesktopMutationRequest,
	DesktopMutationArtifactSet,
	DesktopMutationAuthorityEvidence,
) (DesktopMutationObservationInput, error) {
	appendDesktopHelperOrder(s.order, "execute")
	return s.observation, s.err
}

type desktopHelperReplayStub struct {
	cached      runtimeport.DesktopMutationReceipt
	completed   bool
	err         error
	completeErr error
	begins      int
	completes   int
	order       *[]string
}

func (s *desktopHelperReplayStub) BeginDesktopMutationRequest(
	context.Context,
	runtimeport.DesktopMutationRequest,
) (runtimeport.DesktopMutationReceipt, bool, error) {
	s.begins++
	appendDesktopHelperOrder(s.order, "replay.begin")
	return s.cached, s.completed, s.err
}

func (s *desktopHelperReplayStub) CompleteDesktopMutationRequest(
	context.Context,
	runtimeport.DesktopMutationRequest,
	runtimeport.DesktopMutationReceipt,
) error {
	s.completes++
	appendDesktopHelperOrder(s.order, "replay.complete")
	return s.completeErr
}

type desktopHelperSignerStub struct {
	receipt runtimeport.DesktopMutationReceipt
	err     error
	order   *[]string
}

func (s *desktopHelperSignerStub) SignDesktopMutationReceipt(
	_ context.Context,
	input runtimeport.DesktopMutationReceiptInput,
) (runtimeport.DesktopMutationReceipt, error) {
	appendDesktopHelperOrder(s.order, "sign")
	if s.err != nil {
		return runtimeport.DesktopMutationReceipt{}, s.err
	}
	input.Signature = bytes.Repeat([]byte{0x42}, 64)
	input.SignatureDigest = runtimeinstall.Sum(input.Signature)
	receipt, err := runtimeport.NewDesktopMutationReceipt(input)
	s.receipt = receipt
	return receipt, err
}

type desktopHelperClockStub struct{ now time.Time }

func (s *desktopHelperClockStub) Now() time.Time { return s.now }

type desktopHelperReceiptEncoderStub struct {
	err   error
	order *[]string
}

func (s *desktopHelperReceiptEncoderStub) EncodeDesktopMutationReceipt(
	receipt runtimeport.DesktopMutationReceipt,
) ([]byte, error) {
	appendDesktopHelperOrder(s.order, "encode")
	if s.err != nil {
		return nil, s.err
	}
	return receipt.CanonicalBytes(), nil
}

func desktopHelperReceipt(
	t testing.TB,
	request runtimeport.DesktopMutationRequest,
	completed time.Time,
	exitCode uint32,
	reboot runtimeinstall.Hash,
) runtimeport.DesktopMutationReceipt {
	t.Helper()
	signature := bytes.Repeat([]byte{0x33}, 64)
	receipt, err := runtimeport.NewDesktopMutationReceipt(runtimeport.DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(), Nonce: request.Nonce(),
		ExitCode: exitCode, PostState: request.ExpectedState(), RebootReceipt: reboot,
		CompletedAt: completed, ExpiresAt: request.ExpiresAt(), Signature: signature,
		SignatureDigest: runtimeinstall.Sum(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func appendDesktopHelperOrder(order *[]string, value string) {
	if order != nil {
		*order = append(*order, value)
	}
}
