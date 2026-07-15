package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001CanonicalDesktopMutationCodecRoundTripsIndependentlyVerifiableAuthority(t *testing.T) {
	t.Parallel()
	plan, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	input := DesktopMutationEnvelopeInput{
		SignedRelease:            []byte(`{"fixture":"signed-release"}`),
		SignedRuntimeCatalog:     []byte(`{"fixture":"signed-runtime-catalog"}`),
		CanonicalPlan:            plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "runtime-catalog-windows-amd64",
		HelperResourceID:         "runtime-helper-windows-amd64",
	}
	codec, err := NewCanonicalDesktopMutationTransportCodec(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeDesktopMutationRequest(t.Context(), request)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] == '\n' || !json.Valid(raw) {
		t.Fatalf("EncodeDesktopMutationRequest() bytes=%d error=%v", len(raw), err)
	}
	decoded, err := DecodeCanonicalDesktopMutationRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := decoded.BindAuthority(authority)
	artifact, present := decoded.Artifact()
	if err != nil || bound.Digest() != request.Digest() || bound.ExpectedState() != request.ExpectedState() ||
		decoded.RuntimeCatalogResourceID() != input.RuntimeCatalogResourceID ||
		decoded.HelperResourceID() != input.HelperResourceID ||
		!bytes.Equal(decoded.SignedRelease(), input.SignedRelease) ||
		!bytes.Equal(decoded.SignedRuntimeCatalog(), input.SignedRuntimeCatalog) ||
		!bytes.Equal(decoded.CanonicalPlan(), input.CanonicalPlan) || !present ||
		artifact.Path() != authority.ArtifactPath() || artifact.SHA256() != authority.ArtifactSHA256() ||
		artifact.Size() != authority.ArtifactBytes() {
		t.Fatalf("decoded desktop request mismatch: request=%+v artifact=%+v present=%t error=%v", bound, artifact, present, err)
	}
	reencoded, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(reencoded, raw) {
		t.Fatalf("CanonicalBytes() mismatch error=%v", err)
	}

	input.SignedRelease[2] ^= 1
	input.SignedRuntimeCatalog[2] ^= 1
	input.CanonicalPlan[2] ^= 1
	copyOfRelease := decoded.SignedRelease()
	copyOfRelease[2] ^= 1
	if bytes.Equal(codec.signedRelease, input.SignedRelease) || bytes.Equal(decoded.SignedRelease(), copyOfRelease) {
		t.Fatal("desktop mutation envelope aliases caller-owned bytes")
	}
}

func TestPF001CanonicalDesktopMutationCodecCarriesNoArtifactForFixedWindowsPrerequisites(t *testing.T) {
	t.Parallel()
	plan, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallPrerequisites)
	codec, err := NewCanonicalDesktopMutationTransportCodec(DesktopMutationEnvelopeInput{
		SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeDesktopMutationRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalDesktopMutationRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := decoded.BindAuthority(authority)
	_, present := decoded.Artifact()
	if err != nil || bound.Digest() != request.Digest() || present {
		t.Fatalf("prerequisite envelope bound=%+v artifact=%t error=%v", bound, present, err)
	}
}

func TestPF001CanonicalDesktopMutationCodecBindsRemovalWithoutTransportingAnExecutable(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopAdapterAuthority(t, platform)
			request := desktopMutationRequestForAuthority(t, authority, runtimeport.DesktopMutationRemoveRuntime)
			codec, err := NewCanonicalDesktopMutationTransportCodec(DesktopMutationEnvelopeInput{
				SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
				RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := codec.EncodeDesktopMutationRequest(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeCanonicalDesktopMutationRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := decoded.BindAuthority(authority)
			_, present := decoded.Artifact()
			if err != nil || bound.Digest() != request.Digest() || present ||
				bound.ArtifactDigest() != authority.ArtifactSHA256() {
				t.Fatalf("platform=%s bound=%+v artifact=%t error=%v", platform, bound, present, err)
			}
		})
	}
}

func TestPF001CanonicalDesktopMutationCodecRejectsAmbiguityAndAuthoritySubstitution(t *testing.T) {
	t.Parallel()
	plan, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	codec, err := NewCanonicalDesktopMutationTransportCodec(DesktopMutationEnvelopeInput{
		SignedRelease: []byte(`{"fixture":"release"}`), SignedRuntimeCatalog: []byte(`{"fixture":"catalog"}`),
		CanonicalPlan: plan.CanonicalBytes(), RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeDesktopMutationRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"leading whitespace": append([]byte(" "), raw...),
		"unknown field": bytes.Replace(
			raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1,
		),
		"duplicate field": bytes.Replace(
			raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1,
		),
		"request digest": bytes.Replace(
			raw, []byte(request.Digest().String()), []byte(runtimeinstall.Sum([]byte("foreign-request")).String()), 1,
		),
	} {
		decoded, decodeError := DecodeCanonicalDesktopMutationRequest(candidate)
		if decodeError == nil {
			if _, bindError := decoded.BindAuthority(authority); bindError == nil {
				t.Fatalf("%s mutation accepted", name)
			}
		}
	}
	document := copyDesktopMutationEnvelope(mustDecodeDesktopMutationRequest(t, raw).document)
	document.Artifact.Path = `C:\Users\Agent User\AppData\Local\AgentMemory\runtime\foreign.exe`
	substitutedArtifact, err := encodeCanonicalDesktopMutationEnvelope(document)
	if err != nil {
		t.Fatal(err)
	}
	decodedArtifact, decodeError := DecodeCanonicalDesktopMutationRequest(substitutedArtifact)
	if decodeError == nil {
		if _, bindError := decodedArtifact.BindAuthority(authority); bindError == nil {
			t.Fatal("artifact path mutation accepted")
		}
	}

	_, foreignAuthority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	if _, bindError := mustDecodeDesktopMutationRequest(t, raw).BindAuthority(foreignAuthority); bindError == nil {
		t.Fatal("cross-platform authority substitution accepted")
	}
	for name, input := range map[string]DesktopMutationEnvelopeInput{
		"empty release": {
			SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		},
		"noncanonical release": {
			SignedRelease: []byte(`{ "x": 1 }`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		},
		"bad catalog": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`x`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		},
		"bad plan": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: []byte(`{}`),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		},
		"unsafe resource": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "../catalog", HelperResourceID: "helper",
		},
	} {
		if candidate, constructError := NewCanonicalDesktopMutationTransportCodec(input); candidate != nil || constructError == nil {
			t.Fatalf("%s input accepted", name)
		}
	}
}

func TestPF001CanonicalDesktopMutationCodecContainsContextAndMalformedTransport(t *testing.T) {
	t.Parallel()
	plan, _, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	codec, err := NewCanonicalDesktopMutationTransportCodec(DesktopMutationEnvelopeInput{
		SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, encodeError := codec.EncodeDesktopMutationRequest(cancelled, request); !errors.Is(encodeError, context.Canceled) {
		t.Fatalf("cancelled error=%v", encodeError)
	}
	if _, encodeError := codec.EncodeDesktopMutationRequest(hostileNilContext(), request); !errors.Is(encodeError, ErrProvisionIntegrity) {
		t.Fatalf("nil context error=%v", encodeError)
	}
	if decoded, decodeError := DecodeCanonicalDesktopMutationRequest(nil); decodeError == nil || len(decoded.CanonicalPlan()) != 0 {
		t.Fatalf("empty transport accepted: %+v %v", decoded, decodeError)
	}
	if _, bindingError := NewDesktopMutationArtifactBinding("relative.exe", runtimeinstall.Sum([]byte("x")), 1); bindingError == nil {
		t.Fatal("relative desktop artifact binding accepted")
	}
}

func desktopMutationCodecFixture(
	t testing.TB,
	operation runtimeport.DesktopMutationOperation,
) (runtimeinstall.Plan, runtimeport.DesktopAuthority, runtimeport.DesktopMutationRequest) {
	t.Helper()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	request := desktopMutationRequestForAuthorityAt(t, authority, operation, now)
	return plan, authority, request
}

func desktopMutationRequestForAuthority(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	operation runtimeport.DesktopMutationOperation,
) runtimeport.DesktopMutationRequest {
	t.Helper()
	return desktopMutationRequestForAuthorityAt(
		t, authority, operation, time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
	)
}

func desktopMutationRequestForAuthorityAt(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	operation runtimeport.DesktopMutationOperation,
	now time.Time,
) runtimeport.DesktopMutationRequest {
	t.Helper()
	artifact := runtimeinstall.Hash{}
	if operation == runtimeport.DesktopMutationInstallRuntime || operation == runtimeport.DesktopMutationRemoveRuntime {
		artifact = authority.ArtifactSHA256()
	}
	request, err := runtimeport.NewDesktopMutationRequest(
		"desktop-runtime-install", 1, operation, authority,
		runtimeinstall.Sum([]byte("desktop-consent")), artifact, runtimeport.Nonce{1, 2, 3},
		now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustDecodeDesktopMutationRequest(t testing.TB, raw []byte) DecodedDesktopMutationRequest {
	t.Helper()
	decoded, err := DecodeCanonicalDesktopMutationRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

type desktopMutationEncoderStub struct {
	raw   []byte
	err   error
	calls int
}

func (s *desktopMutationEncoderStub) EncodeDesktopMutationRequest(
	_ context.Context,
	request runtimeport.DesktopMutationRequest,
) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if len(s.raw) == 0 {
		return request.CanonicalBytes(), nil
	}
	return append([]byte(nil), s.raw...), nil
}
