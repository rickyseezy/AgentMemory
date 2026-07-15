package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006CanonicalPrivilegeCodecRoundTripsAuthenticatedRequestEnvelope(t *testing.T) {
	t.Parallel()
	plan, authority, request, _ := privilegeCodecFixture(t)
	input := PrivilegeEnvelopeInput{
		SignedRelease:            []byte(`{"fixture":"signed-release"}`),
		SignedRuntimeCatalog:     []byte(`{"fixture":"signed-runtime-catalog"}`),
		CanonicalPlan:            plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "runtime-catalog-linux-amd64",
		HelperResourceID:         "runtime-helper-linux-amd64",
		ArtifactStager:           privilegeCodecArtifactStager(authority),
	}
	codec, err := NewCanonicalPrivilegeTransportCodec(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodePrivilegeRequest(t.Context(), request)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] == '\n' || !json.Valid(raw) {
		t.Fatalf("EncodePrivilegeRequest() bytes=%d error=%v", len(raw), err)
	}
	decoded, err := DecodeCanonicalPrivilegeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := decoded.BindAuthority(authority)
	if err != nil || bound.Digest() != request.Digest() || bound.OperationKey() != request.OperationKey() ||
		decoded.RuntimeCatalogResourceID() != input.RuntimeCatalogResourceID ||
		decoded.HelperResourceID() != input.HelperResourceID ||
		!bytes.Equal(decoded.SignedRelease(), input.SignedRelease) ||
		!bytes.Equal(decoded.SignedRuntimeCatalog(), input.SignedRuntimeCatalog) ||
		!bytes.Equal(decoded.CanonicalPlan(), input.CanonicalPlan) || len(decoded.Artifacts()) != 7 ||
		decoded.Artifacts()[2].ArtifactID() != "docker-ce" ||
		decoded.Artifacts()[2].Path() != "/home/agentmemory/.cache/agentmemory/"+authority.Digest().String()+"/"+
			"docker-ce-"+decoded.Artifacts()[2].SHA256().String()+".deb" {
		t.Fatalf("decoded request mismatch: request=%+v error=%v", bound, err)
	}
	reencoded, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(reencoded, raw) {
		t.Fatalf("CanonicalBytes() mismatch error=%v", err)
	}

	// Constructor and accessors must not retain caller-owned buffers.
	input.SignedRelease[2] ^= 1
	input.SignedRuntimeCatalog[2] ^= 1
	input.CanonicalPlan[2] ^= 1
	copyOfRelease := decoded.SignedRelease()
	copyOfRelease[2] ^= 1
	if bytes.Equal(codec.signedRelease, input.SignedRelease) ||
		bytes.Equal(decoded.SignedRelease(), copyOfRelease) {
		t.Fatal("privilege envelope aliases caller-owned bytes")
	}
}

type privilegeArtifactStagerStub struct {
	bindings []PrivilegeArtifactBinding
	err      error
}

func (s *privilegeArtifactStagerStub) StagePrivilegeArtifacts(
	context.Context,
	runtimeport.LinuxAuthority,
) ([]PrivilegeArtifactBinding, error) {
	return append([]PrivilegeArtifactBinding(nil), s.bindings...), s.err
}

func privilegeCodecArtifactStager(authority runtimeport.LinuxAuthority) *privilegeArtifactStagerStub {
	bindings := make([]PrivilegeArtifactBinding, 0, len(authority.Packages()))
	for _, pkg := range authority.Packages() {
		digest := runtimeinstall.Sum([]byte(pkg.Name()))
		bindings = append(bindings, PrivilegeArtifactBinding{
			artifactID: pkg.Name(),
			path: filepath.Join(
				"/home/agentmemory/.cache/agentmemory", authority.Digest().String(),
				pkg.Name()+"-"+digest.String()+".deb",
			),
			sha256: digest, size: 1024,
		})
	}
	return &privilegeArtifactStagerStub{bindings: bindings}
}

func TestPF006CanonicalPrivilegeCodecRejectsAmbiguityAndSubstitution(t *testing.T) {
	t.Parallel()
	plan, authority, request, _ := privilegeCodecFixture(t)
	valid, err := NewCanonicalPrivilegeTransportCodec(PrivilegeEnvelopeInput{
		SignedRelease:        []byte(`{"fixture":"signed-release"}`),
		SignedRuntimeCatalog: []byte(`{"fixture":"signed-runtime-catalog"}`), CanonicalPlan: plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "runtime-catalog-linux-amd64", HelperResourceID: "runtime-helper-linux-amd64",
		ArtifactStager: privilegeCodecArtifactStager(authority),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := valid.EncodePrivilegeRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"leading whitespace": append([]byte(" "), raw...),
		"unknown field":      bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
		"duplicate field":    bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"request digest": bytes.Replace(
			raw, []byte(request.Digest().String()), []byte(runtimeinstall.Sum([]byte("foreign-request")).String()), 1,
		),
		"expected state": bytes.Replace(
			raw, []byte(request.ExpectedState().String()), []byte(runtimeinstall.Sum([]byte("foreign-state")).String()), 1,
		),
	}
	for name, candidate := range mutations {
		if decoded, decodeError := DecodeCanonicalPrivilegeRequest(candidate); decodeError == nil {
			if _, bindError := decoded.BindAuthority(authority); bindError == nil {
				t.Fatalf("%s mutation accepted", name)
			}
		}
	}
	foreignPlan, _ := runtimeinstall.NewPlanV1(
		mustDifferentCodecHost(t), runtimeinstall.NewAbsentRuntimeDiscovery(), mustDifferentCodecRuntime(t),
	)
	if codec, constructError := NewCanonicalPrivilegeTransportCodec(PrivilegeEnvelopeInput{
		SignedRelease: []byte(`{"fixture":"signed-release"}`), SignedRuntimeCatalog: []byte(`{"fixture":"catalog"}`),
		CanonicalPlan: foreignPlan.CanonicalBytes(), RuntimeCatalogResourceID: "runtime-catalog-linux-amd64",
		HelperResourceID: "runtime-helper-linux-amd64", ArtifactStager: privilegeCodecArtifactStager(authority),
	}); constructError != nil {
		t.Fatal(constructError)
	} else if _, encodeError := codec.EncodePrivilegeRequest(t.Context(), request); encodeError == nil {
		t.Fatal("request was encoded under a substituted plan")
	}
	for name, input := range map[string]PrivilegeEnvelopeInput{
		"empty release": {
			SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
			ArtifactStager: privilegeCodecArtifactStager(authority),
		},
		"noncanonical release": {
			SignedRelease: []byte(`{ "x": 1 }`), SignedRuntimeCatalog: []byte(`{}`),
			CanonicalPlan: plan.CanonicalBytes(), RuntimeCatalogResourceID: "catalog",
			HelperResourceID: "helper", ArtifactStager: privilegeCodecArtifactStager(authority),
		},
		"bad catalog": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`x`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
			ArtifactStager: privilegeCodecArtifactStager(authority),
		},
		"bad plan": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: []byte(`{}`),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
			ArtifactStager: privilegeCodecArtifactStager(authority),
		},
		"unsafe resource": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "../catalog", HelperResourceID: "helper",
			ArtifactStager: privilegeCodecArtifactStager(authority),
		},
		"missing stager": {
			SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
			RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		},
	} {
		if codec, constructError := NewCanonicalPrivilegeTransportCodec(input); codec != nil || constructError == nil {
			t.Fatalf("%s input accepted", name)
		}
	}
}

func TestPF006CanonicalPrivilegeCodecRejectsArtifactHandoffSubstitution(t *testing.T) {
	t.Parallel()
	plan, authority, request, _ := privilegeCodecFixture(t)
	codec, err := NewCanonicalPrivilegeTransportCodec(PrivilegeEnvelopeInput{
		SignedRelease:        []byte(`{"fixture":"signed-release"}`),
		SignedRuntimeCatalog: []byte(`{"fixture":"signed-runtime-catalog"}`),
		CanonicalPlan:        plan.CanonicalBytes(), RuntimeCatalogResourceID: "runtime-catalog-linux-amd64",
		HelperResourceID: "runtime-helper-linux-amd64", ArtifactStager: privilegeCodecArtifactStager(authority),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodePrivilegeRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalPrivilegeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*canonicalPrivilegeEnvelope){
		"missing signed package": func(document *canonicalPrivilegeEnvelope) {
			document.Artifacts = document.Artifacts[1:]
		},
		"duplicate artifact id": func(document *canonicalPrivilegeEnvelope) {
			document.Artifacts[1].ArtifactID = document.Artifacts[0].ArtifactID
		},
		"substituted parent": func(document *canonicalPrivilegeEnvelope) {
			document.Artifacts[0].Path = filepath.Join(
				filepath.Dir(filepath.Dir(document.Artifacts[0].Path)),
				runtimeinstall.Sum([]byte("foreign-authority")).String(),
				filepath.Base(document.Artifacts[0].Path),
			)
		},
		"digest filename mismatch": func(document *canonicalPrivilegeEnvelope) {
			document.Artifacts[0].SHA256 = runtimeinstall.Sum([]byte("foreign-artifact")).String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := copyPrivilegeEnvelope(decoded.document)
			mutate(&document)
			candidate, encodeError := encodeCanonicalPrivilegeEnvelope(document)
			if encodeError != nil {
				t.Fatal(encodeError)
			}
			untrusted, decodeError := DecodeCanonicalPrivilegeRequest(candidate)
			if decodeError == nil {
				if _, bindError := untrusted.BindAuthority(authority); bindError == nil {
					t.Fatal("substituted artifact handoff accepted")
				}
			}
		})
	}
}

func TestPF006CanonicalPrivilegeCodecPropagatesContextAndContainsStagerFailure(t *testing.T) {
	t.Parallel()
	plan, _, request, _ := privilegeCodecFixture(t)
	stagerFailure := errors.New("private staging failed")
	codec, err := NewCanonicalPrivilegeTransportCodec(PrivilegeEnvelopeInput{
		SignedRelease: []byte(`{}`), SignedRuntimeCatalog: []byte(`{}`), CanonicalPlan: plan.CanonicalBytes(),
		RuntimeCatalogResourceID: "catalog", HelperResourceID: "helper",
		ArtifactStager: &privilegeArtifactStagerStub{err: stagerFailure},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, encodeError := codec.EncodePrivilegeRequest(t.Context(), request); !errors.Is(encodeError, ErrProvisionIntegrity) ||
		errors.Is(encodeError, stagerFailure) {
		t.Fatalf("stager error escaped boundary: %v", encodeError)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, encodeError := codec.EncodePrivilegeRequest(cancelled, request); !errors.Is(encodeError, context.Canceled) {
		t.Fatalf("cancelled error=%v", encodeError)
	}
	if _, encodeError := codec.EncodePrivilegeRequest(hostileNilContext(), request); !errors.Is(encodeError, ErrProvisionIntegrity) {
		t.Fatalf("nil context error=%v", encodeError)
	}
	if _, constructError := NewPrivilegeArtifactBinding("bad/id", "/tmp/artifact", runtimeinstall.Sum([]byte("x")), 1); constructError == nil {
		t.Fatal("unsafe public artifact binding accepted")
	}
}

func TestPF006CanonicalPrivilegeReceiptRoundTripsWithoutTrustingSignature(t *testing.T) {
	t.Parallel()
	_, _, _, receipt := privilegeCodecFixture(t)
	raw, err := EncodeCanonicalPrivilegeReceipt(receipt)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] == '\n' {
		t.Fatalf("EncodeCanonicalPrivilegeReceipt() bytes=%d error=%v", len(raw), err)
	}
	decoded, err := DecodeCanonicalPrivilegeReceipt(raw)
	if err != nil || decoded.Digest() != receipt.Digest() ||
		!bytes.Equal(decoded.Signature(), receipt.Signature()) {
		t.Fatalf("DecodeCanonicalPrivilegeReceipt() digest=%s error=%v", decoded.Digest(), err)
	}
	for name, candidate := range map[string][]byte{
		"whitespace": append(raw, ' '),
		"unknown":    bytes.Replace(raw, []byte(`"authority_digest"`), []byte(`"unknown":true,"authority_digest"`), 1),
		"duplicate":  bytes.Replace(raw, []byte(`"result":"completed"`), []byte(`"result":"completed","result":"completed"`), 1),
		"digest":     bytes.Replace(raw, []byte(receipt.Digest().String()), []byte(runtimeinstall.Sum([]byte("foreign")).String()), 1),
	} {
		if value, decodeError := DecodeCanonicalPrivilegeReceipt(candidate); decodeError == nil || !value.Digest().IsZero() {
			t.Fatalf("%s receipt accepted: digest=%s error=%v", name, value.Digest(), decodeError)
		}
	}
}

func privilegeCodecFixture(
	t *testing.T,
) (runtimeinstall.Plan, runtimeport.LinuxAuthority, runtimeport.PrivilegeRequest, runtimeport.PrivilegeReceipt) {
	t.Helper()
	plan, authority := adapterAuthority(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expected, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeInstallPackages)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "runtime-install", Attempt: 1, Operation: runtimeport.PrivilegeInstallPackages,
		Authority: authority, Nonce: runtimeport.Nonce{1, 2, 3}, IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeport.ExpectedRepositoryStateDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := runtimeport.ExpectedPackageStateDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtimeport.NewPrivilegeReceipt(runtimeport.PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(), ExpiresAt: request.ExpiresAt(),
		Result: runtimeport.PrivilegeResultCompleted, ObservedState: request.ExpectedState(),
		PackageStateDigest: packages, RepositoryDigest: repository,
		HelperDigest: runtimeinstall.Sum([]byte("signed-linux-helper")), Signature: bytes.Repeat([]byte{0x42}, 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, authority, request, receipt
}

func mustDifferentCodecHost(t testing.TB) runtimeinstall.HostCapabilities {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		16, 64<<30, 48<<30, 200<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func mustDifferentCodecRuntime(t testing.TB) runtimeinstall.CertifiedRuntime {
	t.Helper()
	runtime, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.2", "stable", 8,
		runtimeinstall.Sum([]byte("foreign-catalog")), linuxTerms(runtimeinstall.Sum([]byte("foreign-terms"))), 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}
