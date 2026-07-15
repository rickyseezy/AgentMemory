package launcher

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativeLinuxHelperAuthoritySelectsExactVerifiedReleaseResource(t *testing.T) {
	t.Parallel()
	manifest := releaseinventory.DigestBytes([]byte("signed release manifest"))
	verifier := &nativeLinuxHelperReleaseStub{}
	resources := []releaseinventory.Resource{
		nativeDesktopHelperResource(t, "darwin", "arm64"),
		nativeDesktopHelperResource(t, "linux", "amd64"),
		nativeDesktopHelperResource(t, "linux", "arm64"),
	}
	resolver, err := newNativeLinuxHelperAuthorityResolver(
		verifier, releaseinventory.SignedManifest{}, manifest, resources,
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	helper, err := resolver.ResolveLinuxHelperAuthority(t.Context(), authority)
	if err != nil || !helper.ValidFor(authority) || helper.ResourceID() != "runtime-helper-linux-amd64" ||
		helper.CanonicalPath() != "/usr/libexec/agentmemory/agentmemory-runtime-helper" ||
		helper.SHA256() != runtimeinstall.Sum([]byte("helper-linux")) ||
		helper.ReleaseManifestDigest() != runtimeinstall.Hash(manifest) || verifier.calls != 1 {
		t.Fatalf("helper=%+v error=%v calls=%d", helper, err, verifier.calls)
	}
	if resource := helper.Resource(); resource.ID() != helper.ResourceID() ||
		resource.Digest() != releaseinventory.Digest(helper.SHA256()) {
		t.Fatalf("resource=%+v", resource)
	}
}

func TestPF006NativeLinuxHelperAuthorityFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	manifest := releaseinventory.DigestBytes([]byte("signed release manifest"))
	linux := nativeDesktopHelperResource(t, "linux", "amd64")
	verifier := &nativeLinuxHelperReleaseStub{}
	for name, input := range map[string]struct {
		verifier  nativeLinuxHelperReleaseVerifier
		manifest  releaseinventory.Digest
		resources []releaseinventory.Resource
	}{
		"nil verifier":  {manifest: manifest, resources: []releaseinventory.Resource{linux}},
		"zero manifest": {verifier: verifier, resources: []releaseinventory.Resource{linux}},
		"no linux": {verifier: verifier, manifest: manifest,
			resources: []releaseinventory.Resource{nativeDesktopHelperResource(t, "darwin", "arm64")}},
	} {
		resolver, constructError := newNativeLinuxHelperAuthorityResolver(
			input.verifier, releaseinventory.SignedManifest{}, input.manifest, input.resources,
		)
		if resolver != nil || constructError == nil {
			t.Fatalf("%s resolver=%+v error=%v", name, resolver, constructError)
		}
	}
	resolver, err := newNativeLinuxHelperAuthorityResolver(
		verifier, releaseinventory.SignedManifest{}, manifest, []releaseinventory.Resource{linux, linux},
	)
	if err != nil {
		t.Fatalf("duplicates are rejected at selection: %v", err)
	}
	if _, err := resolver.ResolveLinuxHelperAuthority(
		t.Context(), launcherLinuxAuthority(t, runtimeport.PackageManagerAPT),
	); err == nil {
		t.Fatal("duplicate helper accepted")
	}

	resolver, err = newNativeLinuxHelperAuthorityResolver(
		verifier, releaseinventory.SignedManifest{}, manifest, []releaseinventory.Resource{linux},
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier.err = errors.New("private release failure")
	if _, err := resolver.ResolveLinuxHelperAuthority(
		t.Context(), launcherLinuxAuthority(t, runtimeport.PackageManagerAPT),
	); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("release failure error=%v", err)
	}
	verifier.err = nil
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.ResolveLinuxHelperAuthority(
		cancelled, launcherLinuxAuthority(t, runtimeport.PackageManagerAPT),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestPF006NativeLinuxPrivilegeCodecCarriesExactReverifiedReleaseCatalogAndPlan(t *testing.T) {
	t.Parallel()
	plan, authority := launcherLinuxPrivilegePlan(t)
	releaseRaw := []byte(`{"fixture":"signed-release"}`)
	catalogRaw := []byte(`{"fixture":"signed-runtime-catalog"}`)
	verified := launcherLinuxVerifiedExecution(t, plan, catalogRaw)
	resolver, err := newNativeLinuxHelperAuthorityResolver(
		&nativeLinuxHelperReleaseStub{}, verified.request.SignedRelease,
		releaseinventory.DigestBytes([]byte("signed release manifest")),
		[]releaseinventory.Resource{nativeDesktopHelperResource(t, "linux", "amd64")},
	)
	if err != nil {
		t.Fatal(err)
	}
	codec, helper, err := buildNativeLinuxPrivilegeCodecWithEncoders(
		t.Context(), verified, authority, resolver,
		func(releaseinventory.SignedManifest) ([]byte, error) { return append([]byte(nil), releaseRaw...), nil },
		func(runtimecatalog.SignedManifest) ([]byte, error) { return append([]byte(nil), catalogRaw...), nil },
	)
	if err != nil || codec == nil || !helper.ValidFor(authority) {
		t.Fatalf("codec=%+v helper=%+v error=%v", codec, helper, err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expected, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeInstallPackages)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "runtime-install", Attempt: 1, Operation: runtimeport.PrivilegeInstallPackages,
		Authority: authority, Nonce: runtimeport.Nonce{1}, IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodePrivilegeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := runtimeprovision.DecodeCanonicalPrivilegeRequest(raw)
	if err != nil || !bytes.Equal(decoded.SignedRelease(), releaseRaw) ||
		!bytes.Equal(decoded.SignedRuntimeCatalog(), catalogRaw) ||
		!bytes.Equal(decoded.CanonicalPlan(), plan.CanonicalBytes()) ||
		decoded.HelperResourceID() != helper.ResourceID() ||
		decoded.RuntimeCatalogResourceID() != verified.request.RuntimeCatalogID {
		t.Fatalf("decoded envelope mismatch: decoded=%+v error=%v", decoded, err)
	}
}

func TestPF006NativeLinuxPrivilegeCodecRejectsCatalogAndHelperSubstitution(t *testing.T) {
	t.Parallel()
	plan, authority := launcherLinuxPrivilegePlan(t)
	catalogRaw := []byte(`{"fixture":"signed-runtime-catalog"}`)
	valid := launcherLinuxVerifiedExecution(t, plan, catalogRaw)
	validResolver, err := newNativeLinuxHelperAuthorityResolver(
		&nativeLinuxHelperReleaseStub{}, valid.request.SignedRelease,
		releaseinventory.DigestBytes([]byte("signed release manifest")),
		[]releaseinventory.Resource{nativeDesktopHelperResource(t, "linux", "amd64")},
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseEncoder := func(releaseinventory.SignedManifest) ([]byte, error) { return []byte(`{}`), nil }
	catalogEncoder := func(runtimecatalog.SignedManifest) ([]byte, error) { return append([]byte(nil), catalogRaw...), nil }
	for name, test := range map[string]struct {
		verified  nativeVerifiedRuntimeExecution
		authority runtimeport.LinuxAuthority
		resolver  *nativeLinuxHelperAuthorityResolver
		catalog   nativeRuntimeCatalogEncoder
	}{
		"catalog bytes": {verified: valid, authority: authority, resolver: validResolver,
			catalog: func(runtimecatalog.SignedManifest) ([]byte, error) { return []byte(`{"foreign":true}`), nil }},
		"authority plan": {verified: valid, authority: runtimeport.LinuxAuthority{}, resolver: validResolver, catalog: catalogEncoder},
		"helper missing": {verified: valid, authority: authority, resolver: &nativeLinuxHelperAuthorityResolver{}, catalog: catalogEncoder},
	} {
		codec, helper, buildError := buildNativeLinuxPrivilegeCodecWithEncoders(
			t.Context(), test.verified, test.authority, test.resolver, releaseEncoder, test.catalog,
		)
		if codec != nil || helper.ResourceID() != "" || buildError == nil {
			t.Fatalf("%s codec=%+v helper=%+v error=%v", name, codec, helper, buildError)
		}
	}
}

func launcherLinuxPrivilegePlan(t *testing.T) (runtimeinstall.Plan, runtimeport.LinuxAuthority) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	if !authority.ValidFor(plan) {
		t.Fatal("launcher Linux authority fixture does not match its plan")
	}
	return plan, authority
}

func launcherLinuxVerifiedExecution(
	t testing.TB,
	plan runtimeinstall.Plan,
	catalogRaw []byte,
) nativeVerifiedRuntimeExecution {
	t.Helper()
	request := nativeRuntimeEvidenceRequest(t)
	resource := nativeRuntimeCatalogResource(t, catalogRaw)
	outer, err := install.ParseDigest(resource.Digest().Hex())
	if err != nil {
		t.Fatal(err)
	}
	inner, err := install.ParseDigest(plan.CatalogDigest().String())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := installplanapp.NewRuntimePlanAuthority(
		request.OperationID, request.ParentPlanDigest, plan, request.HostEvidenceDigest,
		install.DigestBytes([]byte("discovery")), outer, inner,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.RuntimeCatalogID = resource.ID()
	request.RuntimeCatalogDigest = outer
	request.RuntimeCatalogResource = resource
	return nativeVerifiedRuntimeExecution{authority: authority, request: request}
}

type nativeLinuxHelperReleaseStub struct {
	calls int
	err   error
}

func (s *nativeLinuxHelperReleaseStub) VerifyReleaseResource(
	context.Context,
	releaseinventory.SignedManifest,
	releaseinventory.Resource,
) error {
	s.calls++
	return s.err
}
