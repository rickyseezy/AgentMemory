package releaseverify

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001VerifiedDistributionCatalogRejectsPartialAndInvalidRetainedAuthority(t *testing.T) {
	t.Parallel()
	source := &distributionSourceStub{raw: []byte(`not-json`)}
	verifier := &distributionVerifierStub{}
	resolver := &distributionResolverStub{}
	var typedSource *distributionSourceStub
	var typedVerifier *distributionVerifierStub
	var typedResolver *distributionResolverStub
	for _, test := range []struct {
		name     string
		source   DistributionEnvelopeSource
		verifier distributionVerifier
		resolver bootstrapTemplateResolver
	}{
		{name: "missing source", verifier: verifier, resolver: resolver},
		{name: "typed source", source: typedSource, verifier: verifier, resolver: resolver},
		{name: "missing verifier", source: source, resolver: resolver},
		{name: "typed verifier", source: source, verifier: typedVerifier, resolver: resolver},
		{name: "missing resolver", source: source, verifier: verifier},
		{name: "typed resolver", source: source, verifier: verifier, resolver: typedResolver},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewVerifiedDistributionCatalog(test.source, test.verifier, test.resolver)
			if catalog != nil || !errors.Is(err, ErrBootstrapCatalogIntegrity) {
				t.Fatalf("catalog=%v error=%v", catalog, err)
			}
		})
	}
	catalog, err := NewVerifiedDistributionCatalog(source, verifier, resolver)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate absent-context security boundary.
	if _, err := catalog.Current(nil); !errors.Is(err, ErrBootstrapCatalogIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	var absent *VerifiedDistributionCatalog
	if _, err := absent.Current(t.Context()); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
		t.Fatalf("nil catalog error=%v", err)
	}
	if _, err := catalog.Exact(t.Context(), releaseinventory.Digest{}); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
		t.Fatalf("zero exact digest error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := catalog.Current(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if _, err := catalog.Current(t.Context()); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
		t.Fatalf("invalid envelope error=%v", err)
	}
	if nilDistributionCapability(1) || !nilDistributionCapability(nil) {
		t.Fatal("distribution capability nil classifier is inconsistent")
	}
}

func TestPF001VerifiedDistributionCatalogSanitizesSourceAndVerificationFailures(t *testing.T) {
	t.Parallel()
	validEnvelope, err := releaseinventory.EncodeSignedManifestV1(signedReleaseFixture(t, fixtureOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name         string
		sourceError  error
		verifyError  error
		resolveError error
		want         error
	}{
		{name: "private source", sourceError: errors.New("private path"), want: ErrBootstrapCatalogUnavailable},
		{name: "source cancellation", sourceError: context.Canceled, want: context.Canceled},
		{name: "verification integrity", verifyError: integrity(FailureReasonDigestMismatch), want: ErrBootstrapCatalogIntegrity},
		{name: "verification dependency", verifyError: verificationError(ErrorCodeDependencyUnavailable, FailureReasonDependencyUnavailable, true, "safe"), want: ErrBootstrapCatalogUnavailable},
		{name: "verification deadline", verifyError: verificationError(ErrorCodeDeadlineExceeded, FailureReasonDeadline, true, "safe"), want: ErrBootstrapCatalogUnavailable},
		{name: "unknown verification", verifyError: errors.New("private verifier"), want: ErrBootstrapCatalogUnavailable},
		{name: "resolver integrity", resolveError: ErrBootstrapCatalogIntegrity, want: ErrBootstrapCatalogIntegrity},
		{name: "resolver private", resolveError: errors.New("private resolver"), want: ErrBootstrapCatalogUnavailable},
		{name: "resolver deadline", resolveError: context.DeadlineExceeded, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &distributionSourceStub{raw: validEnvelope, err: test.sourceError}
			verifier := &distributionVerifierStub{err: test.verifyError}
			resolver := &distributionResolverStub{err: test.resolveError}
			catalog, err := NewVerifiedDistributionCatalog(source, verifier, resolver)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := catalog.Current(t.Context()); !errors.Is(err, test.want) ||
				stringsContainPrivate(err) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func stringsContainPrivate(err error) bool {
	return err != nil && (err.Error() == "private path" || err.Error() == "private verifier" || err.Error() == "private resolver")
}

type distributionSourceStub struct {
	raw []byte
	err error
}

func (s *distributionSourceStub) ReadDistributionEnvelope(context.Context) ([]byte, error) {
	return append([]byte(nil), s.raw...), s.err
}

type distributionVerifierStub struct{ err error }

func (s *distributionVerifierStub) Verify(context.Context, releaseinventory.SignedManifest) (VerifiedInventory, error) {
	return VerifiedInventory{}, s.err
}

type distributionResolverStub struct{ err error }

func (s *distributionResolverStub) Resolve(
	context.Context,
	VerifiedInventory,
	releaseinventory.SignedManifest,
) (VerifiedBootstrapTemplate, error) {
	return VerifiedBootstrapTemplate{}, s.err
}
