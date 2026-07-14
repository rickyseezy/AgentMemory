package firststart

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001DistributionTemplateCatalogFailsClosedAndSanitizesBoundaries(t *testing.T) {
	t.Parallel()
	var typedNil *distributionCatalogStub
	if catalog, err := NewDistributionTemplateCatalog(typedNil); catalog != nil ||
		!errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("typed nil catalog=%v error=%v", catalog, err)
	}
	stub := &distributionCatalogStub{}
	catalog, err := NewDistributionTemplateCatalog(stub)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate absent-context security boundary.
	if _, err := catalog.Current(nil); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	var absent *DistributionTemplateCatalog
	if _, err := absent.Current(t.Context()); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil catalog error=%v", err)
	}
	if _, err := catalog.Exact(t.Context(), releaseinventory.Digest{}); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("zero digest error=%v", err)
	}
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "integrity", err: releaseverify.ErrBootstrapCatalogIntegrity, want: firststartapp.ErrIntegrity},
		{name: "unavailable", err: releaseverify.ErrBootstrapCatalogUnavailable, want: firststartapp.ErrUnavailable},
		{name: "private", err: errors.New("private source"), want: firststartapp.ErrUnavailable},
		{name: "cancelled", err: context.Canceled, want: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub.err = test.err
			if _, err := catalog.Current(t.Context()); !errors.Is(err, test.want) ||
				(err != nil && err.Error() == "private source") {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
	stub.err = nil
	if _, err := catalog.Current(t.Context()); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("zero verified template error=%v", err)
	}
	if nilDistributionCatalog(1) || !nilDistributionCatalog(nil) {
		t.Fatal("distribution catalog nil classifier is inconsistent")
	}
}

type distributionCatalogStub struct{ err error }

func (s *distributionCatalogStub) Current(context.Context) (releaseverify.VerifiedBootstrapTemplate, error) {
	return releaseverify.VerifiedBootstrapTemplate{}, s.err
}

func (s *distributionCatalogStub) Exact(
	context.Context,
	releaseinventory.Digest,
) (releaseverify.VerifiedBootstrapTemplate, error) {
	return releaseverify.VerifiedBootstrapTemplate{}, s.err
}
