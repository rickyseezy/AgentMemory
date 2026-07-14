package installplanapp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestRuntimePlanAuthorityRecordRoundTripsAndDefensivelyCopies(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.ResolveRuntimePlan(t.Context(), plan.Digest(), plan.OperationID()); err != nil {
		t.Fatal(err)
	}
	authority := fixture.runtimePlans.authority
	record := authority.Record()
	restored, err := RestoreRuntimePlanAuthority(record)
	if err != nil || !restored.Equal(authority) || restored.BindingDigest().IsZero() {
		t.Fatalf("restored authority = %+v/%v", restored, err)
	}
	if restored.DiscoveryEvidenceDigest().IsZero() {
		t.Fatal("restored authority lost discovery evidence")
	}
	record.CanonicalPlan[0] ^= 0xff
	if bytes.Equal(record.CanonicalPlan, authority.Plan().CanonicalBytes()) {
		t.Fatal("authority record exposed mutable plan bytes")
	}
}

func TestRuntimePlanAuthorityRejectsEveryTamperedBinding(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.ResolveRuntimePlan(t.Context(), plan.Digest(), plan.OperationID()); err != nil {
		t.Fatal(err)
	}
	base := fixture.runtimePlans.authority.Record()
	if _, err := NewRuntimePlanAuthority(
		fixture.runtimePlans.authority.OperationID(), fixture.runtimePlans.authority.ParentPlanDigest(),
		fixture.runtimePlans.authority.Plan(), install.DigestBytes([]byte("host")),
		install.DigestBytes([]byte("discovery")), install.DigestBytes([]byte("foreign catalog")),
	); !errors.Is(err, ErrRuntimePlanIntegrity) {
		t.Fatalf("foreign signed catalog authority error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*RuntimePlanAuthorityRecord)
	}{
		{name: "schema", mutate: func(record *RuntimePlanAuthorityRecord) { record.SchemaVersion++ }},
		{name: "operation", mutate: func(record *RuntimePlanAuthorityRecord) { record.OperationID = "foreign" }},
		{name: "parent", mutate: func(record *RuntimePlanAuthorityRecord) {
			record.ParentPlanDigest = install.DigestBytes([]byte("foreign")).String()
		}},
		{name: "plan", mutate: func(record *RuntimePlanAuthorityRecord) { record.CanonicalPlan = []byte(`{"schema_version":1}`) }},
		{name: "host", mutate: func(record *RuntimePlanAuthorityRecord) {
			record.HostEvidenceDigest = install.DigestBytes([]byte("foreign")).String()
		}},
		{name: "discovery", mutate: func(record *RuntimePlanAuthorityRecord) {
			record.DiscoveryEvidenceDigest = install.DigestBytes([]byte("foreign")).String()
		}},
		{name: "catalog", mutate: func(record *RuntimePlanAuthorityRecord) {
			record.SignedCatalogEvidenceDigest = install.DigestBytes([]byte("foreign")).String()
		}},
		{name: "binding", mutate: func(record *RuntimePlanAuthorityRecord) {
			record.BindingDigest = install.DigestBytes([]byte("foreign")).String()
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := base
			record.CanonicalPlan = append([]byte(nil), base.CanonicalPlan...)
			test.mutate(&record)
			if _, restoreError := RestoreRuntimePlanAuthority(record); !errors.Is(restoreError, ErrRuntimePlanIntegrity) {
				t.Fatalf("RestoreRuntimePlanAuthority() error = %v", restoreError)
			}
		})
	}
}
