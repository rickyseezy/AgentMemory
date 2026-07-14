package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ReleasePhaseAdvancesOnlyForExactVerifiedRelease(t *testing.T) {
	t.Parallel()

	request, plan, query, verifier := releasePhaseFixture(t)
	phase, err := NewReleaseVerificationPhase(query, verifier)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.VerifyRelease(context.Background(), request)
	if err != nil {
		t.Fatalf("VerifyRelease() error = %v", err)
	}
	if output.Outcome() != installapp.PhaseOutcomeCompleted ||
		!output.InputDigest().Equal(install.DigestBytes(request.CanonicalPlan())) ||
		!output.OutputDigest().Equal(plan.ManifestDigest) ||
		!output.VerifiedArtifactDigest().Equal(plan.ManifestDigest) || verifier.calls != 1 {
		t.Fatalf("VerifyRelease() = %+v, calls=%d", output, verifier.calls)
	}
}

func TestPF001ReleasePhaseRejectsCrossBindingAndIncompleteVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*ReleaseVerificationPlan, *releasePlanQuery, *releaseVerifier)
	}{
		{name: "plan unavailable", configure: func(_ *ReleaseVerificationPlan, query *releasePlanQuery, _ *releaseVerifier) {
			query.err = errors.New("private plan path")
		}},
		{name: "parent digest mismatch", configure: func(plan *ReleaseVerificationPlan, _ *releasePlanQuery, _ *releaseVerifier) {
			plan.PlanDigest, _ = install.BindPlan([]byte("another plan"))
		}},
		{name: "missing release", configure: func(plan *ReleaseVerificationPlan, _ *releasePlanQuery, _ *releaseVerifier) {
			plan.ReleaseID = ""
		}},
		{name: "missing digest", configure: func(plan *ReleaseVerificationPlan, _ *releasePlanQuery, _ *releaseVerifier) {
			plan.ManifestDigest = install.Digest{}
		}},
		{name: "missing sequence", configure: func(plan *ReleaseVerificationPlan, _ *releasePlanQuery, _ *releaseVerifier) {
			plan.ReleaseSequence = 0
		}},
		{name: "missing ownership", configure: func(plan *ReleaseVerificationPlan, _ *releasePlanQuery, _ *releaseVerifier) {
			plan.RuntimeOwnership = install.RuntimeOwnershipUndetermined
		}},
		{name: "verified identity mismatch", configure: func(_ *ReleaseVerificationPlan, _ *releasePlanQuery, verifier *releaseVerifier) {
			verifier.result.ReleaseID = "substituted-release"
		}},
		{name: "verified digest mismatch", configure: func(_ *ReleaseVerificationPlan, _ *releasePlanQuery, verifier *releaseVerifier) {
			verifier.result.ManifestDigest = install.DigestBytes([]byte("substituted"))
		}},
		{name: "verified sequence mismatch", configure: func(_ *ReleaseVerificationPlan, _ *releasePlanQuery, verifier *releaseVerifier) {
			verifier.result.ReleaseSequence++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, plan, query, verifier := releasePhaseFixture(t)
			test.configure(&plan, query, verifier)
			query.plan = plan
			phase, err := NewReleaseVerificationPhase(query, verifier)
			if err != nil {
				t.Fatal(err)
			}
			_, err = phase.VerifyRelease(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Error() != string(typed.Code()) || containsSensitive(typed.Error()) {
				t.Fatalf("VerifyRelease() error = %#v", err)
			}
		})
	}
}

func TestPF001ReleasePhaseMapsClosedVerifierFailuresWithoutLeakingDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   releaseverify.ErrorCode
		want   installapp.PhaseOutcome
		action string
	}{
		{name: "unsupported", code: releaseverify.ErrorCodeUnsupportedHost, want: installapp.PhaseOutcomeUnsupportedHost, action: "installation.select_supported_host"},
		{name: "integrity", code: releaseverify.ErrorCodeIntegrityViolation, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.obtain_verified_release"},
		{name: "conflict", code: releaseverify.ErrorCodeConflict, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.obtain_verified_release"},
		{name: "schema", code: releaseverify.ErrorCodeSchemaUnsupported, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.obtain_verified_release"},
		{name: "forbidden", code: releaseverify.ErrorCodeForbidden, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.obtain_verified_release"},
		{name: "dependency", code: releaseverify.ErrorCodeDependencyUnavailable, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_release_verification"},
		{name: "deadline", code: releaseverify.ErrorCodeDeadlineExceeded, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.retry_release_verification"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, _, query, verifier := releasePhaseFixture(t)
			verifier.err = codedReleaseError{code: test.code}
			phase, _ := NewReleaseVerificationPhase(query, verifier)
			output, err := phase.VerifyRelease(context.Background(), request)
			if err != nil || output.Outcome() != test.want || output.NextSafeAction() != test.action {
				t.Fatalf("VerifyRelease() = %+v, %v", output, err)
			}
		})
	}

	request, _, query, verifier := releasePhaseFixture(t)
	verifier.err = errors.New("secret verification detail")
	phase, _ := NewReleaseVerificationPhase(query, verifier)
	_, err := phase.VerifyRelease(context.Background(), request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != ErrorCodeReleaseUnavailable || containsSensitive(typed.Error()) {
		t.Fatalf("unexpected verifier error = %#v", err)
	}
}

func TestPF001ReleasePhaseRequiresAllCapabilitiesAndValidRequest(t *testing.T) {
	t.Parallel()

	_, _, query, verifier := releasePhaseFixture(t)
	if _, err := NewReleaseVerificationPhase(nil, verifier); err == nil {
		t.Fatal("NewReleaseVerificationPhase() accepted nil plan query")
	}
	if _, err := NewReleaseVerificationPhase(query, nil); err == nil {
		t.Fatal("NewReleaseVerificationPhase() accepted nil verifier")
	}
	var typedNil *releaseVerifier
	if _, err := NewReleaseVerificationPhase(query, typedNil); err == nil {
		t.Fatal("NewReleaseVerificationPhase() accepted typed-nil verifier")
	}
	phase, _ := NewReleaseVerificationPhase(query, verifier)
	if _, err := phase.VerifyRelease(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("VerifyRelease() accepted an invalid request")
	}
}

func TestPF001ReleaseApplicationAdapterRejectsMissingOrUnauthenticatedProjection(t *testing.T) {
	t.Parallel()

	if _, err := NewReleaseApplicationAdapter(nil); err == nil {
		t.Fatal("NewReleaseApplicationAdapter() accepted nil application")
	}
	var typedNil *releaseApplication
	if _, err := NewReleaseApplicationAdapter(typedNil); err == nil {
		t.Fatal("NewReleaseApplicationAdapter() accepted typed-nil application")
	}
	application := &releaseApplication{err: errors.New("private trust failure")}
	adapter, err := NewReleaseApplicationAdapter(application)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.VerifyRelease(context.Background(), releaseinventory.SignedManifest{}); err == nil || err.Error() != "private trust failure" {
		t.Fatalf("VerifyRelease() error = %v", err)
	}
	application.err = nil
	if _, err := adapter.VerifyRelease(context.Background(), releaseinventory.SignedManifest{}); err == nil {
		t.Fatal("VerifyRelease() accepted an empty verified inventory")
	}

	digest := install.DigestBytes([]byte("manifest"))
	verified, err := newVerifiedRelease("release-v1", digest.String(), 7)
	if err != nil || verified.ReleaseID != "release-v1" ||
		!verified.ManifestDigest.Equal(digest) || verified.ReleaseSequence != 7 {
		t.Fatalf("newVerifiedRelease() = %+v, %v", verified, err)
	}
	for _, input := range []struct {
		releaseID string
		digest    string
		sequence  uint64
	}{
		{digest: digest.String(), sequence: 1},
		{releaseID: "release-v1", digest: "invalid", sequence: 1},
		{releaseID: "release-v1", digest: digest.String()},
	} {
		if _, err := newVerifiedRelease(input.releaseID, input.digest, input.sequence); err == nil {
			t.Fatalf("newVerifiedRelease(%+v) accepted invalid projection", input)
		}
	}
}

func releasePhaseFixture(
	t *testing.T,
) (installapp.PhaseRequest, ReleaseVerificationPlan, *releasePlanQuery, *releaseVerifier) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	planDigest, _ := install.BindPlan([]byte("canonical plan"))
	request, err := installapp.NewPhaseRequestForIntegration(operationID, planDigest, 1, []byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.DigestBytes([]byte("signed release manifest"))
	plan := ReleaseVerificationPlan{
		PlanDigest: planDigest, ReleaseID: "release-v1", ManifestDigest: manifest,
		ReleaseSequence: 17, RuntimeOwnership: install.RuntimeOwnershipReusedExternal,
	}
	query := &releasePlanQuery{plan: plan}
	verifier := &releaseVerifier{result: VerifiedRelease{
		ReleaseID: plan.ReleaseID, ManifestDigest: manifest, ReleaseSequence: plan.ReleaseSequence,
	}}
	return request, plan, query, verifier
}

type releasePlanQuery struct {
	plan ReleaseVerificationPlan
	err  error
}

func (q *releasePlanQuery) ResolveReleasePlan(context.Context, install.PlanDigest) (ReleaseVerificationPlan, error) {
	return q.plan, q.err
}

type releaseVerifier struct {
	result VerifiedRelease
	err    error
	calls  int
}

func (v *releaseVerifier) VerifyRelease(context.Context, releaseinventory.SignedManifest) (VerifiedRelease, error) {
	v.calls++
	return v.result, v.err
}

type codedReleaseError struct{ code releaseverify.ErrorCode }

func (e codedReleaseError) Error() string                 { return "sensitive release failure" }
func (e codedReleaseError) Code() releaseverify.ErrorCode { return e.code }

type releaseApplication struct{ err error }

func (a *releaseApplication) Verify(
	context.Context,
	releaseinventory.SignedManifest,
) (releaseverify.VerifiedInventory, error) {
	return releaseverify.VerifiedInventory{}, a.err
}
