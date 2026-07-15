package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF006NativeRuntimeEnsurerRebuildsOnlyAfterDurableReverification(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	execution, err := installplanapp.NewRuntimeExecutionAuthority(request, authority)
	if err != nil {
		t.Fatal(err)
	}
	want := runtimeinstallapp.Result{OperationID: authority.OperationID().String(), Attempt: 1}
	application := &nativeRuntimeApplicationStub{result: want}
	query := &nativeRuntimeExecutionQueryStub{execution: execution}
	verification := &nativeRuntimeExecutionVerificationStub{verified: nativeVerifiedRuntimeExecution{
		authority: authority, runtime: catalog,
	}}
	platform := &nativePlatformRuntimeFactoryStub{application: application}
	ensurer, err := newNativeRuntimeEnsurer(
		authority.ParentPlanDigest(), authority.OperationID(), query, verification, platform,
	)
	if err != nil {
		t.Fatal(err)
	}
	command := runtimeinstallapp.Command{
		OperationID: authority.OperationID().String(), CanonicalPlan: authority.Plan().CanonicalBytes(),
	}
	result, err := ensurer.Ensure(t.Context(), command)
	if err != nil || result != want || query.calls != 1 || verification.calls != 1 ||
		platform.calls != 1 || application.calls != 1 {
		t.Fatalf("result=%+v error=%v calls=%d/%d/%d/%d", result, err,
			query.calls, verification.calls, platform.calls, application.calls)
	}
	cancelled, err := ensurer.Cancel(t.Context(), command)
	if err != nil || cancelled != want || query.calls != 2 || verification.calls != 2 ||
		platform.calls != 2 || application.calls != 2 {
		t.Fatalf("cancelled=%+v error=%v calls=%d/%d/%d/%d", cancelled, err,
			query.calls, verification.calls, platform.calls, application.calls)
	}
}

func TestPF006NativeRuntimeEnsurerRejectsSubstitutionBeforePlatformBuild(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	execution, err := installplanapp.NewRuntimeExecutionAuthority(request, authority)
	if err != nil {
		t.Fatal(err)
	}
	foreignOperation, _ := install.NewOperationID("019f5f9f-0000-7abc-8123-0123456789ab")
	tests := []struct {
		name      string
		operation install.OperationID
		canonical []byte
		query     *nativeRuntimeExecutionQueryStub
		verify    *nativeRuntimeExecutionVerificationStub
		platform  *nativePlatformRuntimeFactoryStub
		wantCalls int
	}{
		{name: "operation", operation: foreignOperation, canonical: authority.Plan().CanonicalBytes(),
			query:  &nativeRuntimeExecutionQueryStub{execution: execution},
			verify: &nativeRuntimeExecutionVerificationStub{}, platform: &nativePlatformRuntimeFactoryStub{}},
		{name: "plan", operation: authority.OperationID(), canonical: append(authority.Plan().CanonicalBytes(), '\n'),
			query:  &nativeRuntimeExecutionQueryStub{execution: execution},
			verify: &nativeRuntimeExecutionVerificationStub{}, platform: &nativePlatformRuntimeFactoryStub{}},
		{name: "query", operation: authority.OperationID(), canonical: authority.Plan().CanonicalBytes(),
			query:  &nativeRuntimeExecutionQueryStub{err: errors.New("private")},
			verify: &nativeRuntimeExecutionVerificationStub{}, platform: &nativePlatformRuntimeFactoryStub{}},
		{name: "verification", operation: authority.OperationID(), canonical: authority.Plan().CanonicalBytes(),
			query:    &nativeRuntimeExecutionQueryStub{execution: execution},
			verify:   &nativeRuntimeExecutionVerificationStub{err: errors.New("private")},
			platform: &nativePlatformRuntimeFactoryStub{}},
		{name: "platform", operation: authority.OperationID(), canonical: authority.Plan().CanonicalBytes(),
			query: &nativeRuntimeExecutionQueryStub{execution: execution},
			verify: &nativeRuntimeExecutionVerificationStub{verified: nativeVerifiedRuntimeExecution{
				authority: authority, runtime: catalog,
			}}, platform: &nativePlatformRuntimeFactoryStub{err: errors.New("private")}, wantCalls: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ensurer, constructError := newNativeRuntimeEnsurer(
				authority.ParentPlanDigest(), authority.OperationID(), test.query, test.verify, test.platform,
			)
			if constructError != nil {
				t.Fatal(constructError)
			}
			result, ensureError := ensurer.Ensure(t.Context(), runtimeinstallapp.Command{
				OperationID: test.operation.String(), CanonicalPlan: test.canonical,
			})
			if !errors.Is(ensureError, errNativeInstallerIntegrity) || result.OperationID != "" ||
				test.platform.calls != test.wantCalls {
				t.Fatalf("result=%+v error=%v platform calls=%d", result, ensureError, test.platform.calls)
			}
		})
	}
}

func TestPF006NativeRuntimeEnsurerRejectsIncompleteComposition(t *testing.T) {
	t.Parallel()
	request, authority, _ := nativeRuntimeExecutionFixture(t)
	execution, err := installplanapp.NewRuntimeExecutionAuthority(request, authority)
	if err != nil {
		t.Fatal(err)
	}
	query := &nativeRuntimeExecutionQueryStub{execution: execution}
	verify := &nativeRuntimeExecutionVerificationStub{}
	platform := &nativePlatformRuntimeFactoryStub{}
	tests := []struct {
		parent    install.PlanDigest
		operation install.OperationID
		query     nativeRuntimeExecutionQuery
		verify    nativeRuntimeExecutionVerification
		platform  nativePlatformRuntimeApplicationFactory
	}{
		{operation: authority.OperationID(), query: query, verify: verify, platform: platform},
		{parent: authority.ParentPlanDigest(), query: query, verify: verify, platform: platform},
		{parent: authority.ParentPlanDigest(), operation: authority.OperationID(), verify: verify, platform: platform},
		{parent: authority.ParentPlanDigest(), operation: authority.OperationID(), query: query, platform: platform},
		{parent: authority.ParentPlanDigest(), operation: authority.OperationID(), query: query, verify: verify},
	}
	for _, test := range tests {
		if ensurer, constructError := newNativeRuntimeEnsurer(
			test.parent, test.operation, test.query, test.verify, test.platform,
		); ensurer != nil || constructError == nil {
			t.Fatalf("incomplete ensurer=%+v error=%v", ensurer, constructError)
		}
	}
}

type nativeRuntimeExecutionQueryStub struct {
	execution installplanapp.RuntimeExecutionAuthority
	err       error
	calls     int
}

func (s *nativeRuntimeExecutionQueryStub) ResolveRuntimeExecutionAuthority(
	context.Context,
	install.PlanDigest,
	install.OperationID,
) (installplanapp.RuntimeExecutionAuthority, error) {
	s.calls++
	return s.execution, s.err
}

type nativeRuntimeExecutionVerificationStub struct {
	verified nativeVerifiedRuntimeExecution
	err      error
	calls    int
}

func (s *nativeRuntimeExecutionVerificationStub) VerifyRuntimeExecution(
	context.Context,
	installplanapp.RuntimeExecutionAuthority,
) (nativeVerifiedRuntimeExecution, error) {
	s.calls++
	return s.verified, s.err
}

type nativePlatformRuntimeFactoryStub struct {
	application installphase.RuntimeEnsurer
	err         error
	calls       int
}

func (s *nativePlatformRuntimeFactoryStub) BuildRuntimeApplication(
	context.Context,
	nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	s.calls++
	return s.application, s.err
}

type nativeRuntimeApplicationStub struct {
	result runtimeinstallapp.Result
	err    error
	calls  int
}

func (s *nativeRuntimeApplicationStub) Ensure(
	context.Context,
	runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	s.calls++
	return s.result, s.err
}

func (s *nativeRuntimeApplicationStub) Cancel(
	context.Context,
	runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	s.calls++
	return s.result, s.err
}
