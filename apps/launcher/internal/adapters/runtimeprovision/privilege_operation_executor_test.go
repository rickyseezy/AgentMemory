package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006ClosedPrivilegeOperationExecutorDispatchesOnlyExactCapabilityThenReprovesState(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	for _, operation := range []runtimeport.PrivilegeOperation{
		runtimeport.PrivilegeConfigureRepository,
		runtimeport.PrivilegeInstallPackages,
		runtimeport.PrivilegeConfigureSubordinateIDs,
		runtimeport.PrivilegeEnableUserService,
		runtimeport.PrivilegeVerifyManagedState,
	} {
		t.Run(string(operation), func(t *testing.T) {
			request := privilegeOperationRequest(t, baseRequest, operation)
			evidence := privilegeOperationAuthorityEvidence(t, request.Authority())
			events := make([]string, 0, 2)
			repository := &privilegeRepositoryManagerStub{events: &events, changed: true}
			packages := &privilegePackageManagerStub{events: &events, changed: true}
			subordinates := &privilegeSubordinateManagerStub{events: &events, changed: true}
			service := &privilegeServiceManagerStub{events: &events, changed: true}
			observer := &privilegeManagedStateObserverStub{
				events: &events, observation: completePrivilegeManagedObservation(t, authority),
			}
			executor, err := NewClosedPrivilegeOperationExecutor(PrivilegeOperationDependencies{
				Repository: repository, Packages: packages, Subordinates: subordinates,
				Service: service, Observer: observer,
			})
			if err != nil {
				t.Fatal(err)
			}
			transaction := privilegeArtifactTransactionStub{root: "/root/transaction"}
			observation, err := executor.ExecutePrivilegeOperation(t.Context(), request, transaction, evidence)
			expectedMutation := map[runtimeport.PrivilegeOperation]string{
				runtimeport.PrivilegeConfigureRepository:     "repository",
				runtimeport.PrivilegeInstallPackages:         "packages",
				runtimeport.PrivilegeConfigureSubordinateIDs: "subordinates",
				runtimeport.PrivilegeEnableUserService:       "service",
			}[operation]
			expectedEvents := []string{"observe"}
			expectedResult := runtimeport.PrivilegeResultAlreadyApplied
			if expectedMutation != "" {
				expectedEvents = []string{expectedMutation, "observe"}
				expectedResult = runtimeport.PrivilegeResultCompleted
			}
			if err != nil || observation.Result != expectedResult || observation.ObservedState != request.ExpectedState() ||
				len(events) != len(expectedEvents) {
				t.Fatalf("operation=%s observation=%+v events=%v error=%v", operation, observation, events, err)
			}
			for index := range events {
				if events[index] != expectedEvents[index] {
					t.Fatalf("operation=%s events=%v want=%v", operation, events, expectedEvents)
				}
			}
		})
	}
}

func TestPF006ClosedPrivilegeOperationExecutorRejectsMutationOrObservationFailure(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	validObservation := completePrivilegeManagedObservation(t, authority)
	for name, configure := range map[string]func(*PrivilegeOperationDependencies, *runtimeport.PrivilegeRequest){
		"repository mutation": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureRepository)
			input.Repository = &privilegeRepositoryManagerStub{err: errors.New("repository failed")}
		},
		"package mutation": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeInstallPackages)
			input.Packages = &privilegePackageManagerStub{err: errors.New("packages failed")}
		},
		"subordinate mutation": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureSubordinateIDs)
			input.Subordinates = &privilegeSubordinateManagerStub{err: errors.New("subordinates failed")}
		},
		"service mutation": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeEnableUserService)
			input.Service = &privilegeServiceManagerStub{err: errors.New("service failed")}
		},
		"observation failure": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeVerifyManagedState)
			input.Observer = &privilegeManagedStateObserverStub{err: errors.New("observe failed")}
		},
		"state substitution": func(input *PrivilegeOperationDependencies, request *runtimeport.PrivilegeRequest) {
			*request = privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeVerifyManagedState)
			invalid := validObservation
			invalid.PackageStateDigest = runtimeinstall.Sum([]byte("foreign state"))
			input.Observer = &privilegeManagedStateObserverStub{observation: invalid}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := baseRequest
			dependencies := PrivilegeOperationDependencies{
				Repository: &privilegeRepositoryManagerStub{}, Packages: &privilegePackageManagerStub{},
				Subordinates: &privilegeSubordinateManagerStub{}, Service: &privilegeServiceManagerStub{},
				Observer: &privilegeManagedStateObserverStub{observation: validObservation},
			}
			configure(&dependencies, &request)
			executor, err := NewClosedPrivilegeOperationExecutor(dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if observation, executeError := executor.ExecutePrivilegeOperation(
				t.Context(), request, privilegeArtifactTransactionStub{root: "/root/transaction"},
				privilegeOperationAuthorityEvidence(t, request.Authority()),
			); !errors.Is(executeError, runtimeport.ErrPrivilegeIntegrity) || !observation.ObservedState.IsZero() {
				t.Fatalf("observation=%+v error=%v", observation, executeError)
			}
		})
	}
	if executor, err := NewClosedPrivilegeOperationExecutor(PrivilegeOperationDependencies{}); executor != nil || err == nil {
		t.Fatal("missing closed operation dependencies accepted")
	}
}

func privilegeOperationAuthorityEvidence(
	t testing.TB,
	authority runtimeport.LinuxAuthority,
) PrivilegeAuthorityEvidence {
	t.Helper()
	evidence, err := NewPrivilegeAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func privilegeOperationRequest(
	t testing.TB,
	base runtimeport.PrivilegeRequest,
	operation runtimeport.PrivilegeOperation,
) runtimeport.PrivilegeRequest {
	t.Helper()
	expected, err := runtimeport.ExpectedPrivilegeState(base.Authority(), operation)
	if err != nil {
		t.Fatal(err)
	}
	input := base.TransportInput()
	input.Operation = operation
	input.ExpectedState = expected
	request, err := runtimeport.NewPrivilegeRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func completePrivilegeManagedObservation(
	t testing.TB,
	authority runtimeport.LinuxAuthority,
) PrivilegeManagedStateObservation {
	t.Helper()
	packages, err := runtimeport.ExpectedPackageStateDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeport.ExpectedRepositoryStateDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	return PrivilegeManagedStateObservation{
		PackageStateDigest: packages, RepositoryDigest: repository,
		ServiceUnitDigest: authority.ServiceUnitDigest(), ServiceEnabled: true, ServiceActive: true,
		UserLingerEnabled: true, SubordinateIDs: authority.SubordinateIDCount(),
		SubordinateUIDStart: 100000, SubordinateGIDStart: 200000,
		SubordinateStateDigest: runtimeinstall.Sum([]byte("subordinate state")),
	}
}

type privilegeRepositoryManagerStub struct {
	events  *[]string
	changed bool
	err     error
}

func (s *privilegeRepositoryManagerStub) EnsurePrivilegeRepository(
	context.Context,
	runtimeport.PrivilegeRequest,
	PrivilegeArtifactSet,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "repository")
	}
	return s.changed, s.err
}

type privilegePackageManagerStub struct {
	events  *[]string
	changed bool
	err     error
}

func (s *privilegePackageManagerStub) EnsurePrivilegePackages(
	context.Context,
	runtimeport.PrivilegeRequest,
	PrivilegeArtifactSet,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "packages")
	}
	return s.changed, s.err
}

type privilegeSubordinateManagerStub struct {
	events  *[]string
	changed bool
	err     error
}

func (s *privilegeSubordinateManagerStub) EnsurePrivilegeSubordinateIDs(
	context.Context,
	runtimeport.PrivilegeRequest,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "subordinates")
	}
	return s.changed, s.err
}

type privilegeServiceManagerStub struct {
	events  *[]string
	changed bool
	err     error
}

func (s *privilegeServiceManagerStub) EnsurePrivilegeUserService(
	context.Context,
	runtimeport.PrivilegeRequest,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "service")
	}
	return s.changed, s.err
}

type privilegeManagedStateObserverStub struct {
	events      *[]string
	observation PrivilegeManagedStateObservation
	err         error
}

func (s *privilegeManagedStateObserverStub) ObservePrivilegeManagedState(
	context.Context,
	runtimeport.PrivilegeRequest,
) (PrivilegeManagedStateObservation, error) {
	if s.events != nil {
		*s.events = append(*s.events, "observe")
	}
	return s.observation, s.err
}
