package runtimeprovision

import (
	"context"
	"errors"
	"slices"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006ManagedStateObserverProjectsOnlyOperationEvidenceInDeterministicOrder(t *testing.T) {
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
			events := make([]string, 0, 4)
			observer, err := NewNativePrivilegeManagedStateObserver(PrivilegeManagedStateDependencies{
				Repository: &privilegeRepositoryStateProbeStub{events: &events, matches: true},
				Packages:   &privilegePackageStateProbeEventsStub{events: &events, matches: true},
				Subordinates: &privilegeSubIDStateProbeStub{
					events: &events, uidStart: 100000, gidStart: 200000,
					count: authority.SubordinateIDCount(), digest: runtimeinstall.Sum([]byte("subids")),
				},
				Service: &privilegeUserServiceStateProbeStub{
					events: &events, unit: authority.ServiceUnitDigest(), linger: true, enabled: true, active: true,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := privilegeOperationRequest(t, baseRequest, operation)
			observation, err := observer.ObservePrivilegeManagedState(t.Context(), request)
			wanted := map[runtimeport.PrivilegeOperation][]string{
				runtimeport.PrivilegeConfigureRepository:     {"repository"},
				runtimeport.PrivilegeInstallPackages:         {"repository", "packages"},
				runtimeport.PrivilegeConfigureSubordinateIDs: {"subordinates"},
				runtimeport.PrivilegeEnableUserService:       {"service"},
				runtimeport.PrivilegeVerifyManagedState:      {"repository", "packages", "subordinates", "service"},
			}[operation]
			if err != nil || !slices.Equal(events, wanted) {
				t.Fatalf("observation=%+v events=%v want=%v error=%v", observation, events, wanted, err)
			}
		})
	}
}

func TestPF006ManagedStateObserverRejectsMissingOrFailedIndependentState(t *testing.T) {
	t.Parallel()
	_, _, baseRequest, _ := privilegeCodecFixture(t)
	dependencies := PrivilegeManagedStateDependencies{
		Repository:   &privilegeRepositoryStateProbeStub{matches: false},
		Packages:     &privilegePackageStateProbeEventsStub{matches: true},
		Subordinates: &privilegeSubIDStateProbeStub{},
		Service:      &privilegeUserServiceStateProbeStub{},
	}
	observer, err := NewNativePrivilegeManagedStateObserver(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeConfigureRepository)
	if observation, callError := observer.ObservePrivilegeManagedState(t.Context(), request); !errors.Is(callError, runtimeport.ErrPrivilegeIntegrity) || !observation.RepositoryDigest.IsZero() {
		t.Fatalf("observation=%+v error=%v", observation, callError)
	}
	if observer, err := NewNativePrivilegeManagedStateObserver(PrivilegeManagedStateDependencies{}); observer != nil || err == nil {
		t.Fatal("missing state observers accepted")
	}
}

type privilegeRepositoryStateProbeStub struct {
	events  *[]string
	matches bool
	err     error
}

func (s *privilegeRepositoryStateProbeStub) PrivilegeRepositoryStateMatches(
	context.Context,
	runtimeport.LinuxAuthority,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "repository")
	}
	return s.matches, s.err
}

type privilegePackageStateProbeEventsStub struct {
	events  *[]string
	matches bool
	err     error
}

func (s *privilegePackageStateProbeEventsStub) PrivilegePackageStateMatches(
	context.Context,
	runtimeport.LinuxAuthority,
) (bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "packages")
	}
	return s.matches, s.err
}

type privilegeSubIDStateProbeStub struct {
	events             *[]string
	uidStart, gidStart uint32
	count              uint32
	digest             runtimeinstall.Hash
	err                error
}

func (s *privilegeSubIDStateProbeStub) ObservePrivilegeSubordinateIDState(
	context.Context,
	runtimeport.LinuxAuthority,
) (uint32, uint32, uint32, runtimeinstall.Hash, error) {
	if s.events != nil {
		*s.events = append(*s.events, "subordinates")
	}
	return s.uidStart, s.gidStart, s.count, s.digest, s.err
}

type privilegeUserServiceStateProbeStub struct {
	events                  *[]string
	unit                    runtimeinstall.Hash
	linger, enabled, active bool
	err                     error
}

func (s *privilegeUserServiceStateProbeStub) ObservePrivilegeUserServiceState(
	context.Context,
	runtimeport.LinuxAuthority,
) (runtimeinstall.Hash, bool, bool, bool, error) {
	if s.events != nil {
		*s.events = append(*s.events, "service")
	}
	return s.unit, s.linger, s.enabled, s.active, s.err
}
