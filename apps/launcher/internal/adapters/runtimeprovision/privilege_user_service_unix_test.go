//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativePrivilegeUserServiceEnablesLingerAndExactUnitThenReproves(t *testing.T) {
	t.Parallel()
	authority, request := privilegeUserServiceFixture(t, []byte("[Service]\nExecStart=/usr/bin/dockerd-rootless.sh\n"))
	loginctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleLoginCTL),
		results: []privilegeServiceRunResult{
			{result: argvprocess.Result{StandardOutput: []byte("no\n")}}, {},
			{result: argvprocess.Result{StandardOutput: []byte("yes\n")}},
		},
	}
	systemctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleSystemCTL),
		results: []privilegeServiceRunResult{
			{result: argvprocess.Result{ExitCode: 4}, err: errors.New("not found")}, {}, {},
			{result: argvprocess.Result{StandardOutput: []byte(privilegeActiveSystemdState)}},
		},
	}
	manager, err := NewNativePrivilegeUserServiceManager(loginctl, systemctl)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := manager.EnsurePrivilegeUserService(t.Context(), request)
	if err != nil || !changed || loginctl.calls != 3 || systemctl.calls != 4 {
		t.Fatalf("changed=%t loginctl=%d systemctl=%d error=%v", changed, loginctl.calls, systemctl.calls, err)
	}
	if !slices.Equal(loginctl.invocations[1].Arguments(), []string{
		"--no-ask-password", "enable-linger", authorityUIDText(authority),
	}) || !slices.Contains(systemctl.invocations[1].Arguments(), "daemon-reload") ||
		!slices.Contains(systemctl.invocations[2].Arguments(), "--now") {
		t.Fatalf("loginctl=%v systemctl=%v", loginctl.invocations, systemctl.invocations)
	}
}

func TestPF006NativePrivilegeUserServiceIsIdempotentForReprovedActiveState(t *testing.T) {
	t.Parallel()
	authority, request := privilegeUserServiceFixture(t, []byte("unit\n"))
	loginctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleLoginCTL),
		results:   []privilegeServiceRunResult{{result: argvprocess.Result{StandardOutput: []byte("yes\n")}}},
	}
	systemctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleSystemCTL),
		results: []privilegeServiceRunResult{{
			result: argvprocess.Result{StandardOutput: []byte(privilegeActiveSystemdState)},
		}},
	}
	manager, err := NewNativePrivilegeUserServiceManager(loginctl, systemctl)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := manager.EnsurePrivilegeUserService(t.Context(), request)
	if err != nil || changed || loginctl.calls != 1 || systemctl.calls != 1 {
		t.Fatalf("changed=%t loginctl=%d systemctl=%d error=%v", changed, loginctl.calls, systemctl.calls, err)
	}
}

func TestPF001NativePrivilegeUserServiceDisablesManagedUnitWithoutChangingLinger(t *testing.T) {
	t.Parallel()
	authority, baseRequest := privilegeUserServiceFixture(t, []byte("unit\n"))
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeRemoveManagedPackages)
	loginctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleLoginCTL),
		results: []privilegeServiceRunResult{
			{result: argvprocess.Result{StandardOutput: []byte("yes\n")}},
			{result: argvprocess.Result{StandardOutput: []byte("yes\n")}},
		},
	}
	systemctl := &privilegeServiceRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleSystemCTL),
		results: []privilegeServiceRunResult{
			{result: argvprocess.Result{StandardOutput: []byte(privilegeActiveSystemdState)}},
			{},
			{result: argvprocess.Result{StandardOutput: []byte("ActiveState=inactive\nLoadState=loaded\nUnitFileState=disabled\n")}},
		},
	}
	manager, err := NewNativePrivilegeUserServiceManager(loginctl, systemctl)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := manager.DisablePrivilegeUserService(t.Context(), request)
	if err != nil || !changed || loginctl.calls != 2 || systemctl.calls != 3 ||
		!slices.Contains(systemctl.invocations[1].Arguments(), "disable") ||
		!slices.Contains(systemctl.invocations[1].Arguments(), "--now") {
		t.Fatalf("changed=%t loginctl=%d systemctl=%d invocations=%v error=%v", changed, loginctl.calls, systemctl.calls, systemctl.invocations, err)
	}
}

func TestPF006NativePrivilegeUserServiceRejectsUnitAndObservationSubstitution(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		unit    []byte
		linger  string
		systemd string
	}{
		"malformed linger":  {unit: []byte("unit\n"), linger: "true\n", systemd: privilegeActiveSystemdState},
		"malformed systemd": {unit: []byte("unit\n"), linger: "yes\n", systemd: "ActiveState=active\n"},
	} {
		t.Run(name, func(t *testing.T) {
			authority, request := privilegeUserServiceFixture(t, test.unit)
			loginctl := &privilegeServiceRunnerStub{
				authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleLoginCTL),
				results: []privilegeServiceRunResult{{
					result: argvprocess.Result{StandardOutput: []byte(test.linger)},
				}},
			}
			systemctl := &privilegeServiceRunnerStub{
				authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleSystemCTL),
				results: []privilegeServiceRunResult{{
					result: argvprocess.Result{StandardOutput: []byte(test.systemd)},
				}},
			}
			manager, err := NewNativePrivilegeUserServiceManager(loginctl, systemctl)
			if err != nil {
				t.Fatal(err)
			}
			if changed, callError := manager.EnsurePrivilegeUserService(t.Context(), request); changed ||
				!errors.Is(callError, runtimeport.ErrPrivilegeIntegrity) {
				t.Fatalf("changed=%t error=%v", changed, callError)
			}
		})
	}

	authority, request := privilegeUserServiceFixture(t, []byte("unit\n"))
	unitPath := filepath.Join(authority.HomeDirectory(), ".config", "systemd", "user", "docker.service")
	if err := os.Remove(unitPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(authority.HomeDirectory(), "foreign"), unitPath); err != nil {
		t.Fatal(err)
	}
	manager, err := NewNativePrivilegeUserServiceManager(
		&privilegeServiceRunnerStub{authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleLoginCTL)},
		&privilegeServiceRunnerStub{authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleSystemCTL)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if changed, callError := manager.EnsurePrivilegeUserService(t.Context(), request); changed ||
		!errors.Is(callError, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("symlink changed=%t error=%v", changed, callError)
	}
}

const privilegeActiveSystemdState = "ActiveState=active\nLoadState=loaded\nUnitFileState=enabled\n"

func privilegeUserServiceFixture(
	t *testing.T,
	unit []byte,
) (runtimeport.LinuxAuthority, runtimeport.PrivilegeRequest) {
	t.Helper()
	_, baseAuthority, baseRequest, _ := privilegeCodecFixture(t)
	input := baseAuthority.TransportInput()
	uid, gid := privilegeSubIDTestOwner(t)
	if uid == 0 || gid == 0 {
		t.Skip("user-service ownership fixture requires a non-root test account")
	}
	input.InvokingUID, input.InvokingGID = uid, gid
	input.PrincipalID = "linux:uid:" + strconv.FormatUint(uint64(uid), 10)
	input.RuntimeDirectory = "/run/user/" + strconv.FormatUint(uint64(uid), 10)
	input.Endpoint = "unix://" + input.RuntimeDirectory + "/docker.sock"
	input.HomeDirectory = t.TempDir()
	input.ServiceUnitDigest = runtimeinstall.Sum(unit)
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(authority.HomeDirectory(), ".config", "systemd", "user")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, authority.ServiceID())
	if err := os.WriteFile(path, unit, 0o600); err != nil {
		t.Fatal(err)
	}
	inputRequest := baseRequest.TransportInput()
	inputRequest.Authority = authority
	inputRequest.Operation = runtimeport.PrivilegeEnableUserService
	expected, err := runtimeport.ExpectedPrivilegeState(authority, inputRequest.Operation)
	if err != nil {
		t.Fatal(err)
	}
	inputRequest.ExpectedState = expected
	request, err := runtimeport.NewPrivilegeRequest(inputRequest)
	if err != nil {
		t.Fatal(err)
	}
	return authority, request
}

func authorityUIDText(authority runtimeport.LinuxAuthority) string {
	return strings.TrimPrefix(authority.PrincipalID(), "linux:uid:")
}

type privilegeServiceRunResult struct {
	result argvprocess.Result
	err    error
}

type privilegeServiceRunnerStub struct {
	authority   argvprocess.ExecutableAuthority
	results     []privilegeServiceRunResult
	invocations []argvprocess.Invocation
	calls       int
}

func (s *privilegeServiceRunnerStub) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return s.authority
}

func (s *privilegeServiceRunnerStub) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	s.invocations = append(s.invocations, invocation)
	index := s.calls
	s.calls++
	if index >= len(s.results) {
		return argvprocess.Result{}, errors.New("unexpected service invocation")
	}
	return s.results[index].result, s.results[index].err
}

var _ argvprocess.Runner = (*privilegeServiceRunnerStub)(nil)
