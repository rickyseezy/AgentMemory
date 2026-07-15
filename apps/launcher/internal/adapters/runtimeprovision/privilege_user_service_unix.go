//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const maximumPrivilegeServiceUnitBytes = 1 << 20

// PrivilegeUserServiceStateProbe independently observes the exact unit,
// persistent linger, enablement, and activity state.
type PrivilegeUserServiceStateProbe interface {
	ObservePrivilegeUserServiceState(
		context.Context,
		runtimeport.LinuxAuthority,
	) (runtimeinstall.Hash, bool, bool, bool, error)
}

// NativePrivilegeUserServiceManager controls only docker.service in the
// verified account's local user manager.
type NativePrivilegeUserServiceManager struct {
	loginctl  argvprocess.Runner
	systemctl argvprocess.Runner
}

// NewNativePrivilegeUserServiceManager requires independently signed systemd
// helper roles; neither executable nor account can be selected later.
func NewNativePrivilegeUserServiceManager(
	loginctl argvprocess.Runner,
	systemctl argvprocess.Runner,
) (*NativePrivilegeUserServiceManager, error) {
	if nilArtifactDependency(loginctl) || nilArtifactDependency(systemctl) ||
		!validPrivilegeServiceRunner(loginctl.ExecutableAuthority(), argvprocess.ExecutableRoleLoginCTL) ||
		!validPrivilegeServiceRunner(systemctl.ExecutableAuthority(), argvprocess.ExecutableRoleSystemCTL) {
		return nil, errors.New("signed loginctl and systemctl runners are required")
	}
	return &NativePrivilegeUserServiceManager{loginctl: loginctl, systemctl: systemctl}, nil
}

// EnsurePrivilegeUserService enables linger and then reloads/enables/starts
// only when independent pre-state proves a mutation is necessary.
func (m *NativePrivilegeUserServiceManager) EnsurePrivilegeUserService(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (bool, error) {
	if m == nil || ctx == nil || request.Operation() != runtimeport.PrivilegeEnableUserService ||
		request.Digest().IsZero() || !m.runnersMatchPrivilegeServiceAuthority(request.Authority()) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	authority := request.Authority()
	unit, linger, enabled, active, err := m.ObservePrivilegeUserServiceState(ctx, authority)
	if err != nil || unit != authority.ServiceUnitDigest() {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	if linger && enabled && active {
		return false, nil
	}
	if !linger {
		invocation, invocationError := argvprocess.NewLoginctlEnableLingerInvocation(
			m.loginctl.ExecutableAuthority().CanonicalPath(), authority.InvokingUID(),
		)
		if invocationError != nil || runPrivilegeServiceInvocation(ctx, m.loginctl, invocation) != nil {
			return false, privilegeOperationContextOrIntegrity(ctx)
		}
	}
	if !enabled || !active {
		reload, reloadError := argvprocess.NewSystemctlUserDaemonReloadInvocation(
			m.systemctl.ExecutableAuthority().CanonicalPath(), authority.AccountName(),
		)
		enable, enableError := argvprocess.NewSystemctlUserEnableNowInvocation(
			m.systemctl.ExecutableAuthority().CanonicalPath(), authority.AccountName(),
		)
		if reloadError != nil || enableError != nil ||
			runPrivilegeServiceInvocation(ctx, m.systemctl, reload) != nil ||
			runPrivilegeServiceInvocation(ctx, m.systemctl, enable) != nil {
			return false, privilegeOperationContextOrIntegrity(ctx)
		}
	}
	unit, linger, enabled, active, err = m.ObservePrivilegeUserServiceState(ctx, authority)
	if err != nil || unit != authority.ServiceUnitDigest() || !linger || !enabled || !active {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	return true, nil
}

// DisablePrivilegeUserService stops and disables only the exact verified
// docker.service. Linger and the unit file are preserved because either may
// predate AgentMemory or be shared with another rootless workflow.
func (m *NativePrivilegeUserServiceManager) DisablePrivilegeUserService(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (bool, error) {
	if m == nil || ctx == nil || request.Operation() != runtimeport.PrivilegeRemoveManagedPackages ||
		request.Digest().IsZero() || !m.runnersMatchPrivilegeServiceAuthority(request.Authority()) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	authority := request.Authority()
	unit, _, enabled, active, err := m.ObservePrivilegeUserServiceState(ctx, authority)
	if err != nil || unit != authority.ServiceUnitDigest() {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	if !enabled && !active {
		return false, nil
	}
	disable, err := argvprocess.NewSystemctlUserDisableNowInvocation(
		m.systemctl.ExecutableAuthority().CanonicalPath(), authority.AccountName(),
	)
	if err != nil || runPrivilegeServiceInvocation(ctx, m.systemctl, disable) != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	unit, _, enabled, active, err = m.ObservePrivilegeUserServiceState(ctx, authority)
	if err != nil || unit != authority.ServiceUnitDigest() || enabled || active {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	return true, nil
}

// ObservePrivilegeUserServiceState rehashes the user-owned unit before and
// after querying systemd so a replaced unit cannot authorize a receipt.
func (m *NativePrivilegeUserServiceManager) ObservePrivilegeUserServiceState(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (runtimeinstall.Hash, bool, bool, bool, error) {
	if m == nil || ctx == nil || !m.runnersMatchPrivilegeServiceAuthority(authority) {
		return runtimeinstall.Hash{}, false, false, false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, false, false, false, err
	}
	unit, err := verifyPrivilegeUserServiceUnit(authority)
	if err != nil {
		return runtimeinstall.Hash{}, false, false, false, err
	}
	linger, err := m.observePrivilegeLinger(ctx, authority)
	if err != nil {
		return runtimeinstall.Hash{}, false, false, false, err
	}
	enabled, active, err := m.observePrivilegeSystemdUnit(ctx, authority)
	if err != nil {
		return runtimeinstall.Hash{}, false, false, false, err
	}
	reverified, err := verifyPrivilegeUserServiceUnit(authority)
	if err != nil || reverified != unit {
		return runtimeinstall.Hash{}, false, false, false, runtimeport.ErrPrivilegeIntegrity
	}
	return unit, linger, enabled, active, nil
}

func (m *NativePrivilegeUserServiceManager) observePrivilegeLinger(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (bool, error) {
	invocation, err := argvprocess.NewLoginctlShowLingerInvocation(
		m.loginctl.ExecutableAuthority().CanonicalPath(), authority.InvokingUID(),
	)
	if err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	result, err := m.loginctl.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	switch string(result.StandardOutput) {
	case "yes\n":
		return true, nil
	case "no\n":
		return false, nil
	default:
		return false, runtimeport.ErrPrivilegeIntegrity
	}
}

func (m *NativePrivilegeUserServiceManager) observePrivilegeSystemdUnit(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (bool, bool, error) {
	invocation, err := argvprocess.NewSystemctlUserShowInvocation(
		m.systemctl.ExecutableAuthority().CanonicalPath(), authority.AccountName(),
	)
	if err != nil {
		return false, false, runtimeport.ErrPrivilegeIntegrity
	}
	result, runError := m.systemctl.Run(ctx, invocation)
	if runError != nil {
		if contextError := ctx.Err(); contextError != nil {
			return false, false, contextError
		}
		if result.ExitCode == 4 && !result.OutputTruncated && len(result.StandardOutput) == 0 {
			return false, false, nil
		}
		return false, false, runtimeport.ErrPrivilegeIntegrity
	}
	if result.ExitCode != 0 || result.OutputTruncated {
		return false, false, runtimeport.ErrPrivilegeIntegrity
	}
	return parsePrivilegeSystemdUnitState(result.StandardOutput)
}

func parsePrivilegeSystemdUnitState(raw []byte) (bool, bool, error) {
	if len(raw) == 0 || len(raw) > 4096 || raw[len(raw)-1] != '\n' {
		return false, false, runtimeport.ErrPrivilegeIntegrity
	}
	properties := make(map[string]string, 3)
	for _, line := range strings.Split(string(raw[:len(raw)-1]), "\n") {
		key, value, present := strings.Cut(line, "=")
		if !present || value == "" || strings.ContainsAny(value, "\x00\r\n=") ||
			(key != "LoadState" && key != "UnitFileState" && key != "ActiveState") {
			return false, false, runtimeport.ErrPrivilegeIntegrity
		}
		if _, duplicate := properties[key]; duplicate {
			return false, false, runtimeport.ErrPrivilegeIntegrity
		}
		properties[key] = value
	}
	if len(properties) != 3 {
		return false, false, runtimeport.ErrPrivilegeIntegrity
	}
	if properties["LoadState"] != "loaded" {
		return false, false, nil
	}
	return properties["UnitFileState"] == "enabled", properties["ActiveState"] == "active", nil
}

func runPrivilegeServiceInvocation(
	ctx context.Context,
	runner argvprocess.Runner,
	invocation argvprocess.Invocation,
) error {
	result, err := runner.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated {
		return privilegeOperationContextOrIntegrity(ctx)
	}
	return nil
}

func verifyPrivilegeUserServiceUnit(
	authority runtimeport.LinuxAuthority,
) (runtimeinstall.Hash, error) {
	if !authority.Valid() || authority.ServiceID() != "docker.service" {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	directory := filepath.Join(authority.HomeDirectory(), ".config", "systemd", "user")
	for _, path := range []string{
		authority.HomeDirectory(), filepath.Join(authority.HomeDirectory(), ".config"),
		filepath.Join(authority.HomeDirectory(), ".config", "systemd"), directory,
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
		}
		metadata, valid := info.Sys().(*syscall.Stat_t)
		if !valid || metadata.Uid != authority.InvokingUID() {
			return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
		}
	}
	path := filepath.Join(directory, authority.ServiceID())
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	file := os.NewFile(uintptr(descriptor), "privilege-user-service-unit")
	if file == nil {
		_ = unix.Close(descriptor)
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = file.Close() }()
	var metadata unix.Stat_t
	if unix.Fstat(descriptor, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Uid != authority.InvokingUID() || metadata.Gid != authority.InvokingGID() || metadata.Nlink != 1 ||
		uint32(metadata.Mode)&0o022 != 0 || metadata.Size <= 0 || metadata.Size > maximumPrivilegeServiceUnitBytes {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maximumPrivilegeServiceUnitBytes+1))
	if err != nil || written != metadata.Size {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	var digest runtimeinstall.Hash
	copy(digest[:], hasher.Sum(nil))
	if digest != authority.ServiceUnitDigest() {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	return digest, nil
}

func validPrivilegeServiceRunner(
	authority argvprocess.ExecutableAuthority,
	role argvprocess.ExecutableRole,
) bool {
	path := map[argvprocess.ExecutableRole]string{
		argvprocess.ExecutableRoleLoginCTL:  "/usr/bin/loginctl",
		argvprocess.ExecutableRoleSystemCTL: "/usr/bin/systemctl",
	}[role]
	return authority.Valid() && authority.Platform() == runtimeinstall.PlatformLinux.String() &&
		authority.Role() == role && authority.CanonicalPath() == path
}

func (m *NativePrivilegeUserServiceManager) runnersMatchPrivilegeServiceAuthority(
	authority runtimeport.LinuxAuthority,
) bool {
	if m == nil || nilArtifactDependency(m.loginctl) || nilArtifactDependency(m.systemctl) || !authority.Valid() {
		return false
	}
	loginctl := m.loginctl.ExecutableAuthority()
	systemctl := m.systemctl.ExecutableAuthority()
	return validPrivilegeServiceRunner(loginctl, argvprocess.ExecutableRoleLoginCTL) &&
		validPrivilegeServiceRunner(systemctl, argvprocess.ExecutableRoleSystemCTL) &&
		loginctl.RuntimePlanDigest() == authority.PlanDigest() &&
		systemctl.RuntimePlanDigest() == authority.PlanDigest() &&
		loginctl.Architecture() == authority.Architecture().String() &&
		systemctl.Architecture() == authority.Architecture().String() && loginctl.SameSignedPlan(systemctl)
}

var _ PrivilegeUserServiceManager = (*NativePrivilegeUserServiceManager)(nil)
var _ PrivilegeUserServiceStateProbe = (*NativePrivilegeUserServiceManager)(nil)
