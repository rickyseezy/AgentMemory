//go:build linux

package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type nativeLinuxRunnerSet struct {
	docker    *process.Runner
	compose   *process.Runner
	rootless  *process.Runner
	rpmkeys   *process.Runner
	privilege *process.Runner
}

type nativeLinuxPrivilegeRunnerSet struct {
	transaction *process.Runner
	query       *process.Runner
	loginctl    *process.Runner
	systemctl   *process.Runner
}

func newNativeLinuxRunnerSet(
	authority runtimeport.LinuxAuthority,
	release releaseinventory.Digest,
) (nativeLinuxRunnerSet, error) {
	receipts, err := newNativeLinuxPackageReceiptVerifier(authority, release)
	if err != nil {
		return nativeLinuxRunnerSet{}, errNativeInstallerIntegrity
	}
	publisher, err := process.NewNativePublisherVerifier(process.NativePublisherDependencies{
		LinuxPackageReceipt: receipts,
	})
	if err != nil {
		return nativeLinuxRunnerSet{}, errNativeInstallerIntegrity
	}
	construct := func(role argvprocess.ExecutableRole) (*process.Runner, error) {
		executable, authorityError := newNativeLinuxExecutableAuthority(authority, release, role)
		if authorityError != nil {
			return nil, errNativeInstallerIntegrity
		}
		runner, runnerError := process.NewRunner(executable, publisher)
		if runnerError != nil {
			return nil, errNativeInstallerIntegrity
		}
		return runner, nil
	}
	docker, err := construct(argvprocess.ExecutableRoleDockerCLI)
	if err != nil {
		return nativeLinuxRunnerSet{}, err
	}
	compose, err := construct(argvprocess.ExecutableRoleComposePlugin)
	if err != nil {
		return nativeLinuxRunnerSet{}, err
	}
	rootless, err := construct(argvprocess.ExecutableRoleRootlessSetup)
	if err != nil {
		return nativeLinuxRunnerSet{}, err
	}
	privilege, err := construct(argvprocess.ExecutableRolePrivilegeBroker)
	if err != nil {
		return nativeLinuxRunnerSet{}, err
	}
	result := nativeLinuxRunnerSet{docker: docker, compose: compose, rootless: rootless, privilege: privilege}
	if authority.PackageManager() == runtimeport.PackageManagerDNF {
		result.rpmkeys, err = construct(argvprocess.ExecutableRoleRPMKeys)
		if err != nil {
			return nativeLinuxRunnerSet{}, err
		}
	}
	return result, nil
}

func newNativeLinuxPrivilegeRunnerSet(
	authority runtimeport.LinuxAuthority,
	release releaseinventory.Digest,
) (nativeLinuxPrivilegeRunnerSet, error) {
	receipts, err := newNativeLinuxPackageReceiptVerifier(authority, release)
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, errNativeInstallerIntegrity
	}
	publisher, err := process.NewNativePublisherVerifier(process.NativePublisherDependencies{
		LinuxPackageReceipt: receipts,
	})
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, errNativeInstallerIntegrity
	}
	construct := func(role argvprocess.ExecutableRole) (*process.Runner, error) {
		executable, authorityError := newNativeLinuxExecutableAuthority(authority, release, role)
		if authorityError != nil {
			return nil, errNativeInstallerIntegrity
		}
		runner, runnerError := process.NewRunner(executable, publisher)
		if runnerError != nil {
			return nil, errNativeInstallerIntegrity
		}
		return runner, nil
	}
	transactionRole, queryRole := argvprocess.ExecutableRoleAPTTransaction, argvprocess.ExecutableRoleDPKGQuery
	if authority.PackageManager() == runtimeport.PackageManagerDNF {
		transactionRole, queryRole = argvprocess.ExecutableRoleDNFTransaction, argvprocess.ExecutableRoleRPMQuery
	}
	transaction, err := construct(transactionRole)
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, err
	}
	query, err := construct(queryRole)
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, err
	}
	loginctl, err := construct(argvprocess.ExecutableRoleLoginCTL)
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, err
	}
	systemctl, err := construct(argvprocess.ExecutableRoleSystemCTL)
	if err != nil {
		return nativeLinuxPrivilegeRunnerSet{}, err
	}
	return nativeLinuxPrivilegeRunnerSet{
		transaction: transaction, query: query, loginctl: loginctl, systemctl: systemctl,
	}, nil
}
