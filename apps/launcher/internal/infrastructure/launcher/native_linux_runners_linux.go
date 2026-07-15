//go:build linux

package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type nativeLinuxRunnerSet struct {
	docker   *process.Runner
	compose  *process.Runner
	rootless *process.Runner
	rpmkeys  *process.Runner
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
	result := nativeLinuxRunnerSet{docker: docker, compose: compose, rootless: rootless}
	if authority.PackageManager() == runtimeport.PackageManagerDNF {
		result.rpmkeys, err = construct(argvprocess.ExecutableRoleRPMKeys)
		if err != nil {
			return nativeLinuxRunnerSet{}, err
		}
	}
	return result, nil
}
