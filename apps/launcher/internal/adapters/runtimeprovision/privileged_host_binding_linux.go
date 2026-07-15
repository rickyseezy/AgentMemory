//go:build linux

package runtimeprovision

import (
	"context"
	"os"
	"os/user"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const polkitOriginalUIDEnvironment = "PKEXEC_UID"

type nativePrivilegedLinuxIdentitySource struct{}

// NewPrivilegedLinuxHostBindingProvider constructs the root-helper identity
// provider. PKEXEC_UID is the only admitted invocation identity surface.
func NewPrivilegedLinuxHostBindingProvider() (*PrivilegedLinuxHostBindingProvider, error) {
	source := &nativePrivilegedLinuxIdentitySource{}
	return newPrivilegedLinuxHostBindingProvider(source, source)
}

func (*nativePrivilegedLinuxIdentitySource) CurrentPrivilegedLinuxIdentity(
	ctx context.Context,
) (privilegedLinuxIdentity, error) {
	if ctx == nil {
		return privilegedLinuxIdentity{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return privilegedLinuxIdentity{}, err
	}
	rawUID, present := os.LookupEnv(polkitOriginalUIDEnvironment)
	parsedUID, uidError := strconv.ParseUint(rawUID, 10, 32)
	if os.Geteuid() != 0 || !present || rawUID == "" || uidError != nil || parsedUID == 0 ||
		strconv.FormatUint(parsedUID, 10) != rawUID {
		return privilegedLinuxIdentity{}, ErrUnsupportedHost
	}
	account, err := user.LookupId(rawUID)
	if err != nil || account.Uid != rawUID {
		return privilegedLinuxIdentity{}, ErrUnsupportedHost
	}
	parsedGID, gidError := strconv.ParseUint(account.Gid, 10, 32)
	if gidError != nil || parsedGID == 0 || strconv.FormatUint(parsedGID, 10) != account.Gid {
		return privilegedLinuxIdentity{}, ErrUnsupportedHost
	}
	// G115: both values were bounded by ParseUint(..., 32).
	identity := privilegedLinuxIdentity{
		uid: uint32(parsedUID), gid: uint32(parsedGID), account: account.Username, home: account.HomeDir,
	}
	if !identity.valid() || validateOwnerDirectory(identity.home, identity.uid, false) != nil {
		return privilegedLinuxIdentity{}, ErrUnsupportedHost
	}
	return identity, nil
}

func (*nativePrivilegedLinuxIdentitySource) CurrentPrivilegedLinuxMachine(
	ctx context.Context,
) (string, runtimeinstall.Hash, error) {
	if ctx == nil {
		return "", runtimeinstall.Hash{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", runtimeinstall.Hash{}, err
	}
	_, version, err := linuxOSRelease()
	if err != nil {
		return "", runtimeinstall.Hash{}, ErrProbeFailed
	}
	digest, err := linuxMachineDigest()
	if err != nil {
		return "", runtimeinstall.Hash{}, ErrProbeFailed
	}
	return version, digest, nil
}

var (
	_ privilegedLinuxIdentitySource = (*nativePrivilegedLinuxIdentitySource)(nil)
	_ privilegedLinuxMachineSource  = (*nativePrivilegedLinuxIdentitySource)(nil)
)
