//go:build linux

package runtimeprovision

import (
	"context"
	"os"
	"os/user"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

// NativeLinuxHostBindingProvider reads only fixed native identity sources.
type NativeLinuxHostBindingProvider struct{}

// NewNativeLinuxHostBindingProvider constructs the production identity probe.
func NewNativeLinuxHostBindingProvider() *NativeLinuxHostBindingProvider {
	return &NativeLinuxHostBindingProvider{}
}

// CurrentLinuxHostBinding binds the actual non-root effective user and
// machine. Catalog policy is deliberately unavailable at this boundary.
func (*NativeLinuxHostBindingProvider) CurrentLinuxHostBinding(
	ctx context.Context,
) (runtimecatalogapp.LinuxHostBinding, error) {
	if ctx == nil {
		return runtimecatalogapp.LinuxHostBinding{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, err
	}
	current, err := user.Current()
	if err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, ErrProbeFailed
	}
	uid, uidError := strconv.ParseUint(current.Uid, 10, 32)
	gid, gidError := strconv.ParseUint(current.Gid, 10, 32)
	if uidError != nil || gidError != nil || uid == 0 || gid == 0 ||
		os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return runtimecatalogapp.LinuxHostBinding{}, ErrUnsupportedHost
	}
	if err := validateOwnerDirectory(current.HomeDir, uint32(uid), false); err != nil { // #nosec G115 -- parsed as uint32 above.
		return runtimecatalogapp.LinuxHostBinding{}, ErrUnsupportedHost
	}
	_, versionID, err := linuxOSRelease()
	if err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, ErrProbeFailed
	}
	machineDigest, err := linuxMachineDigest()
	if err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, ErrProbeFailed
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, err
	}
	runtimeDirectory := "/run/user/" + strconv.FormatUint(uid, 10)
	return runtimecatalogapp.NewLinuxHostBinding(runtimecatalogapp.LinuxHostBindingInput{
		VersionID:   versionID,
		InvokingUID: uint32(uid), InvokingGID: uint32(gid), // #nosec G115 -- parsed as uint32 above.
		AccountName: current.Username, PrincipalID: "linux:uid:" + strconv.FormatUint(uid, 10),
		MachineDigest: machineDigest, HomeDirectory: current.HomeDir,
		RuntimeDirectory: runtimeDirectory, Endpoint: "unix://" + runtimeDirectory + "/docker.sock",
	})
}

var _ LinuxHostBindingProvider = (*NativeLinuxHostBindingProvider)(nil)
