//go:build linux

package bootstrap

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const linuxMachineIDPath = "/etc/machine-id"

// LinuxOwnerBindingSource binds bootstrap state to the systemd machine ID and
// effective invoking UID. It makes no claims for macOS or Windows identity.
type LinuxOwnerBindingSource struct {
	machineIDPath      string
	expectedMachineUID uint32
	effectiveUID       func() int
}

var _ bootstrapport.OwnerBindingSource = (*LinuxOwnerBindingSource)(nil)

// NewLinuxOwnerBindingSource creates the Linux identity adapter.
func NewLinuxOwnerBindingSource() *LinuxOwnerBindingSource {
	return newLinuxOwnerBindingSource(linuxMachineIDPath, 0, os.Geteuid)
}

func newLinuxOwnerBindingSource(
	machineIDPath string,
	expectedMachineUID uint32,
	effectiveUID func() int,
) *LinuxOwnerBindingSource {
	return &LinuxOwnerBindingSource{
		machineIDPath:      machineIDPath,
		expectedMachineUID: expectedMachineUID,
		effectiveUID:       effectiveUID,
	}
}

// Current reads and validates Linux owner identity without following a
// machine-id symlink.
func (s *LinuxOwnerBindingSource) Current(ctx context.Context) (install.OwnerBinding, error) {
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	if s == nil || s.machineIDPath == "" || s.effectiveUID == nil {
		return install.OwnerBinding{}, fmt.Errorf("%w: Linux owner source is not configured", bootstrapport.ErrIntegrity)
	}
	info, err := os.Lstat(s.machineIDPath)
	if err != nil {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity is unavailable", bootstrapport.ErrIntegrity)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity file is unsafe", bootstrapport.ErrIntegrity)
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != s.expectedMachineUID {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity owner is unsafe", bootstrapport.ErrIntegrity)
	}

	descriptor, err := syscall.Open(s.machineIDPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity cannot be opened safely", bootstrapport.ErrIntegrity)
	}
	file := os.NewFile(uintptr(descriptor), "machine-id")
	if file == nil {
		_ = syscall.Close(descriptor)
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity descriptor is invalid", bootstrapport.ErrIntegrity)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity cannot be read", bootstrapport.ErrIntegrity)
	}
	machineID, valid := canonicalLinuxMachineID(contents)
	if !valid {
		return install.OwnerBinding{}, fmt.Errorf("%w: machine identity format is invalid", bootstrapport.ErrIntegrity)
	}
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	return install.BindOwner("linux:machine-id:"+machineID, "linux:uid:"+strconv.Itoa(s.effectiveUID()))
}

func canonicalLinuxMachineID(contents []byte) (string, bool) {
	switch len(contents) {
	case 32:
	case 33:
		if contents[32] != '\n' {
			return "", false
		}
		contents = contents[:32]
	default:
		return "", false
	}
	value := string(contents)
	return value, lowerHex(value)
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
