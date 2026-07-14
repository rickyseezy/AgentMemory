//go:build windows

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

type windowsIdentityCapability interface {
	MachineGUID(context.Context) (string, error)
	UserSID(context.Context) (string, error)
}

// WindowsOwnerBindingSource binds bootstrap state to the local MachineGuid and
// the invoking process token's user SID.
type WindowsOwnerBindingSource struct{ identity windowsIdentityCapability }

var _ bootstrapport.OwnerBindingSource = (*WindowsOwnerBindingSource)(nil)

// NewWindowsOwnerBindingSource creates the native Windows owner source.
func NewWindowsOwnerBindingSource() (*WindowsOwnerBindingSource, error) {
	return newWindowsOwnerBindingSource(windowsNativeIdentity{})
}

func newWindowsOwnerBindingSource(identity windowsIdentityCapability) (*WindowsOwnerBindingSource, error) {
	if nilDependency(identity) {
		return nil, errors.New("windows owner source requires native machine and SID capabilities")
	}
	return &WindowsOwnerBindingSource{identity: identity}, nil
}

// Current resolves canonical identities and returns only their domain hashes.
func (s *WindowsOwnerBindingSource) Current(ctx context.Context) (install.OwnerBinding, error) {
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	if s == nil || nilDependency(s.identity) {
		return install.OwnerBinding{}, fmt.Errorf("%w: Windows owner source is not configured", bootstrapport.ErrIntegrity)
	}
	machineGUID, err := s.identity.MachineGUID(ctx)
	if err != nil {
		return install.OwnerBinding{}, err
	}
	userSID, err := s.identity.UserSID(ctx)
	if err != nil {
		return install.OwnerBinding{}, err
	}
	machineGUID, ok := canonicalWindowsMachineGUID(machineGUID)
	if !ok {
		return install.OwnerBinding{}, fmt.Errorf("%w: Windows machine GUID is invalid", bootstrapport.ErrIntegrity)
	}
	userSID, ok = canonicalWindowsSID(userSID)
	if !ok {
		return install.OwnerBinding{}, fmt.Errorf("%w: Windows invoking SID is invalid", bootstrapport.ErrIntegrity)
	}
	return install.BindOwner("windows:machine-guid:"+machineGUID, "windows:sid:"+userSID)
}

func canonicalWindowsMachineGUID(value string) (string, bool) {
	value = strings.ToLower(value)
	if len(value) != 36 {
		return "", false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return "", false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return "", false
			}
		}
	}
	return value, true
}

func canonicalWindowsSID(value string) (string, bool) {
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() {
		return "", false
	}
	canonical := sid.String()
	return canonical, canonical == value
}

type windowsNativeIdentity struct{}

func (windowsNativeIdentity) MachineGUID(ctx context.Context) (string, error) {
	return windowssecurity.MachineGUID(ctx)
}

func (windowsNativeIdentity) UserSID(ctx context.Context) (string, error) {
	_, value, err := windowssecurity.CurrentUserSID(ctx)
	return value, err
}
