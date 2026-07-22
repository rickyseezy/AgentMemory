package mcpsessionhost

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

var errSessionAuthority = errors.New("PF-005 host session authority is unavailable")

type installationLockSource interface {
	Acquire(context.Context) (installapp.InstallationLock, error)
}

// InstallationLock adapts the shared machine-global lock without weakening its ownership.
type InstallationLock struct{ source installationLockSource }

// NewInstallationLock rejects an absent shared lock authority.
func NewInstallationLock(source installationLockSource) (*InstallationLock, error) {
	if nilAuthority(source) {
		return nil, errSessionAuthority
	}
	return &InstallationLock{source: source}, nil
}

// Acquire returns the same idempotent held lock through the PF-005 port.
func (l *InstallationLock) Acquire(ctx context.Context) (mcpsessionapp.InstallationLock, error) {
	if l == nil || ctx == nil || nilAuthority(l.source) {
		return nil, errSessionAuthority
	}
	held, err := l.source.Acquire(ctx)
	if err != nil || nilAuthority(held) {
		return nil, errors.Join(errSessionAuthority, err)
	}
	return held, nil
}

type activePointerSource interface {
	Load(context.Context, string) (activerelease.Pointer, error)
}

// ActiveRelease binds pointer loading to the authenticated installation identity.
type ActiveRelease struct {
	source         activePointerSource
	installationID string
}

// NewActiveRelease fixes the only installation whose active pointer may be loaded.
func NewActiveRelease(source activePointerSource, installationID string) (*ActiveRelease, error) {
	if nilAuthority(source) || !mcpsession.ValidUUIDv7(installationID) {
		return nil, errSessionAuthority
	}
	return &ActiveRelease{source: source, installationID: installationID}, nil
}

// LoadActive loads and independently verifies the pointer's installation binding.
func (a *ActiveRelease) LoadActive(ctx context.Context) (activerelease.Pointer, error) {
	if a == nil || ctx == nil || nilAuthority(a.source) || !mcpsession.ValidUUIDv7(a.installationID) {
		return activerelease.Pointer{}, errSessionAuthority
	}
	pointer, err := a.source.Load(ctx, a.installationID)
	if err != nil || pointer.IsZero() || pointer.InstallationID() != a.installationID {
		return activerelease.Pointer{}, errors.Join(errSessionAuthority, err)
	}
	return pointer, nil
}

func nilAuthority(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() { //nolint:exhaustive // Non-nilable concrete values are valid capabilities.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ mcpsessionapp.InstallationLockPort = (*InstallationLock)(nil)
	_ mcpsessionapp.ActiveReleasePort    = (*ActiveRelease)(nil)
)
