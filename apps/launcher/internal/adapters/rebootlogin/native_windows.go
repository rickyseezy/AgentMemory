//go:build windows

package rebootlogin

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
	"golang.org/x/sys/windows/registry"
)

const perUserRunKey = `Software\Microsoft\Windows\CurrentVersion\Run`

type windowsRegistrar struct{}

// NewNativeRegistrar uses the documented per-user Run facility. The entry is
// removed only after resumed aggregate progress is durable; unlike RunOnce,
// this path remains available to a standard user and survives a process crash.
func NewNativeRegistrar() (rebootapp.LoginRegistrar, error) { return windowsRegistrar{}, nil }

func (windowsRegistrar) Register(ctx context.Context, record rebootcontinuation.Record) error {
	if ctx == nil || record.OperationID().IsZero() || record.Nonce().IsZero() {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, err := renderWindowsEntry(record)
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, perUserRunKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return rebootapp.ErrUnavailable
	}
	defer key.Close()
	existing, _, readError := key.GetStringValue(value.name)
	if readError == nil && existing != value.content {
		return rebootapp.ErrConflict
	}
	if readError != nil && !errors.Is(readError, registry.ErrNotExist) {
		return rebootapp.ErrUnavailable
	}
	if readError == nil {
		return nil
	}
	if err := key.SetStringValue(value.name, value.content); err != nil {
		return rebootapp.ErrUnavailable
	}
	return nil
}

func (windowsRegistrar) Remove(ctx context.Context, operationID install.OperationID) error {
	if ctx == nil || operationID.IsZero() {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := rebootcontinuation.TokenFor(operationID)
	if err != nil {
		return rebootapp.ErrIntegrity
	}
	return (windowsRegistrar{}).RemoveToken(ctx, token)
}

func (windowsRegistrar) RemoveToken(ctx context.Context, token string) error {
	if ctx == nil || !validEntryToken(token) {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, perUserRunKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return rebootapp.ErrUnavailable
	}
	defer key.Close()
	if err := key.DeleteValue("AgentMemory-" + token); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return rebootapp.ErrUnavailable
	}
	return nil
}

var _ rebootapp.LoginRegistrar = windowsRegistrar{}
var _ TokenRemover = windowsRegistrar{}
