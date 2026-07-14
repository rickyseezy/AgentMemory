//go:build windows

// Package hostlock serializes PF-001 machine-mutating operations.
package hostlock

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
)

const installationMutexIdentityPrefix = "agentmemory:pf001:installation-lock:v1:windows-machine-guid:"

type machineIdentitySource func(context.Context) (string, error)

// Port owns the process-independent named mutex. The name is shared by every
// principal on one machine. The mutex security descriptor binds each object's
// lifetime to the invoking SID; incorporating the SID into the name would be
// unsafe because different local principals could then mutate the machine
// concurrently under different mutexes.
type Port struct {
	machineIdentity machineIdentitySource
}

// New ignores the Unix path parameter and preserves the cross-platform
// composition signature. Windows derives its kernel-object name from the
// canonical local machine identity during Acquire.
func New(_ string) (*Port, error) {
	return &Port{machineIdentity: windowssecurity.MachineGUID}, nil
}

// Acquire waits interruptibly for the machine-bound global installation
// mutex. The windowssecurity capability creates it with an explicit protected
// owner-only descriptor and re-verifies owner plus exact DACL even when the
// named object already existed.
func (p *Port) Acquire(ctx context.Context) (installapp.InstallationLock, error) {
	if ctx == nil {
		return nil, errors.New("installation lock context is required")
	}
	name, err := p.mutexName(ctx)
	if err != nil {
		return nil, err
	}
	mutex, err := windowssecurity.AcquireOwnerMutex(ctx, name)
	if err != nil {
		return nil, err
	}
	return &heldLock{mutex: mutex}, nil
}

func (p *Port) mutexName(ctx context.Context) (string, error) {
	if p == nil || p.machineIdentity == nil {
		return "", errors.New("installation mutex machine identity capability is unavailable")
	}
	machineGUID, err := p.machineIdentity(ctx)
	if err != nil {
		return "", errors.New("installation mutex machine identity is unavailable")
	}
	machineGUID = strings.ToLower(machineGUID)
	if !canonicalMachineGUID(machineGUID) {
		return "", errors.New("installation mutex machine identity is invalid")
	}
	name, err := windowssecurity.OwnerMutexName(installationMutexIdentityPrefix + machineGUID)
	if err != nil {
		return "", errors.New("installation mutex identity cannot be derived")
	}
	return name, nil
}

func canonicalMachineGUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

type heldLock struct {
	mu       sync.Mutex
	mutex    *windowssecurity.OwnerMutex
	released bool
	result   error
}

// Release always attempts cleanup, even when the operation context was
// cancelled. The secure handle remains owned by windowssecurity until this
// method tells its pinned owner thread to release and close it.
func (l *heldLock) Release(_ context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return l.result
	}
	l.released = true
	l.result = l.mutex.Release()
	return l.result
}
