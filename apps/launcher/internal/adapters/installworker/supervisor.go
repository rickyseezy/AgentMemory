// Package installworker supervises process-owned PF-001 installer workers.
package installworker

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const closeTimeout = 5 * time.Second

// ErrSupervisorUnavailable means the worker authority is absent or closed.
var ErrSupervisorUnavailable = errors.New("installation supervisor unavailable")

type installer interface {
	Install(context.Context, installapp.InstallCommand) (installapp.InstallResult, error)
}

type worker struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// Supervisor owns at most one worker for each operation/plan binding.
type Supervisor struct {
	installer installer
	mu        sync.Mutex
	workers   map[string]*worker
	closed    bool
}

// New creates a process-owned exact-operation worker supervisor.
func New(installer installer) (*Supervisor, error) {
	if nilCapability(installer) {
		return nil, ErrSupervisorUnavailable
	}
	return &Supervisor{installer: installer, workers: make(map[string]*worker)}, nil
}

// EnsureRunning validates the command, coalesces concurrent calls, and returns
// only after the worker is registered. Worker execution is deliberately not
// bound to an MCP request deadline.
func (s *Supervisor) EnsureRunning(ctx context.Context, command installapp.InstallCommand) error {
	_, err := s.ensureWorker(ctx, command)
	return err
}

// RunToPause starts or joins the exact worker and waits until it reaches Ready,
// another durable pause, or a terminal outcome. It is used by the short-lived
// native login continuation process so its resources remain alive until the
// installer has durably settled.
func (s *Supervisor) RunToPause(ctx context.Context, command installapp.InstallCommand) error {
	current, err := s.ensureWorker(ctx, command)
	if err != nil {
		return err
	}
	select {
	case <-current.done:
		return current.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) ensureWorker(ctx context.Context, command installapp.InstallCommand) (*worker, error) {
	if s == nil || ctx == nil {
		return nil, ErrSupervisorUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operationID, err := install.NewOperationID(command.OperationID)
	if err != nil || len(command.CanonicalPlan) == 0 {
		return nil, ErrSupervisorUnavailable
	}
	planDigest, err := install.BindPlan(command.CanonicalPlan)
	if err != nil {
		return nil, ErrSupervisorUnavailable
	}
	key := operationID.String() + ":" + planDigest.String()
	ownedCommand := installapp.InstallCommand{
		OperationID: operationID.String(), CanonicalPlan: append([]byte(nil), command.CanonicalPlan...),
		ResumeContinuation: command.ResumeContinuation,
	}
	if command.ResumeReceipt != nil {
		receipt := *command.ResumeReceipt
		ownedCommand.ResumeReceipt = &receipt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSupervisorUnavailable
	}
	if current, running := s.workers[key]; running {
		return current, nil
	}
	workerContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	current := &worker{cancel: cancel, done: make(chan struct{})}
	s.workers[key] = current
	go s.run(workerContext, key, current, ownedCommand)
	return current, nil
}

func (s *Supervisor) run(
	ctx context.Context,
	key string,
	current *worker,
	command installapp.InstallCommand,
) {
	defer close(current.done)
	_, current.err = s.installer.Install(ctx, command)
	s.mu.Lock()
	if s.workers[key] == current {
		delete(s.workers, key)
	}
	s.mu.Unlock()
}

// Close cancels every process-owned worker and waits for bounded settlement.
func (s *Supervisor) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrSupervisorUnavailable
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	workers := make([]*worker, 0, len(s.workers))
	for _, current := range s.workers {
		workers = append(workers, current)
		current.cancel()
	}
	s.mu.Unlock()
	deadline, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
	defer cancel()
	for _, current := range workers {
		select {
		case <-current.done:
		case <-deadline.Done():
			return ErrSupervisorUnavailable
		}
	}
	return nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
