// Package installcontrol adapts the PF-001 install saga to pre-Ready control
// surfaces without exposing canonical plan bytes at inbound boundaries.
package installcontrol

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// InstallCanceller binds canonical plan authority at composition time.
type InstallCanceller struct {
	application InstallCancellationApplication
	command     installapp.CancelCommand
	operationID install.OperationID
	planDigest  install.PlanDigest
}

// InstallCancellationApplication is the single use-case method needed by the
// adapter; the concrete InstallApplication satisfies it in production.
type InstallCancellationApplication interface {
	Cancel(context.Context, installapp.CancelCommand) (installapp.InstallResult, error)
}

// NewInstallCanceller rejects any mismatch between the command and the
// durable setup binding before an MCP request can reach the installer.
func NewInstallCanceller(
	application InstallCancellationApplication,
	command installapp.CancelCommand,
	operationID install.OperationID,
	planDigest install.PlanDigest,
) (*InstallCanceller, error) {
	boundPlan, err := install.BindPlan(command.CanonicalPlan)
	if nilApplication(application) || command.OperationID == "" || len(command.CanonicalPlan) == 0 ||
		operationID.IsZero() || planDigest.IsZero() || err != nil ||
		command.OperationID != operationID.String() || !boundPlan.Equal(planDigest) {
		return nil, errors.New("installation cancellation binding is invalid")
	}
	return &InstallCanceller{
		application: application,
		command: installapp.CancelCommand{
			OperationID:   command.OperationID,
			CanonicalPlan: append([]byte(nil), command.CanonicalPlan...),
		},
		operationID: operationID,
		planDigest:  planDigest,
	}, nil
}

// RequestCancellation delegates only the pre-bound command and verifies the
// safe result identity before acknowledging the request.
func (c *InstallCanceller) RequestCancellation(ctx context.Context) error {
	if c == nil || ctx == nil || nilApplication(c.application) || c.operationID.IsZero() || c.planDigest.IsZero() {
		return errors.New("installation cancellation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := c.application.Cancel(ctx, installapp.CancelCommand{
		OperationID:   c.command.OperationID,
		CanonicalPlan: append([]byte(nil), c.command.CanonicalPlan...),
	})
	if err != nil {
		return err
	}
	if result.OperationID != c.operationID.String() ||
		(!result.CancellationRequested && !result.CancellationSettled && result.State != install.StateCancelled) {
		return errors.New("installation cancellation result is invalid")
	}
	return nil
}

func nilApplication(value InstallCancellationApplication) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ mcpbootstrapapp.CancellationPort = (*InstallCanceller)(nil)
