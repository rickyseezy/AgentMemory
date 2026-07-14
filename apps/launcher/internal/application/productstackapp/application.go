// Package productstackapp coordinates signed-source-derived Docker stack
// mutations without exposing caller-constructible Compose execution authority.
package productstackapp

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Application is the product stack use case.
type Application struct {
	compose containerengine.ReleaseComposePort
}

// New requires the production release-derived Compose boundary.
func New(compose containerengine.ReleaseComposePort) (*Application, error) {
	if nilCapability(compose) {
		return nil, errors.New("release Compose capability is required")
	}
	return &Application{compose: compose}, nil
}

// RunMigrations executes only a migration authorization.
func (a *Application) RunMigrations(
	ctx context.Context,
	authorization productstack.Authorization,
) (productstack.Receipt, error) {
	if !authorization.Valid() || authorization.Operation() != productstack.OperationMigrate {
		return productstack.Receipt{}, productstack.ErrIntegrity
	}
	rendered, err := a.compose.RunReleaseMigrations(ctx, authorization.Source())
	return a.receipt(authorization, rendered, err)
}

// StartCoreAndGraph executes only the persistent-stack start authorization.
func (a *Application) StartCoreAndGraph(
	ctx context.Context,
	authorization productstack.Authorization,
) (productstack.Receipt, error) {
	if !authorization.Valid() || authorization.Operation() != productstack.OperationStartCoreAndGraph {
		return productstack.Receipt{}, productstack.ErrIntegrity
	}
	rendered, err := a.compose.StartReleaseAndWait(ctx, authorization.Source())
	return a.receipt(authorization, rendered, err)
}

func (a *Application) receipt(
	authorization productstack.Authorization,
	rendered containerengine.RenderedConfiguration,
	operationError error,
) (productstack.Receipt, error) {
	if operationError != nil {
		return productstack.Receipt{}, productstack.ErrUnavailable
	}
	digest, err := install.ParseDigest(rendered.Digest().Hex())
	if err != nil {
		return productstack.Receipt{}, productstack.ErrIntegrity
	}
	receipt, err := productstack.NewReceiptForAdapter(authorization, digest)
	if err != nil {
		return productstack.Receipt{}, productstack.ErrIntegrity
	}
	return receipt, nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ productstack.Ensurer = (*Application)(nil)
