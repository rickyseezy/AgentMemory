package setuphttp

import (
	"context"
	"errors"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
)

// Controller owns successive one-use setup servers for one launcher process.
// Each OpenSetup call invalidates the preceding capability by shutting down
// its listeners before minting and opening a fresh browser capability.
type Controller struct {
	owner        context.Context
	config       Config
	dependencies Dependencies

	mu      sync.Mutex
	current *Server
	closed  bool
}

// NewController validates all server dependencies without binding a listener.
// ExpiresAt must be absent because each one-use authority receives a fresh
// SessionLifetime-relative expiry at OpenSetup time.
func NewController(
	owner context.Context,
	config Config,
	dependencies Dependencies,
) (*Controller, error) {
	if owner == nil || owner.Err() != nil || !config.ExpiresAt.IsZero() || nilDependency(dependencies.Clock) {
		return nil, errors.New("setup controller configuration is invalid")
	}
	config = normalizeConfig(config)
	now := dependencies.Clock.Now().UTC()
	if now.IsZero() {
		return nil, errors.New("setup controller clock is invalid")
	}
	validationConfig := config
	validationConfig.ExpiresAt = now.Add(config.SessionLifetime)
	if _, err := NewServer(validationConfig, dependencies); err != nil {
		return nil, err
	}
	return &Controller{owner: owner, config: config, dependencies: dependencies}, nil
}

// OpenSetup closes any prior authority and opens a fresh one. No capability,
// URL, port, or origin crosses this boundary.
func (c *Controller) OpenSetup(ctx context.Context) error {
	if c == nil || ctx == nil {
		return errors.New("setup controller is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.owner == nil || c.owner.Err() != nil {
		return errors.New("setup controller is closed")
	}
	if c.current != nil {
		closeContext, cancelClose := context.WithTimeout(context.WithoutCancel(ctx), c.config.RequestTimeout)
		closeError := c.current.Close(closeContext)
		cancelClose()
		if closeError != nil {
			return errors.New("previous setup authority could not be closed")
		}
		c.current = nil
	}
	now := c.dependencies.Clock.Now().UTC()
	if now.IsZero() {
		return errors.New("setup authority clock is unavailable")
	}
	serverConfig := c.config
	serverConfig.ExpiresAt = now.Add(c.config.SessionLifetime)
	server, err := NewServer(serverConfig, c.dependencies)
	if err != nil {
		return errors.New("setup authority could not be created")
	}
	//nolint:contextcheck // The server must outlive this tool call and inherit the process owner.
	if _, err := server.Start(c.owner); err != nil {
		return errors.New("setup authority could not be opened")
	}
	c.current = server
	return nil
}

// Close permanently closes the controller and its current one-use authority.
func (c *Controller) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return errors.New("setup controller close is invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.current == nil {
		return nil
	}
	server := c.current
	c.current = nil
	return server.Close(ctx)
}

var _ mcpbootstrapapp.SetupPort = (*Controller)(nil)
