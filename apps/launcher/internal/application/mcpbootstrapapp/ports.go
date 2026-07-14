// Package mcpbootstrapapp owns the transport-neutral PF-001 bootstrap surface.
package mcpbootstrapapp

import "context"

// SetupPort opens a new owner-bound local setup capability. Implementations
// keep capability material inside the browser URL and never return it here.
type SetupPort interface {
	OpenSetup(context.Context) error
}

// CancellationPort durably requests cancellation for the operation and plan
// bound when the application is composed.
type CancellationPort interface {
	RequestCancellation(context.Context) error
}
