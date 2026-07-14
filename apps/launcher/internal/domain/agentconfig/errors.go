// Package agentconfig defines the host-neutral PF-001 MCP configuration
// contract and its side-effect-free merge policy.
package agentconfig

import "errors"

var (
	// ErrInvalidDocument reports unsupported, malformed, duplicate-key, or
	// oversized host configuration without echoing its content.
	ErrInvalidDocument = errors.New("agent configuration document is invalid")
	// ErrAmbiguousOwnership reports an existing AgentMemory-named entry that
	// cannot be proven to belong to this installation.
	ErrAmbiguousOwnership = errors.New("agent configuration ownership is ambiguous")
	// ErrManagedEntryConflict reports a managed entry that changed since its
	// protected receipt was recorded.
	ErrManagedEntryConflict = errors.New("managed agent configuration entry changed")
	// ErrInvalidTarget reports incomplete or malformed desired entry metadata.
	ErrInvalidTarget = errors.New("agent configuration target is invalid")
)
