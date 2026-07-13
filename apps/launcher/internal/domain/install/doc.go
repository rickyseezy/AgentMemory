// Package install contains the platform-independent PF-001 installation domain.
//
// The package models the ordered installation phases, immutable plan binding,
// verified step evidence, and restart-safe state transitions. It deliberately
// contains no filesystem, process, operating-system, or container-runtime code.
package install
