package main

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"

// newProductionFactory constructs the native, platform-protected composition.
// It does not manufacture installation state: a pristine or unbound host is
// reported by the protected resolver as AM_BOOTSTRAP_NOT_FOUND.
func newProductionFactory() launcher.MCPFactory { return launcher.NewNativeFactory() }
