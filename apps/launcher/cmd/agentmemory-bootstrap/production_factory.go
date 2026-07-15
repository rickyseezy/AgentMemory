package main

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"

func newProductionFactory() launcher.MCPFactory { return launcher.NewPortableFactory() }
