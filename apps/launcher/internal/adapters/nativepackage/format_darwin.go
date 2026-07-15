//go:build darwin

package nativepackage

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"

// Format returns the only certified macOS package format.
func Format() (releasepublication.Format, error) {
	return packageFormatFor("darwin", nil)
}
