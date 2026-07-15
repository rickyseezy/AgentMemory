//go:build windows

package nativepackage

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"

// Format returns the only certified Windows package format.
func Format() (releasepublication.Format, error) {
	return packageFormatFor("windows", nil)
}
