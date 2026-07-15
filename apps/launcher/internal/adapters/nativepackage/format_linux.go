//go:build linux

package nativepackage

import (
	"io"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

// Format selects only the package family declared by the
// root-owned Linux os-release authority.
func Format() (releasepublication.Format, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", errPackageFormat
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return "", errPackageFormat
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return "", errPackageFormat
	}
	return packageFormatFor("linux", raw)
}
