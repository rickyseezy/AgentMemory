//go:build !windows

package installplanfs

import (
	"os"
	"testing"
)

func securePublishedPlanFile(t *testing.T, _ string, info os.FileInfo) bool {
	t.Helper()
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}
