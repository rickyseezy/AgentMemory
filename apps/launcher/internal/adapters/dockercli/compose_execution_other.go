//go:build !darwin && !linux && !windows

package dockercli

import (
	"context"
	"os"
)

func createPrivateExecutionDirectory(context.Context, string) error { return os.ErrPermission }
func createPrivateExecutionChild(context.Context, *os.File, string, string) (*os.File, bool, error) {
	return nil, false, os.ErrPermission
}
func openPrivateExecutionFile(context.Context, string) (*os.File, error) {
	return nil, os.ErrPermission
}
func openPrivateExecutionDirectory(context.Context, string) (*os.File, error) {
	return nil, os.ErrPermission
}
func sealExecutionFile(*os.File) error      { return os.ErrPermission }
func sealExecutionDirectory(*os.File) error { return os.ErrPermission }
func syncExecutionDirectory(*os.File) error { return os.ErrPermission }
func sealedExecutionMaterialization(os.FileInfo, os.FileInfo, os.FileInfo) bool {
	return false
}
func privateExecutionMaterializationPath(string, bool) bool { return false }
func openExecutionAncestorAuthority(context.Context, string) (executionAncestorAuthority, error) {
	return nil, os.ErrPermission
}
