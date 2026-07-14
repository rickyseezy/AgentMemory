//go:build windows

package dockercli

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func createPrivateExecutionDirectory(ctx context.Context, path string) error {
	return windowssecurity.CreatePrivateDirectory(ctx, path)
}

func createPrivateExecutionChild(
	ctx context.Context,
	directory *os.File,
	name string,
	_ string,
) (*os.File, bool, error) {
	return windowssecurity.OpenOrCreatePrivateChildSharedRead(ctx, directory, name)
}

func openPrivateExecutionFile(ctx context.Context, path string) (*os.File, error) {
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, false)
	return file, err
}

func openPrivateExecutionDirectory(ctx context.Context, path string) (*os.File, error) {
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, true)
	return file, err
}

func sealExecutionFile(*os.File) error      { return nil }
func sealExecutionDirectory(*os.File) error { return nil }

func syncExecutionDirectory(directory *os.File) error {
	return windowssecurity.Flush(directory)
}

func sealedExecutionMaterialization(directory, secret, environment os.FileInfo) bool {
	return directory != nil && directory.IsDir() && secret != nil && secret.Mode().IsRegular() &&
		environment != nil && environment.Mode().IsRegular()
}

func privateExecutionMaterializationPath(path string, wantDirectory bool) bool {
	return privateComposePath(path, wantDirectory)
}

type windowsExecutionAncestorAuthority struct {
	guard *windowssecurity.DirectoryPathGuard
}

func openExecutionAncestorAuthority(ctx context.Context, projectDirectory string) (executionAncestorAuthority, error) {
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, projectDirectory)
	if err != nil {
		return nil, err
	}
	return &windowsExecutionAncestorAuthority{guard: guard}, nil
}

func (a *windowsExecutionAncestorAuthority) verify(ctx context.Context) error {
	if a == nil || a.guard == nil {
		return os.ErrPermission
	}
	return a.guard.Verify(ctx)
}

func (a *windowsExecutionAncestorAuthority) close() error {
	if a == nil || a.guard == nil {
		return nil
	}
	return a.guard.Close()
}
