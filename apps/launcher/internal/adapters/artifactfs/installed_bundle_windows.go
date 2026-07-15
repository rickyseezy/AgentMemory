//go:build windows

package artifactfs

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/windows"
)

func openBundleDirectory(path string, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureDirectory(path)
	}
	if policy != bundleAccessInstalledReadOnly || path == "" || filepath.Clean(path) != path ||
		windowssecurity.ValidateLocalPath(path) != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	ctx := windowsArtifactContext()
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	opened, _, err := windowssecurity.OpenInstalledReadOnly(ctx, path, true)
	if err != nil {
		return nil, err
	}
	directory, err := relabelWindowsFile(opened, path)
	if err != nil {
		return nil, err
	}
	if err := guard.Verify(ctx); err != nil || !safeBundleDirectoryDescriptor(directory, policy) {
		_ = directory.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return directory, nil
}

//nolint:contextcheck,nolintlint // Installed directory identity/DACL proof is one non-cancelable local transaction.
func safeBundleDirectoryDescriptor(directory *os.File, policy bundleAccessPolicy) bool {
	if policy == bundleAccessOwnerPrivate {
		return safeDirectoryDescriptor(directory)
	}
	if policy != bundleAccessInstalledReadOnly || directory == nil || directory.Name() == "" ||
		filepath.Clean(directory.Name()) != directory.Name() {
		return false
	}
	ctx := windowsArtifactContext()
	identity, err := windowssecurity.VerifyInstalledReadOnlyOpened(ctx, directory, true)
	if err != nil {
		return false
	}
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, directory.Name())
	if err != nil {
		return false
	}
	defer func() { _ = guard.Close() }()
	pathFile, pathIdentity, err := windowssecurity.OpenInstalledReadOnly(ctx, directory.Name(), true)
	if err != nil {
		return false
	}
	closeError := pathFile.Close()
	return closeError == nil && pathIdentity == identity && guard.Verify(ctx) == nil
}

func duplicateBundleDirectory(directory *os.File, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return duplicateSecureDirectory(directory)
	}
	if !safeBundleDirectoryDescriptor(directory, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(
		process, windows.Handle(directory.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}
	result := os.NewFile(uintptr(duplicate), directory.Name())
	if result == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, artifactapp.ErrFetchIntegrity
	}
	if !safeBundleDirectoryDescriptor(result, policy) {
		_ = result.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return result, nil
}

//nolint:contextcheck,nolintlint // Installed child traversal is one retained path/handle proof.
func openBundleChildDirectoryAt(parent *os.File, leaf string, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureChildDirectoryAt(parent, leaf, false)
	}
	if !safeLeaf(leaf) || !safeBundleDirectoryDescriptor(parent, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	ctx := windowsArtifactContext()
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, parent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	path := filepath.Join(parent.Name(), leaf)
	opened, childIdentity, err := windowssecurity.OpenInstalledReadOnly(ctx, path, true)
	if err != nil {
		return nil, err
	}
	child, err := relabelWindowsFile(opened, path)
	if err != nil {
		return nil, err
	}
	parentIdentity, parentError := windowssecurity.VerifyInstalledReadOnlyOpened(ctx, parent, true)
	if parentError != nil || parentIdentity.VolumeSerial != childIdentity.VolumeSerial ||
		!strings.EqualFold(filepath.Join(parent.Name(), leaf), child.Name()) ||
		guard.Verify(ctx) != nil || !safeBundleDirectoryDescriptor(child, policy) {
		_ = child.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return child, nil
}

//nolint:contextcheck,nolintlint // Installed leaf traversal is one retained path/handle/DACL proof.
func openBundleReadLeafAt(directory *os.File, leaf string, policy bundleAccessPolicy) (*secureFile, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureReadLeafAt(directory, leaf)
	}
	if !safeLeaf(leaf) || !safeBundleDirectoryDescriptor(directory, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	ownedDirectory, err := duplicateBundleDirectory(directory, policy)
	if err != nil {
		return nil, err
	}
	ctx := windowsArtifactContext()
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, directory.Name())
	if err != nil {
		_ = ownedDirectory.Close()
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	path := filepath.Join(directory.Name(), leaf)
	file, _, err := windowssecurity.OpenInstalledReadOnly(ctx, path, false)
	if err != nil {
		_ = ownedDirectory.Close()
		return nil, err
	}
	result := &secureFile{
		file: file, directory: ownedDirectory, leaf: leaf,
		bundlePolicy: bundleAccessInstalledReadOnly,
	}
	if err := guard.Verify(ctx); err != nil || result.verifyPathIdentity() != nil {
		result.close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return result, nil
}
