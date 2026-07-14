//go:build darwin

package filesystem

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
)

const darwinOperationDirectoryDigestLength = 64

// ensureDarwinOperationDirectory creates and proves the three owner-controlled
// components below the platform user-config boundary. It walks one component
// at a time through descriptor-anchored os.Root values so a symlink or path
// substitution cannot redirect later journal and rollback-anchor operations.
func ensureDarwinOperationDirectory(ctx context.Context, configRoot, operationDirectory string) error {
	return walkDarwinOperationDirectory(ctx, configRoot, operationDirectory, true)
}

func verifyDarwinOperationDirectory(ctx context.Context, configRoot, operationDirectory string) error {
	return walkDarwinOperationDirectory(ctx, configRoot, operationDirectory, false)
}

func walkDarwinOperationDirectory(ctx context.Context, configRoot, operationDirectory string, create bool) error {
	rootPath, components, err := darwinControlledPath(configRoot, operationDirectory)
	if err != nil {
		return err
	}
	// configRoot is the platform-selected user configuration boundary. It may
	// carry system-managed ACLs, so only ownership and final-component no-link
	// identity are required there; every AgentMemory-owned child is stricter.
	if create {
		if err := os.MkdirAll(rootPath, 0o700); err != nil {
			return fmt.Errorf("create macOS configuration boundary: %w", err)
		}
	}
	rootInfo, err := os.Lstat(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		return bootstrapport.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("inspect macOS configuration boundary: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return darwinDirectoryIntegrity("configuration boundary is not a real directory", nil)
	}
	if err := verifyCurrentOwner(rootInfo, "inspect_darwin_config_root"); err != nil {
		return darwinDirectoryIntegrity("configuration boundary owner is unsafe", err)
	}

	currentRoot, err := os.OpenRoot(rootPath)
	if err != nil {
		return darwinDirectoryIntegrity("configuration boundary cannot be anchored", err)
	}
	defer func() { _ = currentRoot.Close() }()
	openedRootInfo, err := currentRoot.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRootInfo) {
		return darwinDirectoryIntegrity("configuration boundary changed while opening", err)
	}
	currentPath := rootPath
	for _, component := range components {
		nextRoot, nextPath, walkError := ensureDarwinControlledChild(ctx, currentRoot, currentPath, component, create)
		if walkError != nil {
			return walkError
		}
		if closeError := currentRoot.Close(); closeError != nil {
			_ = nextRoot.Close()
			return fmt.Errorf("close macOS controlled-directory parent: %w", closeError)
		}
		currentRoot = nextRoot
		currentPath = nextPath
	}

	finalInfo, err := currentRoot.Stat(".")
	if err != nil {
		return darwinDirectoryIntegrity("operation directory descriptor became unavailable", err)
	}
	pathInfo, err := os.Lstat(operationDirectory)
	if err != nil || !os.SameFile(finalInfo, pathInfo) {
		return darwinDirectoryIntegrity("operation directory path was substituted", err)
	}
	currentRootInfo, err := os.Lstat(rootPath)
	if err != nil || !os.SameFile(rootInfo, currentRootInfo) {
		return darwinDirectoryIntegrity("configuration boundary path was substituted", err)
	}
	return nil
}

func darwinControlledPath(configRoot, operationDirectory string) (string, []string, error) {
	if strings.TrimSpace(configRoot) == "" || strings.TrimSpace(operationDirectory) == "" ||
		!filepath.IsAbs(configRoot) || !filepath.IsAbs(operationDirectory) {
		return "", nil, darwinDirectoryIntegrity("absolute configuration and operation paths are required", nil)
	}
	rootPath := filepath.Clean(configRoot)
	directoryPath := filepath.Clean(operationDirectory)
	relative, err := filepath.Rel(rootPath, directoryPath)
	if err != nil {
		return "", nil, darwinDirectoryIntegrity("operation path cannot be related to its configuration boundary", err)
	}
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) != 3 || components[0] != "AgentMemory" || components[1] != "bootstrap" ||
		!validDarwinOperationDirectorySegment(components[2]) {
		return "", nil, darwinDirectoryIntegrity("operation path is outside the closed AgentMemory bootstrap tree", nil)
	}
	return rootPath, components, nil
}

func validDarwinOperationDirectorySegment(value string) bool {
	const prefix = "sha256-"
	if len(value) != len(prefix)+darwinOperationDirectoryDigestLength || !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	return err == nil && len(decoded) == darwinOperationDirectoryDigestLength/2
}

func ensureDarwinControlledChild(
	ctx context.Context,
	parent *os.Root,
	parentPath string,
	name string,
	create bool,
) (*os.Root, string, error) {
	if parent == nil || name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, "", darwinDirectoryIntegrity("invalid controlled-directory component", nil)
	}
	created := false
	expected, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, "", bootstrapport.ErrNotFound
		}
		createError := parent.Mkdir(name, 0o700)
		if createError != nil && !errors.Is(createError, os.ErrExist) {
			return nil, "", fmt.Errorf("create macOS controlled directory: %w", createError)
		}
		created = createError == nil
		expected, err = parent.Lstat(name)
	}
	if err != nil {
		return nil, "", fmt.Errorf("inspect macOS controlled directory: %w", err)
	}
	if !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 || expected.Mode().Perm()&0o077 != 0 {
		return nil, "", darwinDirectoryIntegrity("controlled component is not an owner-only real directory", nil)
	}
	if err := verifyCurrentOwner(expected, "inspect_darwin_controlled_directory"); err != nil {
		return nil, "", darwinDirectoryIntegrity("controlled component owner is unsafe", err)
	}

	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, "", darwinDirectoryIntegrity("controlled component cannot be descriptor-anchored", err)
	}
	fail := func(message string, cause error) (*os.Root, string, error) {
		_ = child.Close()
		return nil, "", darwinDirectoryIntegrity(message, cause)
	}
	openedInfo, err := child.Stat(".")
	if err != nil || !os.SameFile(expected, openedInfo) {
		return fail("controlled component changed while opening", err)
	}
	descriptor, err := child.Open(".")
	if err != nil {
		return fail("controlled component descriptor is unavailable", err)
	}
	if err := verifyOpenedProtectedObject(
		ctx,
		descriptor,
		expected,
		"verify_darwin_controlled_directory",
	); err != nil {
		_ = descriptor.Close()
		return fail("controlled component permission or ACL proof failed", err)
	}
	if created {
		if err := platformDurableSync(descriptor); err != nil {
			_ = descriptor.Close()
			return fail("new controlled component could not be made durable", err)
		}
		parentDescriptor, openError := parent.Open(".")
		if openError != nil {
			_ = descriptor.Close()
			return fail("controlled parent descriptor is unavailable", openError)
		}
		if syncError := platformDurableSync(parentDescriptor); syncError != nil {
			_ = parentDescriptor.Close()
			_ = descriptor.Close()
			return fail("controlled parent entry could not be made durable", syncError)
		}
		if closeError := parentDescriptor.Close(); closeError != nil {
			_ = descriptor.Close()
			return fail("controlled parent descriptor could not close", closeError)
		}
	}
	if err := descriptor.Close(); err != nil {
		return fail("controlled component descriptor could not close", err)
	}

	anchoredInfo, err := parent.Lstat(name)
	if err != nil || !os.SameFile(expected, anchoredInfo) {
		return fail("controlled component was substituted beneath its parent", err)
	}
	childPath := filepath.Join(parentPath, name)
	pathInfo, err := os.Lstat(childPath)
	if err != nil || !os.SameFile(expected, pathInfo) {
		return fail("controlled component path was substituted", err)
	}
	return child, childPath, nil
}

func darwinDirectoryIntegrity(message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", bootstrapport.ErrIntegrity, message)
	}
	return fmt.Errorf("%w: %s: %w", bootstrapport.ErrIntegrity, message, cause)
}
