//go:build linux

package filesystem

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ensureOperationStateFenceDirectory walks the closed operation path beneath
// the configured boundary one descriptor-relative component at a time. This
// prevents MkdirAll from following a pre-positioned controlled ancestor link.
func ensureOperationStateFenceDirectory(
	ctx context.Context,
	configRoot string,
	operationDirectory string,
) error {
	rootPath, components, err := linuxFenceControlledPath(configRoot, operationDirectory)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rootPath, 0o700); err != nil {
		return fmt.Errorf("create operation-state configuration boundary: %w", err)
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		return fmt.Errorf("inspect operation-state configuration boundary: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("operation-state configuration boundary is not a real directory")
	}
	if err := verifyCurrentOwner(rootInfo, "inspect_operation_state_config_root"); err != nil {
		return err
	}

	currentRoot, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("anchor operation-state configuration boundary: %w", err)
	}
	defer func() { _ = currentRoot.Close() }()
	openedRootInfo, err := currentRoot.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRootInfo) {
		return errors.New("operation-state configuration boundary changed while opening")
	}

	currentPath := rootPath
	for _, component := range components {
		expected, inspectError := currentRoot.Lstat(component)
		if errors.Is(inspectError, os.ErrNotExist) {
			createError := currentRoot.Mkdir(component, 0o700)
			if createError != nil && !errors.Is(createError, os.ErrExist) {
				return fmt.Errorf("create controlled operation-state directory: %w", createError)
			}
			expected, inspectError = currentRoot.Lstat(component)
		}
		if inspectError != nil {
			return fmt.Errorf("inspect controlled operation-state directory: %w", inspectError)
		}
		if !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 || expected.Mode().Perm()&0o077 != 0 {
			return errors.New("controlled operation-state component is not an owner-only real directory")
		}
		if err := verifyCurrentOwner(expected, "inspect_operation_state_directory"); err != nil {
			return err
		}

		child, openError := currentRoot.OpenRoot(component)
		if openError != nil {
			return fmt.Errorf("anchor controlled operation-state directory: %w", openError)
		}
		openedInfo, statError := child.Stat(".")
		if statError != nil || !os.SameFile(expected, openedInfo) {
			_ = child.Close()
			return errors.New("controlled operation-state component changed while opening")
		}
		descriptor, openError := child.Open(".")
		if openError != nil {
			_ = child.Close()
			return fmt.Errorf("open controlled operation-state descriptor: %w", openError)
		}
		verifyError := verifyOpenedProtectedObject(
			ctx, descriptor, expected, "verify_operation_state_directory",
		)
		closeDescriptorError := descriptor.Close()
		if verifyError != nil || closeDescriptorError != nil {
			_ = child.Close()
			return errors.Join(verifyError, closeDescriptorError)
		}
		anchoredInfo, inspectError := currentRoot.Lstat(component)
		if inspectError != nil || !os.SameFile(expected, anchoredInfo) {
			_ = child.Close()
			return errors.New("controlled operation-state component was substituted")
		}
		if closeError := currentRoot.Close(); closeError != nil {
			_ = child.Close()
			return fmt.Errorf("close controlled operation-state parent: %w", closeError)
		}
		currentRoot = child
		currentPath = filepath.Join(currentPath, component)
		pathInfo, pathError := os.Lstat(currentPath)
		if pathError != nil || !os.SameFile(expected, pathInfo) {
			return errors.New("controlled operation-state path was substituted")
		}
	}
	finalInfo, err := currentRoot.Stat(".")
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(operationDirectory)
	if err != nil || !os.SameFile(finalInfo, pathInfo) {
		return errors.New("operation-state directory path was substituted")
	}
	currentRootInfo, err := os.Lstat(rootPath)
	if err != nil || !os.SameFile(rootInfo, currentRootInfo) {
		return errors.New("operation-state configuration boundary was substituted")
	}
	return ctx.Err()
}

func linuxFenceControlledPath(configRoot, operationDirectory string) (string, []string, error) {
	if strings.TrimSpace(configRoot) == "" || strings.TrimSpace(operationDirectory) == "" ||
		!filepath.IsAbs(configRoot) || !filepath.IsAbs(operationDirectory) {
		return "", nil, errors.New("absolute operation-state paths are required")
	}
	rootPath := filepath.Clean(configRoot)
	relative, err := filepath.Rel(rootPath, filepath.Clean(operationDirectory))
	if err != nil {
		return "", nil, fmt.Errorf("relate operation-state directory: %w", err)
	}
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) != 3 || components[0] != "AgentMemory" || components[1] != "bootstrap" ||
		!strings.HasPrefix(components[2], "sha256-") || len(components[2]) != len("sha256-")+64 {
		return "", nil, errors.New("operation-state path is outside the closed bootstrap tree")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(components[2], "sha256-"))
	if err != nil || len(decoded) != 32 {
		return "", nil, errors.New("operation-state path digest is invalid")
	}
	return rootPath, components, nil
}
