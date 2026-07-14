// Package bootstrap contains portable bootstrap security adapters. OS-backed
// secret, ownership, and durable-file implementations live behind explicit
// platform build tags.
package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const operationDirectoryPrefix = "sha256-"

// OperationLocator maps operation identities to fixed digest-encoded paths.
// Raw identities never become path components.
type OperationLocator struct {
	root string
}

// NewOperationLocator validates an absolute platform user-config root.
func NewOperationLocator(root string) (*OperationLocator, error) {
	if strings.TrimSpace(root) == "" || strings.IndexByte(root, 0) >= 0 || !filepath.IsAbs(root) {
		return nil, errors.New("bootstrap root must be a non-empty absolute path")
	}
	return &OperationLocator{root: filepath.Clean(root)}, nil
}

// Root returns the normalized configured root.
func (l *OperationLocator) Root() string { return l.root }

// OperationDirectory returns AgentMemory/bootstrap/<digest-encoded-id>.
func (l *OperationLocator) OperationDirectory(operationID install.OperationID) (string, error) {
	if l == nil || strings.TrimSpace(l.root) == "" {
		return "", errors.New("operation locator is not configured")
	}
	if operationID.IsZero() {
		return "", errors.New("operation identity is required")
	}
	canonical := append([]byte("agentmemory:bootstrap-operation-path:v1\x00"), operationID.String()...)
	digest := sha256.Sum256(canonical)
	segment := operationDirectoryPrefix + hex.EncodeToString(digest[:])
	directory := filepath.Join(l.root, "AgentMemory", "bootstrap", segment)
	relative, err := filepath.Rel(l.root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("operation path escaped the configured root")
	}
	return directory, nil
}

// JournalPath returns the closed journal filename for an operation.
func (l *OperationLocator) JournalPath(operationID install.OperationID) (string, error) {
	return l.fixedOperationPath(operationID, "install-operation.json")
}

// KeyPath returns the closed protected-key filename for an operation.
func (l *OperationLocator) KeyPath(operationID install.OperationID) (string, error) {
	return l.fixedOperationPath(operationID, "bootstrap-hmac.key")
}

// RollbackAnchorPath returns the closed anchor filename for an operation.
func (l *OperationLocator) RollbackAnchorPath(operationID install.OperationID) (string, error) {
	return l.fixedOperationPath(operationID, "rollback-anchor.bin")
}

func (l *OperationLocator) fixedOperationPath(operationID install.OperationID, name string) (string, error) {
	directory, err := l.OperationDirectory(operationID)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, name), nil
}
