package mcpsessioncredential

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// FileStore writes session credentials only beneath one pre-created protected root.
type FileStore struct{ root string }

// NewFileStore binds an absolute, clean credential root; native methods prove it on every call.
func NewFileStore(root string) (*FileStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		strings.ContainsAny(root, "\x00\r\n") {
		return nil, errCredentialAuthority
	}
	return &FileStore{root: root}, nil
}

// Write atomically publishes an exact 32-byte owner-protected credential file.
func (s *FileStore) Write(ctx context.Context, sessionID string, secret []byte) (string, error) {
	if s == nil || ctx == nil || !mcpsessionID(sessionID) || len(secret) != credentialBytes {
		return "", errCredentialAuthority
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return writeCredentialFile(ctx, s.root, sessionID+".credential", secret)
}

// Delete removes only a verified file whose bytes match the expected digest.
func (s *FileStore) Delete(ctx context.Context, path, digest string) error {
	if s == nil || ctx == nil || !validStorePath(s.root, path) ||
		!mcpsessionDigest(digest) {
		return errCredentialAuthority
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := deleteCredentialFile(ctx, s.root, filepath.Base(path), digest); err != nil {
		if errors.Is(err, errCredentialMissing) {
			return nil
		}
		return err
	}
	return nil
}

func validStorePath(root, path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Dir(path) != root {
		return false
	}
	leaf := filepath.Base(path)
	return strings.HasSuffix(leaf, ".credential") &&
		mcpsessionID(strings.TrimSuffix(leaf, ".credential"))
}

func mcpsessionID(value string) bool {
	return len(value) == 36 && value[14] == '7' && strings.ContainsRune("89ab", rune(value[19])) &&
		canonicalUUID(value)
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func mcpsessionDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

var errCredentialMissing = errors.New("PF-005 credential file is absent")

var _ ProtectedStore = (*FileStore)(nil)
