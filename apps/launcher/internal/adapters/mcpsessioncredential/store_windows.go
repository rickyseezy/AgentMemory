//go:build windows

package mcpsessioncredential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func writeCredentialFile(ctx context.Context, root, leaf string, secret []byte) (string, error) {
	parent, _, err := windowssecurity.OpenVerified(ctx, root, true, true, true)
	if err != nil {
		return "", errCredentialAuthority
	}
	_ = parent.Close()
	digest := sha256.Sum256(secret)
	temporary := filepath.Join(root, "."+leaf+"."+hex.EncodeToString(digest[:8])+".tmp")
	target := filepath.Join(root, leaf)
	file, err := windowssecurity.CreatePrivateFile(ctx, temporary)
	if err != nil {
		return "", errors.New("PF-005 credential temporary file cannot be created")
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if written, writeError := file.Write(secret); writeError != nil || written != len(secret) ||
		windowssecurity.Flush(file) != nil {
		return "", errors.New("PF-005 credential write failed")
	}
	if _, err := windowssecurity.VerifyOpened(ctx, file, false, true); err != nil {
		return "", errCredentialAuthority
	}
	if err := file.Close(); err != nil {
		return "", errors.New("PF-005 credential close failed")
	}
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, temporary, target)
	if err != nil || !published {
		return "", errors.New("PF-005 credential publication failed")
	}
	removeTemporary = false
	verified, _, err := windowssecurity.OpenVerified(ctx, target, false, false, true)
	if err != nil {
		return "", errCredentialAuthority
	}
	defer verified.Close()
	info, err := verified.Stat()
	if err != nil || info.Size() != credentialBytes {
		return "", errCredentialAuthority
	}
	return target, nil
}

func deleteCredentialFile(ctx context.Context, root, leaf, expectedDigest string) error {
	path := filepath.Join(root, leaf)
	file, _, err := windowssecurity.OpenVerifiedForDelete(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		return errCredentialMissing
	}
	if err != nil {
		return errCredentialAuthority
	}
	value, readError := io.ReadAll(io.LimitReader(file, credentialBytes+1))
	if readError != nil || len(value) != credentialBytes {
		_ = file.Close()
		clear(value)
		return errCredentialAuthority
	}
	digest := sha256.Sum256(value)
	clear(value)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		_ = file.Close()
		return errCredentialAuthority
	}
	if err := windowssecurity.DeleteOpenedFile(ctx, file); err != nil {
		_ = file.Close()
		return errors.New("PF-005 credential deletion failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("PF-005 credential deletion close failed")
	}
	return nil
}
