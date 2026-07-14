//go:build windows

package productfs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"golang.org/x/sys/windows"
)

const (
	windowsProductSecretBytes       = 32
	windowsMaximumTemporaryAttempts = 8
)

type windowsObjectIdentity struct {
	purpose      string
	volumeSerial uint32
	fileIndex    uint64
}

func ensureNativeDirectories(
	ctx context.Context,
	command productinstall.DirectoryCommand,
) (productinstall.DirectoryReceipt, error) {
	if ctx == nil || !command.Valid() {
		return productinstall.DirectoryReceipt{}, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return productinstall.DirectoryReceipt{}, err
	}
	directories := command.Directories()
	paths := make([]string, 0, len(directories))
	for _, specification := range directories {
		if windowssecurity.ValidateLocalPath(specification.Path()) != nil ||
			filepath.Clean(specification.Path()) != specification.Path() {
			return productinstall.DirectoryReceipt{}, productinstall.ErrIntegrity
		}
		paths = append(paths, specification.Path())
	}
	managedRoot, err := commonWindowsManagedRoot(paths)
	if err != nil {
		return productinstall.DirectoryReceipt{}, err
	}
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, managedRoot, managedRoot); err != nil {
		return productinstall.DirectoryReceipt{}, classifyWindowsFilesystemError(err)
	}
	type directoryWork struct {
		index         int
		specification productinstall.DirectorySpec
	}
	work := make([]directoryWork, 0, len(directories))
	for index, specification := range directories {
		work = append(work, directoryWork{index: index, specification: specification})
	}
	sort.Slice(work, func(left, right int) bool {
		leftDepth := strings.Count(work[left].specification.Path(), `\`)
		rightDepth := strings.Count(work[right].specification.Path(), `\`)
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return strings.ToLower(work[left].specification.Path()) < strings.ToLower(work[right].specification.Path())
	})
	identities := make([]windowsObjectIdentity, len(directories))
	var created uint32
	for _, item := range work {
		if err := ctx.Err(); err != nil {
			return productinstall.DirectoryReceipt{}, err
		}
		identity, wasCreated, ensureError := windowssecurity.EnsurePrivateDirectoryTree(
			ctx, managedRoot, item.specification.Path(),
		)
		if ensureError != nil {
			return productinstall.DirectoryReceipt{}, classifyWindowsFilesystemError(ensureError)
		}
		identities[item.index] = windowsObjectIdentity{
			purpose:      string(item.specification.Purpose()),
			volumeSerial: identity.VolumeSerial,
			fileIndex:    identity.FileIndex,
		}
		if wasCreated {
			created++
		}
	}
	stateDigest := digestWindowsDirectoryIdentities(command, identities)
	reused := uint32(len(directories)) - created //nolint:gosec // The closed contract contains exactly six entries.
	return productinstall.NewDirectoryReceiptForAdapter(command, stateDigest, created, reused)
}

func ensureNativeSecrets(
	ctx context.Context,
	command productinstall.SecretCommand,
	fillRandom func([]byte) error,
) (productinstall.SecretReceipt, error) {
	if ctx == nil || !command.Valid() || fillRandom == nil ||
		windowssecurity.ValidateLocalPath(command.SecretDirectory()) != nil ||
		filepath.Clean(command.SecretDirectory()) != command.SecretDirectory() {
		return productinstall.SecretReceipt{}, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return productinstall.SecretReceipt{}, err
	}
	root, _, err := windowssecurity.OpenVerified(ctx, command.SecretDirectory(), true, true, true)
	if err != nil {
		return productinstall.SecretReceipt{}, classifyWindowsFilesystemError(err)
	}
	defer func() { _ = root.Close() }()
	specifications := command.Secrets()
	values := make([][]byte, 0, len(specifications))
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	var created uint32
	for _, specification := range specifications {
		if err := ctx.Err(); err != nil {
			return productinstall.SecretReceipt{}, err
		}
		if !strings.EqualFold(filepath.Dir(specification.Path()), command.SecretDirectory()) ||
			!validWindowsSecretLeaf(filepath.Base(specification.Path())) {
			return productinstall.SecretReceipt{}, productinstall.ErrIntegrity
		}
		value, wasCreated, ensureError := ensureWindowsSecretFile(
			ctx, specification.Path(), fillRandom,
		)
		if ensureError != nil {
			return productinstall.SecretReceipt{}, ensureError
		}
		values = append(values, value)
		if wasCreated {
			created++
		}
	}
	stateDigest, err := digestWindowsSecretState(command, specifications, values)
	if err != nil {
		return productinstall.SecretReceipt{}, err
	}
	reused := uint32(len(specifications)) - created //nolint:gosec // The closed contract contains exactly seven entries.
	return productinstall.NewSecretReceiptForAdapter(command, stateDigest, created, reused)
}

func commonWindowsManagedRoot(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", productinstall.ErrIntegrity
	}
	common := paths[0]
	for _, path := range paths[1:] {
		for !windowsPathWithin(common, path) {
			parent := filepath.Dir(common)
			if strings.EqualFold(parent, common) {
				return "", productinstall.ErrIntegrity
			}
			common = parent
		}
	}
	if strings.EqualFold(common, filepath.VolumeName(common)+`\`) ||
		windowssecurity.ValidateLocalPath(common) != nil {
		return "", productinstall.ErrIntegrity
	}
	return common, nil
}

func windowsPathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, `..\`)
}

func ensureWindowsSecretFile(
	ctx context.Context,
	target string,
	fillRandom func([]byte) error,
) ([]byte, bool, error) {
	value, err := readWindowsSecretFile(ctx, target)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	generated := make([]byte, windowsProductSecretBytes)
	defer clear(generated)
	if err := fillRandom(generated); err != nil {
		return nil, false, windowsUnavailable(err)
	}
	for attempt := 0; attempt < windowsMaximumTemporaryAttempts; attempt++ {
		temporaryEntropy := make([]byte, 16)
		if err := fillRandom(temporaryEntropy); err != nil {
			clear(temporaryEntropy)
			return nil, false, windowsUnavailable(err)
		}
		temporary := filepath.Join(filepath.Dir(target), fmt.Sprintf(".secret-%x.tmp", temporaryEntropy))
		clear(temporaryEntropy)
		file, createError := windowssecurity.CreatePrivateFile(ctx, temporary)
		if errors.Is(createError, windows.ERROR_ALREADY_EXISTS) || errors.Is(createError, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if createError != nil {
			return nil, false, classifyWindowsFilesystemError(createError)
		}
		removeTemporary := true
		func() {
			defer func() {
				_ = file.Close()
				if removeTemporary {
					_ = os.Remove(temporary)
				}
			}()
			if createError = writeWindowsAll(file, generated); createError != nil {
				return
			}
			if createError = windowssecurity.Flush(file); createError != nil {
				return
			}
			if createError = file.Close(); createError != nil {
				return
			}
			var published bool
			published, createError = windowssecurity.AtomicPublishNoReplace(ctx, temporary, target)
			if createError == nil && published {
				removeTemporary = false
			}
			if createError == nil && !published {
				removeTemporary = true
			}
		}()
		if createError != nil {
			return nil, false, classifyWindowsFilesystemError(createError)
		}
		value, readError := readWindowsSecretFile(ctx, target)
		if readError != nil {
			return nil, false, readError
		}
		published := !removeTemporary
		return value, published, nil
	}
	return nil, false, productinstall.ErrUnavailable
}

func readWindowsSecretFile(ctx context.Context, path string) ([]byte, error) {
	file, identity, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, false)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, classifyWindowsFilesystemError(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, windowsUnavailable(err)
	}
	if !info.Mode().IsRegular() || info.Size() != windowsProductSecretBytes || identity.Directory {
		return nil, productinstall.ErrIntegrity
	}
	value, err := io.ReadAll(io.LimitReader(file, windowsProductSecretBytes+1))
	if err != nil {
		return nil, windowsUnavailable(err)
	}
	if len(value) != windowsProductSecretBytes {
		clear(value)
		return nil, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func digestWindowsDirectoryIdentities(
	command productinstall.DirectoryCommand,
	identities []windowsObjectIdentity,
) install.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("agentmemory/product-directories-state/v1\x00"))
	_, _ = hash.Write([]byte(command.BindingDigest().String()))
	var encoded [8]byte
	for _, identity := range identities {
		binary.BigEndian.PutUint64(encoded[:], uint64(len(identity.purpose)))
		_, _ = hash.Write(encoded[:])
		_, _ = hash.Write([]byte(identity.purpose))
		binary.BigEndian.PutUint64(encoded[:], uint64(identity.volumeSerial))
		_, _ = hash.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], identity.fileIndex)
		_, _ = hash.Write(encoded[:])
	}
	return install.DigestBytes(hash.Sum(nil))
}

func digestWindowsSecretState(
	command productinstall.SecretCommand,
	specifications []productinstall.SecretSpec,
	values [][]byte,
) (install.Digest, error) {
	if len(specifications) != len(values) {
		return install.Digest{}, productinstall.ErrIntegrity
	}
	rootIndex := -1
	for index, specification := range specifications {
		if specification.Purpose() == installplan.SecretInstallationRootKey {
			rootIndex = index
			break
		}
	}
	if rootIndex < 0 || len(values[rootIndex]) != windowsProductSecretBytes {
		return install.Digest{}, productinstall.ErrIntegrity
	}
	mac := hmac.New(sha256.New, values[rootIndex])
	_, _ = mac.Write([]byte("agentmemory/product-secrets-state/v1\x00"))
	_, _ = mac.Write([]byte(command.BindingDigest().String()))
	var encoded [8]byte
	for index, specification := range specifications {
		purpose := string(specification.Purpose())
		binary.BigEndian.PutUint64(encoded[:], uint64(len(purpose)))
		_, _ = mac.Write(encoded[:])
		_, _ = mac.Write([]byte(purpose))
		binary.BigEndian.PutUint64(encoded[:], uint64(len(values[index])))
		_, _ = mac.Write(encoded[:])
		_, _ = mac.Write(values[index])
	}
	tag := mac.Sum(nil)
	defer clear(tag)
	return install.DigestBytes(tag), nil
}

func validWindowsSecretLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name &&
		!strings.ContainsAny(name, `/\:`) && !strings.ContainsRune(name, '\x00')
}

func writeWindowsAll(file *os.File, value []byte) error {
	for len(value) > 0 {
		written, err := file.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func classifyWindowsFilesystemError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return windowsUnavailable(err)
	}
	return fmt.Errorf("%w: native protected object could not be verified", productinstall.ErrIntegrity)
}

func windowsUnavailable(err error) error {
	return fmt.Errorf("%w: native Windows filesystem operation failed: %w", productinstall.ErrUnavailable, err)
}
