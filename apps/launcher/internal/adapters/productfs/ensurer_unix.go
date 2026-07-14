//go:build darwin || linux

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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"golang.org/x/sys/unix"
)

const (
	productSecretBytes       = 32
	maximumTemporaryAttempts = 8
)

type unixObjectIdentity struct {
	purpose string
	device  uint64
	inode   uint64
	mode    uint32
	owner   uint32
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
		if !validUnixAbsolutePath(specification.Path()) {
			return productinstall.DirectoryReceipt{}, productinstall.ErrIntegrity
		}
		paths = append(paths, specification.Path())
	}
	managedRoot, err := commonManagedRoot(paths)
	if err != nil {
		return productinstall.DirectoryReceipt{}, err
	}
	uid := uint32(os.Geteuid()) //nolint:gosec // Certified Unix UIDs are unsigned 32-bit values.
	root, err := openOrCreateManagedRoot(ctx, managedRoot, uid)
	if err != nil {
		return productinstall.DirectoryReceipt{}, err
	}
	defer func() { _ = root.Close() }()
	type directoryWork struct {
		index         int
		specification productinstall.DirectorySpec
	}
	work := make([]directoryWork, 0, len(directories))
	for index, specification := range directories {
		work = append(work, directoryWork{index: index, specification: specification})
	}
	sort.Slice(work, func(left, right int) bool {
		leftDepth := strings.Count(work[left].specification.Path(), string(filepath.Separator))
		rightDepth := strings.Count(work[right].specification.Path(), string(filepath.Separator))
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return work[left].specification.Path() < work[right].specification.Path()
	})
	identities := make([]unixObjectIdentity, len(directories))
	var created uint32
	for _, item := range work {
		specification := item.specification
		if err := ctx.Err(); err != nil {
			return productinstall.DirectoryReceipt{}, err
		}
		relative, relativeError := filepath.Rel(managedRoot, specification.Path())
		if relativeError != nil || relative == "." || relative == "" || !validRelativeTree(relative) {
			return productinstall.DirectoryReceipt{}, productinstall.ErrIntegrity
		}
		identity, wasCreated, ensureError := ensurePrivateDescendant(ctx, root, relative, uid)
		if ensureError != nil {
			return productinstall.DirectoryReceipt{}, ensureError
		}
		identity.purpose = string(specification.Purpose())
		identities[item.index] = identity
		if wasCreated {
			created++
		}
	}
	stateDigest := digestDirectoryIdentities(command, identities)
	reused := uint32(len(directories)) - created //nolint:gosec // The closed contract contains exactly six entries.
	return productinstall.NewDirectoryReceiptForAdapter(command, stateDigest, created, reused)
}

func ensureNativeSecrets(
	ctx context.Context,
	command productinstall.SecretCommand,
	fillRandom func([]byte) error,
) (productinstall.SecretReceipt, error) {
	if ctx == nil || !command.Valid() || fillRandom == nil || !validUnixAbsolutePath(command.SecretDirectory()) {
		return productinstall.SecretReceipt{}, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return productinstall.SecretReceipt{}, err
	}
	uid := uint32(os.Geteuid()) //nolint:gosec // Certified Unix UIDs are unsigned 32-bit values.
	root, err := openExistingPrivateDirectory(ctx, command.SecretDirectory(), uid)
	if err != nil {
		return productinstall.SecretReceipt{}, err
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
		if filepath.Dir(specification.Path()) != command.SecretDirectory() ||
			!validSecretLeaf(filepath.Base(specification.Path())) {
			return productinstall.SecretReceipt{}, productinstall.ErrIntegrity
		}
		value, wasCreated, ensureError := ensureSecretFile(
			ctx, root, filepath.Base(specification.Path()), uid, fillRandom,
		)
		if ensureError != nil {
			return productinstall.SecretReceipt{}, ensureError
		}
		values = append(values, value)
		if wasCreated {
			created++
		}
	}
	stateDigest, err := digestSecretState(command, specifications, values)
	if err != nil {
		return productinstall.SecretReceipt{}, err
	}
	reused := uint32(len(specifications)) - created //nolint:gosec // The closed contract contains exactly seven entries.
	return productinstall.NewSecretReceiptForAdapter(command, stateDigest, created, reused)
}

func validUnixAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsRune(path, '\x00')
}

func commonManagedRoot(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", productinstall.ErrIntegrity
	}
	common := paths[0]
	for _, path := range paths[1:] {
		for !pathWithinRoot(common, path) {
			parent := filepath.Dir(common)
			if parent == common {
				return "", productinstall.ErrIntegrity
			}
			common = parent
		}
	}
	if common == string(filepath.Separator) || !validUnixAbsolutePath(common) {
		return "", productinstall.ErrIntegrity
	}
	return common, nil
}

func pathWithinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validRelativeTree(relative string) bool {
	if relative == "" || relative == "." || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return false
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func openOrCreateManagedRoot(ctx context.Context, path string, uid uint32) (*os.File, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unavailable(err)
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, productinstall.ErrUnavailable
	}
	for index, component := range components {
		if err := ctx.Err(); err != nil {
			_ = current.Close()
			return nil, err
		}
		if !validSecretLeaf(component) {
			_ = current.Close()
			return nil, productinstall.ErrIntegrity
		}
		fd, openError := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		created := false
		if errors.Is(openError, unix.ENOENT) {
			if makeError := unix.Mkdirat(int(current.Fd()), component, 0o700); makeError != nil {
				_ = current.Close()
				return nil, classifyPathError(makeError)
			}
			created = true
			if syncError := unix.Fsync(int(current.Fd())); syncError != nil {
				_ = current.Close()
				return nil, unavailable(syncError)
			}
			fd, openError = unix.Openat(
				int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		if openError != nil {
			_ = current.Close()
			return nil, classifyPathError(openError)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return nil, productinstall.ErrUnavailable
		}
		leaf := index == len(components)-1
		if leaf {
			if verifyError := verifyPrivateDirectory(ctx, next, uid); verifyError != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, verifyError
			}
		} else if ancestorError := verifySafeAncestor(next, uid); ancestorError != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, ancestorError
		}
		if created {
			if syncError := unix.Fsync(fd); syncError != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, unavailable(syncError)
			}
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func openExistingPrivateDirectory(ctx context.Context, path string, uid uint32) (*os.File, error) {
	if !validUnixAbsolutePath(path) {
		return nil, productinstall.ErrIntegrity
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unavailable(err)
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, productinstall.ErrUnavailable
	}
	for index, component := range components {
		if err := ctx.Err(); err != nil {
			_ = current.Close()
			return nil, err
		}
		fd, openError := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if openError != nil {
			_ = current.Close()
			return nil, classifyPathError(openError)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return nil, productinstall.ErrUnavailable
		}
		leaf := index == len(components)-1
		if leaf {
			if verifyError := verifyPrivateDirectory(ctx, next, uid); verifyError != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, verifyError
			}
		} else if ancestorError := verifySafeAncestor(next, uid); ancestorError != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, ancestorError
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func ensurePrivateDescendant(
	ctx context.Context,
	managedRoot *os.File,
	relative string,
	uid uint32,
) (unixObjectIdentity, bool, error) {
	rootFD, err := unix.Dup(int(managedRoot.Fd()))
	if err != nil {
		return unixObjectIdentity{}, false, unavailable(err)
	}
	current := os.NewFile(uintptr(rootFD), managedRoot.Name())
	if current == nil {
		_ = unix.Close(rootFD)
		return unixObjectIdentity{}, false, productinstall.ErrUnavailable
	}
	components := strings.Split(relative, string(filepath.Separator))
	leafCreated := false
	for index, component := range components {
		if err := ctx.Err(); err != nil {
			_ = current.Close()
			return unixObjectIdentity{}, false, err
		}
		fd, openError := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		created := false
		if errors.Is(openError, unix.ENOENT) {
			if makeError := unix.Mkdirat(int(current.Fd()), component, 0o700); makeError != nil {
				_ = current.Close()
				return unixObjectIdentity{}, false, classifyPathError(makeError)
			}
			created = true
			if syncError := unix.Fsync(int(current.Fd())); syncError != nil {
				_ = current.Close()
				return unixObjectIdentity{}, false, unavailable(syncError)
			}
			fd, openError = unix.Openat(
				int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		if openError != nil {
			_ = current.Close()
			return unixObjectIdentity{}, false, classifyPathError(openError)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return unixObjectIdentity{}, false, productinstall.ErrUnavailable
		}
		identity, verifyError := privateDirectoryIdentity(ctx, next, uid)
		if verifyError != nil {
			_ = next.Close()
			_ = current.Close()
			return unixObjectIdentity{}, false, verifyError
		}
		if created {
			if syncError := unix.Fsync(fd); syncError != nil {
				_ = next.Close()
				_ = current.Close()
				return unixObjectIdentity{}, false, unavailable(syncError)
			}
		}
		_ = current.Close()
		current = next
		if index == len(components)-1 {
			leafCreated = created
			_ = current.Close()
			return identity, leafCreated, nil
		}
	}
	_ = current.Close()
	return unixObjectIdentity{}, false, productinstall.ErrIntegrity
}

func verifySafeAncestor(directory *os.File, uid uint32) error {
	var state unix.Stat_t
	if directory == nil || unix.Fstat(int(directory.Fd()), &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFDIR {
		return productinstall.ErrIntegrity
	}
	if state.Mode&0o022 != 0 && (state.Uid != 0 || state.Mode&unix.S_ISVTX == 0) {
		return productinstall.ErrIntegrity
	}
	if state.Uid != 0 && state.Uid != uid {
		return productinstall.ErrIntegrity
	}
	return nil
}

func verifyPrivateDirectory(ctx context.Context, directory *os.File, uid uint32) error {
	_, err := privateDirectoryIdentity(ctx, directory, uid)
	return err
}

func privateDirectoryIdentity(
	ctx context.Context,
	directory *os.File,
	uid uint32,
) (unixObjectIdentity, error) {
	if directory == nil {
		return unixObjectIdentity{}, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return unixObjectIdentity{}, err
	}
	var state unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &state); err != nil {
		return unixObjectIdentity{}, unavailable(err)
	}
	if state.Mode&unix.S_IFMT != unix.S_IFDIR || state.Uid != uid || state.Mode&0o777 != 0o700 ||
		state.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return unixObjectIdentity{}, productinstall.ErrIntegrity
	}
	if err := verifyNativeACL(directory); err != nil {
		return unixObjectIdentity{}, err
	}
	if state.Dev < 0 {
		return unixObjectIdentity{}, productinstall.ErrIntegrity
	}
	return unixObjectIdentity{
		device: uint64(state.Dev), // #nosec G115 -- native device identity is proven nonnegative above.
		inode:  state.Ino, mode: uint32(state.Mode), owner: state.Uid,
	}, nil
}

func ensureSecretFile(
	ctx context.Context,
	directory *os.File,
	name string,
	uid uint32,
	fillRandom func([]byte) error,
) ([]byte, bool, error) {
	value, err := readSecretFile(ctx, directory, name, uid)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	generated := make([]byte, productSecretBytes)
	defer clear(generated)
	if err := fillRandom(generated); err != nil {
		return nil, false, unavailable(err)
	}
	for attempt := 0; attempt < maximumTemporaryAttempts; attempt++ {
		temporaryEntropy := make([]byte, 16)
		if err := fillRandom(temporaryEntropy); err != nil {
			clear(temporaryEntropy)
			return nil, false, unavailable(err)
		}
		temporary := fmt.Sprintf(".secret-%x.tmp", temporaryEntropy)
		clear(temporaryEntropy)
		published, publishError := publishSecret(ctx, directory, temporary, name, generated, uid)
		if errors.Is(publishError, unix.EEXIST) {
			continue
		}
		if publishError != nil {
			return nil, false, publishError
		}
		if !published {
			value, readError := readSecretFile(ctx, directory, name, uid)
			return value, false, readError
		}
		value, readError := readSecretFile(ctx, directory, name, uid)
		return value, true, readError
	}
	return nil, false, productinstall.ErrUnavailable
}

func publishSecret(
	ctx context.Context,
	directory *os.File,
	temporary string,
	target string,
	value []byte,
	uid uint32,
) (bool, error) {
	fd, err := unix.Openat(
		int(directory.Fd()), temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return false, classifyPathError(err)
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), temporary, 0)
		return false, productinstall.ErrUnavailable
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(int(directory.Fd()), temporary, 0)
		}
	}()
	if err := writeAll(file, value); err != nil {
		return false, unavailable(err)
	}
	if err := syncNativeFile(file); err != nil {
		return false, unavailable(err)
	}
	if err := unix.Fchmod(fd, 0o400); err != nil {
		return false, unavailable(err)
	}
	if err := syncNativeFile(file); err != nil {
		return false, unavailable(err)
	}
	if err := verifySecretDescriptor(ctx, file, uid, int64(len(value))); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	published, err := publishExclusive(int(directory.Fd()), temporary, target)
	if err != nil {
		return false, classifyPathError(err)
	}
	if !published {
		return false, nil
	}
	removeTemporary = false
	if err := unix.Fsync(int(directory.Fd())); err != nil {
		return false, unavailable(err)
	}
	return true, nil
}

func readSecretFile(ctx context.Context, directory *os.File, name string, uid uint32) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, classifyPathError(err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, productinstall.ErrUnavailable
	}
	defer func() { _ = file.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, unavailable(err)
	}
	if err := verifySecretState(file, before, uid); err != nil {
		return nil, err
	}
	value, err := io.ReadAll(io.LimitReader(file, productSecretBytes+1))
	if err != nil {
		return nil, unavailable(err)
	}
	if len(value) != productSecretBytes {
		clear(value)
		return nil, productinstall.ErrIntegrity
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixObject(before, after) {
		clear(value)
		if err != nil {
			return nil, unavailable(err)
		}
		return nil, productinstall.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func verifySecretDescriptor(ctx context.Context, file *os.File, uid uint32, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var state unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &state); err != nil {
		return unavailable(err)
	}
	if state.Size != size {
		return productinstall.ErrIntegrity
	}
	return verifySecretState(file, state, uid)
}

func verifySecretState(file *os.File, state unix.Stat_t, uid uint32) error {
	if state.Mode&unix.S_IFMT != unix.S_IFREG || state.Uid != uid || state.Mode&0o777 != 0o400 ||
		state.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 || state.Nlink != 1 ||
		state.Size != productSecretBytes {
		return productinstall.ErrIntegrity
	}
	return verifyNativeACL(file)
}

func sameUnixObject(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Uid == right.Uid &&
		left.Mode == right.Mode && left.Nlink == right.Nlink && left.Size == right.Size
}

func digestDirectoryIdentities(
	command productinstall.DirectoryCommand,
	identities []unixObjectIdentity,
) install.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("agentmemory/product-directories-state/v1\x00"))
	_, _ = hash.Write([]byte(command.BindingDigest().String()))
	var encoded [8]byte
	for _, identity := range identities {
		binary.BigEndian.PutUint64(encoded[:], uint64(len(identity.purpose)))
		_, _ = hash.Write(encoded[:])
		_, _ = hash.Write([]byte(identity.purpose))
		binary.BigEndian.PutUint64(encoded[:], identity.device)
		_, _ = hash.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], identity.inode)
		_, _ = hash.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], uint64(identity.mode))
		_, _ = hash.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], uint64(identity.owner))
		_, _ = hash.Write(encoded[:])
	}
	return install.DigestBytes(hash.Sum(nil))
}

func digestSecretState(
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
	if rootIndex < 0 || len(values[rootIndex]) != productSecretBytes {
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

func validSecretLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name &&
		!strings.ContainsRune(name, '\x00')
}

func writeAll(file *os.File, value []byte) error {
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

func classifyPathError(err error) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EISDIR):
		return fmt.Errorf("%w: native path identity changed", productinstall.ErrIntegrity)
	default:
		return unavailable(err)
	}
}

func unavailable(err error) error {
	return fmt.Errorf("%w: native filesystem operation failed: %w", productinstall.ErrUnavailable, err)
}
