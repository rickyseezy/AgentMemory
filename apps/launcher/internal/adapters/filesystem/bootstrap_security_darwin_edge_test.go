//go:build darwin && cgo

package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001DarwinControlledDirectoryRejectsMalformedAndUnavailableBoundaries(t *testing.T) {
	t.Parallel()
	validSegment := "sha256-" + strings.Repeat("a", darwinOperationDirectoryDigestLength)
	for name, paths := range map[string][2]string{
		"empty root":         {"", "/tmp/AgentMemory/bootstrap/" + validSegment},
		"relative root":      {"relative", "/tmp/AgentMemory/bootstrap/" + validSegment},
		"outside tree":       {"/tmp/config", "/tmp/config/other/bootstrap/" + validSegment},
		"invalid digest":     {"/tmp/config", "/tmp/config/AgentMemory/bootstrap/sha256-xyz"},
		"additional segment": {"/tmp/config", "/tmp/config/AgentMemory/bootstrap/" + validSegment + "/extra"},
	} {
		name, paths := name, paths
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := darwinControlledPath(paths[0], paths[1]); !errors.Is(err, bootstrapport.ErrIntegrity) {
				t.Fatalf("darwinControlledPath() error = %v", err)
			}
		})
	}

	missingRoot := filepath.Join(t.TempDir(), "missing")
	missingOperation := filepath.Join(missingRoot, "AgentMemory", "bootstrap", validSegment)
	if err := verifyDarwinOperationDirectory(context.Background(), missingRoot, missingOperation); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing configuration boundary error = %v", err)
	}

	fileRoot := filepath.Join(t.TempDir(), "config-file")
	if err := os.WriteFile(fileRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileOperation := filepath.Join(fileRoot, "AgentMemory", "bootstrap", validSegment)
	if err := verifyDarwinOperationDirectory(context.Background(), fileRoot, fileOperation); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("file configuration boundary error = %v", err)
	}

	root := newDarwinTestConfigRoot(t)
	operation := filepath.Join(root, "AgentMemory", "bootstrap", validSegment)
	if err := verifyDarwinOperationDirectory(context.Background(), root, operation); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing controlled child error = %v", err)
	}
	if _, _, err := ensureDarwinControlledChild(context.Background(), nil, root, "AgentMemory", true); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("nil controlled parent error = %v", err)
	}

	closedRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := closedRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureDarwinControlledChild(context.Background(), closedRoot, root, "AgentMemory", true); err == nil {
		t.Fatal("closed controlled parent was accepted")
	}

	unsafeRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unsafeRoot.Close() }()
	if err := os.WriteFile(filepath.Join(root, "AgentMemory"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureDarwinControlledChild(context.Background(), unsafeRoot, root, "AgentMemory", false); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("non-directory controlled child error = %v", err)
	}
}

func TestPF001DarwinRollbackAnchorRecordRejectsEachPersistedBindingMutation(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-record-machine", "darwin-record-user")
	operationID, _ := install.NewOperationID("darwin-record-mutation")
	anchor, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("state")))
	key := bytes.Repeat([]byte{0x43}, sha256.Size)
	valid, err := encodeDarwinAnchorRecord(anchor, key)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func([]byte){
		"format":    func(record []byte) { record[0] ^= 0xff },
		"operation": func(record []byte) { record[16] ^= 0xff },
		"owner":     func(record []byte) { record[16+sha256.Size] ^= 0xff },
		"zero sequence": func(record []byte) {
			sequenceOffset := 16 + sha256.Size*3
			binary.BigEndian.PutUint64(record[sequenceOffset:sequenceOffset+8], 0)
		},
		"authentication": func(record []byte) { record[len(record)-1] ^= 0xff },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "anchor.bin")
			record := append([]byte(nil), valid...)
			mutate(record)
			if err := os.WriteFile(path, record, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readDarwinAnchorRecord(context.Background(), path, operationID, owner, key); !errors.Is(err, bootstrapport.ErrIntegrity) {
				t.Fatalf("mutated anchor error = %v", err)
			}
		})
	}

	t.Run("wrong operation argument", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "anchor.bin")
		if err := os.WriteFile(path, valid, 0o600); err != nil {
			t.Fatal(err)
		}
		otherOperation, _ := install.NewOperationID("darwin-record-other-operation")
		if _, err := readDarwinAnchorRecord(context.Background(), path, otherOperation, owner, key); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("wrong operation error = %v", err)
		}
	})
}

func TestPF001DarwinRollbackAnchorRejectsInvalidTransitionsAndDependencyFailures(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin-edge-machine", "darwin-edge-user")
	operationID, _ := install.NewOperationID("darwin-anchor-edge")
	anchor, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("edge")))
	keyRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("edge-key")))

	ownerFailure := errors.New("owner lookup failed")
	store, _ := NewDarwinFileRollbackAnchorStore(locator, darwinOperationKeyStub{ref: keyRef}, darwinFilesystemOwnerStub{err: ownerFailure})
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, ownerFailure) {
		t.Fatalf("owner lookup error = %v", err)
	}

	store, _ = NewDarwinFileRollbackAnchorStore(locator, darwinOperationKeyStub{ref: keyRef}, darwinFilesystemOwnerStub{owner: owner})
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing operation directory load error = %v", err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, install.OwnerBinding{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero owner load error = %v", err)
	}
	if _, err := store.Load(context.Background(), keyRef, install.OperationID{}, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation load error = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, math.MaxUint64, anchor); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("overflowing sequence error = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, anchor); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("non-successor sequence error = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, mustDarwinAnchor(t, operationID, owner, 2)); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("missing predecessor error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ignoringCancellation, _ := NewDarwinFileRollbackAnchorStore(
		locator,
		darwinOperationKeyStub{ref: keyRef},
		darwinIgnoringContextOwnerStub{owner: owner},
	)
	if err := ignoringCancellation.Advance(cancelled, keyRef, 0, anchor); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled advance error = %v", err)
	}

	keyFailure := errors.New("key access failed")
	failingKeys, _ := NewDarwinFileRollbackAnchorStore(
		locator,
		darwinOperationKeyStub{ref: keyRef, useErr: keyFailure},
		darwinFilesystemOwnerStub{owner: owner},
	)
	if err := failingKeys.Advance(context.Background(), keyRef, 0, anchor); !errors.Is(err, keyFailure) {
		t.Fatalf("key access error = %v", err)
	}
	if err := failingKeys.ConfirmDurable(context.Background(), keyRef, anchor); !errors.Is(err, keyFailure) {
		t.Fatalf("confirmation key error = %v", err)
	}

	anchorPath, _ := locator.RollbackAnchorPath(operationID)
	if err := os.WriteFile(anchorPath, bytes.Repeat([]byte{0xff}, darwinAnchorRecordSize), 0o600); err != nil {
		t.Fatal(err)
	}
	second := mustDarwinAnchor(t, operationID, owner, 2)
	if err := store.Advance(context.Background(), keyRef, 1, second); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("corrupt predecessor error = %v", err)
	}
}

func TestPF001DarwinOperationJournalRejectsInvalidKeyCallbackBehavior(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	operationID, _ := install.NewOperationID("darwin-operation-key-callback")
	owner, _ := install.BindOwner("darwin-callback-machine", "darwin-callback-user")
	keyRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("darwin-callback-key")))
	operationDirectory, _ := locator.OperationDirectory(operationID)
	path, _ := locator.JournalPath(operationID)

	journal := func(keys bootstrapport.OperationKeySource) *darwinOperationKeyJournal {
		return &darwinOperationKeyJournal{
			configRoot:         root,
			operationDirectory: operationDirectory,
			path:               path,
			keys:               keys,
			keyRef:             keyRef,
			operationID:        operationID,
			owner:              owner,
		}
	}
	if err := journal(darwinOperationKeyStub{ref: keyRef}).withJournal(context.Background(), nil); err == nil {
		t.Fatal("nil journal consumer was accepted")
	}
	if err := journal(darwinOperationKeyStub{ref: keyRef}).validateKeyAccess(context.Background()); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("missing controlled directory error = %v", err)
	}
	if err := ensureDarwinOperationDirectory(context.Background(), root, operationDirectory); err != nil {
		t.Fatal(err)
	}
	if err := journal(darwinShortKeySource{ref: keyRef}).validateKeyAccess(context.Background()); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("short HMAC key error = %v", err)
	}
	if err := journal(darwinDoubleCallbackKeySource{ref: keyRef}).validateKeyAccess(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "more than once") {
		t.Fatalf("double key callback error = %v", err)
	}
}

func TestPF001DarwinProtectedAnchorFileRejectsUnsafeObjects(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x71}, sha256.Size)
	owner, _ := install.BindOwner("darwin-file-machine", "darwin-file-user")
	operationID, _ := install.NewOperationID("darwin-file-attacks")
	anchor := mustDarwinAnchor(t, operationID, owner, 1)
	record, _ := encodeDarwinAnchorRecord(anchor, key)

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := readDarwinProtectedFile(context.Background(), missing, len(record)); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing protected file error = %v", err)
	}

	for name, prepare := range map[string]func(*testing.T, string){
		"directory": func(t *testing.T, path string) { t.Helper(); mustMkdirDarwinEdge(t, path, 0o700) },
		"unsafe mode": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, record, 0o644); err != nil { //nolint:gosec // G306: deliberate unsafe-permission fixture.
				t.Fatal(err)
			}
		},
		"wrong size": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, record[:len(record)-1], 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symbolic link": func(t *testing.T, path string) {
			t.Helper()
			target := path + ".target"
			if err := os.WriteFile(target, record, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		name, prepare := name, prepare
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "anchor.bin")
			prepare(t, path)
			if _, err := readDarwinProtectedFile(context.Background(), path, len(record)); !errors.Is(err, bootstrapport.ErrIntegrity) {
				t.Fatalf("unsafe protected file error = %v", err)
			}
		})
	}

	unsafeTarget := filepath.Join(t.TempDir(), "anchor.bin")
	if err := os.WriteFile(unsafeTarget, []byte("attacker"), 0o644); err != nil { //nolint:gosec // G306: deliberate unsafe-permission fixture.
		t.Fatal(err)
	}
	if err := replaceDarwinProtectedFile(context.Background(), unsafeTarget, record); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("unsafe replacement target error = %v", err)
	}

	missingParent := filepath.Join(t.TempDir(), "missing", "anchor.bin")
	if err := replaceDarwinProtectedFile(context.Background(), missingParent, record); err == nil {
		t.Fatal("replacement beneath a missing parent succeeded")
	}
	if err := verifyDarwinProtectedPath(context.Background(), missing, record); err == nil {
		t.Fatal("missing protected replacement verified")
	}
	if err := syncDarwinProtectedFile(context.Background(), missing); err == nil {
		t.Fatal("missing protected replacement synchronized")
	}

	changed := filepath.Join(t.TempDir(), "changed.bin")
	if err := os.WriteFile(changed, record, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDarwinProtectedPath(context.Background(), changed, []byte("different")); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("changed protected contents error = %v", err)
	}

	if err := verifyPlatformDescriptor(context.Background(), nil); err == nil {
		t.Fatal("nil ACL descriptor was accepted")
	}
	if err := platformDurableSync(nil); err == nil {
		t.Fatal("nil durability descriptor was accepted")
	}
	closed, err := os.Open(changed) //nolint:gosec // G304: test-owned fixed temporary path.
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyPlatformDescriptor(context.Background(), closed); err == nil {
		t.Fatal("closed ACL descriptor was accepted")
	}
	if err := platformDurableSync(closed); err == nil {
		t.Fatal("closed durability descriptor was accepted")
	}

	temporaryRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := temporaryRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createProtectedRootTemporary(context.Background(), temporaryRoot, ".temporary-"); err == nil {
		t.Fatal("closed temporary root was accepted")
	}
}

func mustDarwinAnchor(
	t *testing.T,
	operationID install.OperationID,
	owner install.OwnerBinding,
	sequence uint64,
) install.RollbackAnchor {
	t.Helper()
	anchor, err := install.NewRollbackAnchor(operationID, owner, sequence, install.DigestBytes([]byte("darwin-edge-state")))
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

func mustMkdirDarwinEdge(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
}

type darwinIgnoringContextOwnerStub struct{ owner install.OwnerBinding }

func (s darwinIgnoringContextOwnerStub) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, nil
}

type darwinShortKeySource struct{ ref install.BootstrapKeyRef }

func (s darwinShortKeySource) Ensure(
	context.Context,
	install.OperationID,
	install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	return s.ref, nil
}

func (darwinShortKeySource) UseHMACKey(
	_ context.Context,
	_ install.BootstrapKeyRef,
	_ install.OperationID,
	_ install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	return consumer([]byte("too-short"))
}

type darwinDoubleCallbackKeySource struct{ ref install.BootstrapKeyRef }

func (s darwinDoubleCallbackKeySource) Ensure(
	context.Context,
	install.OperationID,
	install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	return s.ref, nil
}

func (darwinDoubleCallbackKeySource) UseHMACKey(
	_ context.Context,
	_ install.BootstrapKeyRef,
	_ install.OperationID,
	_ install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if err := consumer(bytes.Repeat([]byte{0x17}, sha256.Size)); err != nil {
		return err
	}
	return consumer(bytes.Repeat([]byte{0x17}, sha256.Size))
}
