//go:build linux || (darwin && cgo)

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NativeOperationStateFenceSerializesAndHonorsCancellation(t *testing.T) {
	t.Parallel()

	locator, err := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := NewNativeOperationStateFence(locator)
	second, _ := NewNativeOperationStateFence(locator)
	operationID, _ := install.NewOperationID("native-state-fence")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- first.WithExclusive(context.Background(), operationID, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	var invoked atomic.Bool
	err = second.WithExclusive(ctx, operationID, func() error {
		invoked.Store(true)
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || invoked.Load() {
		t.Fatalf("contended fence error/invoked=%v/%v", err, invoked.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := second.WithExclusive(context.Background(), operationID, func() error {
		invoked.Store(true)
		return nil
	}); err != nil || !invoked.Load() {
		t.Fatalf("released fence error/invoked=%v/%v", err, invoked.Load())
	}
}

func TestPF001NativeOperationStateFenceRejectsInvalidBinding(t *testing.T) {
	t.Parallel()
	if _, err := NewNativeOperationStateFence(nil); err == nil {
		t.Fatal("nil locator accepted")
	}
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "state"))
	fence, _ := NewNativeOperationStateFence(locator)
	//lint:ignore SA1012 Deliberate nil-context attack proves the native fence fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := fence.WithExclusive(nil, install.OperationID{}, nil); err == nil {
		t.Fatal("invalid fence binding accepted")
	}
}

func TestPF001NativeOperationStateFenceRejectsRedirectedControlledAncestor(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	attackerRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(attackerRoot, "AgentMemory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		filepath.Join(attackerRoot, "AgentMemory"),
		filepath.Join(configRoot, "AgentMemory"),
	); err != nil {
		t.Fatal(err)
	}
	locator, err := bootstrapadapter.NewOperationLocator(configRoot)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := NewNativeOperationStateFence(locator)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("redirected-state-fence")
	invoked := false
	if err := fence.WithExclusive(context.Background(), operationID, func() error {
		invoked = true
		return nil
	}); err == nil || invoked {
		t.Fatalf("redirected controlled ancestor error/invoked=%v/%v", err, invoked)
	}
}
