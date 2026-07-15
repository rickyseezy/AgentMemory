//go:build windows

package installplanfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"golang.org/x/sys/windows"
)

func securePublishedPlanFile(t *testing.T, path string, info os.FileInfo) bool {
	t.Helper()
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	file, _, err := windowssecurity.OpenVerified(context.Background(), path, false, false, true)
	if err != nil {
		return false
	}
	return file.Close() == nil
}

func TestWindowsRepositoryReplayWaitsForWinningPublisherFlush(t *testing.T) {
	t.Parallel()
	repository, err := NewRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "replay-wait"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	plan := filesystemPlan(t)
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repository.store.(*windowsStore).root, planFilename(plan.Digest()))
	pointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), filepath.Base(target))
	if file == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("winning publisher handle is invalid")
	}
	released := make(chan error, 1)
	go func() {
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		released <- file.Close()
	}()
	if err := repository.Save(context.Background(), plan); err != nil {
		t.Fatalf("idempotent replay during winning flush: %v", err)
	}
	if closeError := <-released; closeError != nil {
		t.Fatal(closeError)
	}
}
