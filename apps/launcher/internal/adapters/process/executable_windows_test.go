//go:build windows

package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPF001WindowsExecutableDirectoryIdentityIgnoresSafeChildChurn(t *testing.T) {
	t.Parallel()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handle, before, err := openWindowsExecutableDirectoryAbsolute(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	if err := os.Mkdir(filepath.Join(directory, "unrelated-child"), 0o700); err != nil {
		t.Fatal(err)
	}
	after, err := windowsExecutableIdentity(windows.Handle(handle.Fd()), true)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("directory object identity changed after safe child churn: %q != %q", before, after)
	}
}

func TestPF001WindowsExecutableDACLRejectsObjectAndCallbackAllowACEForms(t *testing.T) {
	t.Parallel()
	if !supportedWindowsExecutableDACLType(windows.ACCESS_ALLOWED_ACE_TYPE) ||
		!supportedWindowsExecutableDACLType(windows.ACCESS_DENIED_ACE_TYPE) {
		t.Fatal("basic allow/deny ACE types were rejected")
	}
	for _, aceType := range []uint8{
		0x05, // ACCESS_ALLOWED_OBJECT_ACE_TYPE
		0x09, // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		0x0b, // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		0x0d, // SYSTEM_AUDIT_CALLBACK_ACE_TYPE (invalid in a DACL)
		0xff,
	} {
		if supportedWindowsExecutableDACLType(aceType) {
			t.Fatalf("unparsed ACE type %#x was accepted", aceType)
		}
	}
}

func TestPF001WindowsExecutableLeaseCloseReleasesEveryRetainedHandle(t *testing.T) {
	primary, err := os.CreateTemp(t.TempDir(), "primary-*.exe")
	if err != nil {
		t.Fatal(err)
	}
	firstAncestor, err := os.CreateTemp(t.TempDir(), "ancestor-one-*")
	if err != nil {
		_ = primary.Close()
		t.Fatal(err)
	}
	secondAncestor, err := os.CreateTemp(t.TempDir(), "ancestor-two-*")
	if err != nil {
		_ = primary.Close()
		_ = firstAncestor.Close()
		t.Fatal(err)
	}
	lease := &executableLease{
		file: primary,
		ancestors: []windowsExecutableAncestor{
			{file: firstAncestor},
			{file: secondAncestor},
		},
	}
	lease.close()
	if lease.file != nil || lease.ancestors[0].file != nil || lease.ancestors[1].file != nil {
		t.Fatalf("closed lease retains handles: %#v", lease)
	}
	for _, file := range []*os.File{primary, firstAncestor, secondAncestor} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("retained file %q remains open: %v", file.Name(), err)
		}
	}
	lease.close()
	(*executableLease)(nil).close()
}
