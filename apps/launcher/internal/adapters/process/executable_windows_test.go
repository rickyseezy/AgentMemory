//go:build windows

package process

import (
	"context"
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
