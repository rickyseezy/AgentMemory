//go:build windows

package process

import (
	"testing"

	"golang.org/x/sys/windows"
)

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
