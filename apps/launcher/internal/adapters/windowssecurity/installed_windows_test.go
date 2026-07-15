//go:build windows

package windowssecurity

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestPF001InstalledWindowsDescriptorAllowsReadButOnlySystemMutation(t *testing.T) {
	t.Parallel()
	valid, err := windows.SecurityDescriptorFromString("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)(A;OICIIO;GA;;;CO)")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledReadOnlyDescriptor(valid); err != nil {
		t.Fatalf("valid installed descriptor error=%v", err)
	}
	for name, sddl := range map[string]string{
		"foreign owner": "O:BUD:(A;;FA;;;SY)(A;;FRFX;;;BU)",
		"foreign write": "O:SYD:(A;;FA;;;SY)(A;;FA;;;BU)",
		"absent dacl":   "O:SY",
	} {
		t.Run(name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyInstalledReadOnlyDescriptor(descriptor); err == nil {
				t.Fatal("unsafe installed descriptor accepted")
			}
		})
	}
}

func TestPF001InstalledWindowsTrustedPrincipalSetIsClosed(t *testing.T) {
	t.Parallel()
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil || !trustedInstalledPrincipal(sid) {
			t.Fatalf("trusted SID %d accepted=%t error=%v", kind, trustedInstalledPrincipal(sid), err)
		}
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if trustedInstalledPrincipal(users) || trustedInstalledPrincipal(nil) {
		t.Fatal("untrusted installed principal accepted")
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil || !trustedInstalledPrincipal(installer) {
		t.Fatalf("TrustedInstaller accepted=%t error=%v", trustedInstalledPrincipal(installer), err)
	}
}
