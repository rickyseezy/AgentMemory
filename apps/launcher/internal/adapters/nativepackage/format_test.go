package nativepackage

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001PortablePackageFormatIsSelectedFromClosedPlatformFamilies(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		operatingSystem string
		release         string
		want            releasepublication.Format
	}{
		"macOS":         {operatingSystem: "darwin", want: releasepublication.FormatPKG},
		"Windows":       {operatingSystem: "windows", want: releasepublication.FormatMSI},
		"Ubuntu":        {operatingSystem: "linux", release: "ID=ubuntu\nID_LIKE=debian\n", want: releasepublication.FormatDEB},
		"Debian quoted": {operatingSystem: "linux", release: "ID='debian'\n", want: releasepublication.FormatDEB},
		"Fedora":        {operatingSystem: "linux", release: "ID=fedora\n", want: releasepublication.FormatRPM},
		"RHEL family":   {operatingSystem: "linux", release: "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", want: releasepublication.FormatRPM},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			format, err := packageFormatFor(test.operatingSystem, []byte(test.release))
			if err != nil || format != test.want {
				t.Fatalf("packageFormatFor() = %q, %v", format, err)
			}
		})
	}
}

func TestPF001PortablePackageFormatRejectsAmbiguousOrMalformedAuthority(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"empty":        "",
		"missing ID":   "ID_LIKE=debian\n",
		"unknown":      "ID=arch\n",
		"mixed":        "ID=ubuntu\nID_LIKE=fedora\n",
		"duplicate":    "ID=ubuntu\nID=debian\n",
		"broken":       "ID\n",
		"unterminated": "ID=\"ubuntu\n",
		"shell":        "ID=$(whoami)\n",
	} {
		if format, err := packageFormatFor("linux", []byte(raw)); format != "" || !errors.Is(err, errPackageFormat) {
			t.Fatalf("%s format = %q, %v", name, format, err)
		}
	}
	if format, err := packageFormatFor("plan9", nil); format != "" || !errors.Is(err, errPackageFormat) {
		t.Fatalf("unsupported format = %q, %v", format, err)
	}
	if _, err := parseOSRelease(make([]byte, 64*1024+1)); !errors.Is(err, errPackageFormat) {
		t.Fatalf("oversized parse error = %v", err)
	}
}
