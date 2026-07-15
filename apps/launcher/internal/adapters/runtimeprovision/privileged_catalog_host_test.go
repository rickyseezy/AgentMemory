package runtimeprovision

import "testing"

func TestPF006PrivilegedCatalogHostNormalizesOnlyCanonicalLinuxFacts(t *testing.T) {
	t.Parallel()
	for input, expected := range map[string]string{
		"24.04": "24.4.0",
		"40":    "40.0.0",
		"9.6.2": "9.6.2",
		"01.2":  "1.2.0",
	} {
		actual, err := normalizedPrivilegeCatalogVersion(input)
		if err != nil || actual != expected {
			t.Fatalf("version %q=(%q,%v), want %q", input, actual, err, expected)
		}
	}
	for _, invalid := range []string{"", "1.2.3.4", "v24.04", "1..2"} {
		if actual, err := normalizedPrivilegeCatalogVersion(invalid); err == nil || actual != "" {
			t.Fatalf("invalid version %q=(%q,%v)", invalid, actual, err)
		}
	}
	for input, expected := range map[string]uint64{
		"6.8.0-90-generic":  60_800,
		"5.15.0-1092-azure": 51_500,
	} {
		actual, err := normalizedPrivilegeCatalogBuild(input)
		if err != nil || actual != expected {
			t.Fatalf("build %q=(%d,%v), want %d", input, actual, err, expected)
		}
	}
	for _, invalid := range []string{"", "kernel", "100.1", "6"} {
		if actual, err := normalizedPrivilegeCatalogBuild(invalid); err == nil || actual != 0 {
			t.Fatalf("invalid build %q=(%d,%v)", invalid, actual, err)
		}
	}
}

func TestPF006PrivilegedCatalogHostDetectsExplicitVirtualizationFlags(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{
		[]byte("processor : 0\nflags : fpu vmx sse\n"),
		[]byte("processor : 0\nflags : fpu svm sse\n"),
	} {
		if !privilegedLinuxVirtualizationFlags(raw) {
			t.Fatalf("virtualization flag not detected in %q", raw)
		}
	}
	for _, raw := range [][]byte{nil, []byte("flags : fpu sse\n"), []byte("notflags : vmx\n")} {
		if privilegedLinuxVirtualizationFlags(raw) {
			t.Fatalf("foreign virtualization flag accepted in %q", raw)
		}
	}
}
