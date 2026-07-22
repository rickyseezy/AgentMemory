//go:build darwin || linux

package mcpsessionhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPF005PathResolverRecordsLogicalRealAndDeviceIdentityWithoutRawFingerprint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	workspace := filepath.Join(root, "project [α];$(false)")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	alias := filepath.Join(root, "workspace-link")
	if err := os.Symlink(workspace, alias); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	resolver, err := NewPathIdentityResolver([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewPathIdentityResolver() error = %v", err)
	}

	identity, err := resolver.Resolve(context.Background(), alias)

	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	logical, _ := filepath.Abs(alias)
	resolved, _ := filepath.EvalSymlinks(logical)
	if identity.LogicalPath != logical || identity.RealPath != resolved ||
		!strings.HasPrefix(identity.DeviceIdentity, "dev:") || len(identity.PathFingerprint) != 64 {
		t.Fatalf("Resolve() = %#v", identity)
	}
	if strings.Contains(identity.PathFingerprint, root) || strings.Contains(identity.PathFingerprint, "project") {
		t.Fatalf("fingerprint leaked path: %q", identity.PathFingerprint)
	}
}

func TestPF005PathResolverKeySeparatesFingerprintAndRejectsUnsafeSources(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first, err := NewPathIdentityResolver([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatalf("NewPathIdentityResolver(first) error = %v", err)
	}
	second, err := NewPathIdentityResolver([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatalf("NewPathIdentityResolver(second) error = %v", err)
	}
	left, err := first.Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve(first) error = %v", err)
	}
	right, err := second.Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve(second) error = %v", err)
	}
	if left.PathFingerprint == right.PathFingerprint {
		t.Fatal("different installation keys produced the same path fingerprint")
	}

	regular := filepath.Join(root, "file")
	if err := os.WriteFile(regular, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatalf("Symlink(loop) error = %v", err)
	}
	for _, path := range []string{"", "relative", regular, loop, filepath.Join(root, "missing")} {
		if _, err := first.Resolve(context.Background(), path); err == nil {
			t.Fatalf("Resolve(%q) error = nil", path)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := first.Resolve(cancelled, root); err == nil {
		t.Fatal("Resolve(cancelled) error = nil")
	}
	if _, err := NewPathIdentityResolver(nil); err == nil {
		t.Fatal("NewPathIdentityResolver(nil) error = nil")
	}
}

func TestPF005PathResolverTreatsShellMetacharacterAndUnicodeCorpusAsOpaque(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	resolver, err := NewPathIdentityResolver([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"space directory",
		"semi;colon",
		"dollar$(touch never)",
		"back`tick`",
		"quote\"single'comma,",
		"日本語-🚀-e\u0301",
		"brackets[abc]{def}",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := resolver.Resolve(t.Context(), path)
			if err != nil || identity.RealPath != resolved || len(identity.PathFingerprint) != 64 {
				t.Fatalf("Resolve(%q)=%+v/%v", path, identity, err)
			}
		})
	}
}
