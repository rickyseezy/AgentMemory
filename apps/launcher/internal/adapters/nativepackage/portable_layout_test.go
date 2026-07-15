package nativepackage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPF001PortableLayoutResolvesOnlyClosedExecutableRelativeAuthority(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	release := filepath.Join(root, "release")
	for _, directory := range []string{bin, filepath.Join(release, "objects"), filepath.Join(release, "evidence")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(bin, "agentmemory-bootstrap")
	for path, content := range map[string][]byte{
		executable: []byte("bootstrap"),
		filepath.Join(release, "agentmemory-release-publication.json"):          []byte("publication"),
		filepath.Join(release, "agentmemory-release-publication.sigstore.json"): []byte("signature"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	layout, err := resolvePortableLayout(func() (string, error) { return executable, nil })
	canonicalRoot, canonicalError := filepath.EvalSymlinks(root)
	if err != nil || canonicalError != nil || layout.Root != canonicalRoot ||
		layout.Objects != filepath.Join(canonicalRoot, "release", "objects") ||
		layout.Evidence != filepath.Join(canonicalRoot, "release", "evidence") {
		t.Fatalf("resolvePortableLayout() = %+v, %v", layout, err)
	}
	if !validPortableLayout(layout) {
		t.Fatal("portable layout validation failed")
	}
}

func TestPF001PortableLayoutRejectsEveryPathSubstitution(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	executable := filepath.Join(root, "agentmemory-bootstrap")
	if err := os.WriteFile(executable, []byte("bootstrap"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	for name, resolver := range map[string]executablePathResolver{
		"nil":             nil,
		"error":           func() (string, error) { return "", errors.New("private") },
		"relative":        func() (string, error) { return "relative", nil },
		"wrong directory": func() (string, error) { return executable, nil },
		"link":            func() (string, error) { return link, nil },
		"directory":       func() (string, error) { return root, nil },
	} {
		if layout, err := resolvePortableLayout(resolver); layout != (PortableLayout{}) ||
			!errors.Is(err, ErrCandidateIntegrity) {
			t.Fatalf("%s resolve = %+v, %v", name, layout, err)
		}
	}
	if validPortableLayout(PortableLayout{}) {
		t.Fatal("empty layout accepted")
	}
}
