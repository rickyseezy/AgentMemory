package nativepackage

import (
	"os"
	"path/filepath"
	"strings"
)

// PortableLayout is the closed on-disk contract shared by every certified
// host package. All paths are derived from the verified bootstrap executable.
type PortableLayout struct {
	Root                string
	Objects             string
	Evidence            string
	Publication         string
	PublicationSigstore string
}

type executablePathResolver func() (string, error)

// NativePortableLayout resolves the compile-time bootstrap package without
// consulting PATH, environment variables, the working directory, or MCP data.
func NativePortableLayout() (PortableLayout, error) {
	return resolvePortableLayout(os.Executable)
}

func resolvePortableLayout(executable executablePathResolver) (PortableLayout, error) {
	if executable == nil {
		return PortableLayout{}, ErrCandidateIntegrity
	}
	path, err := executable()
	if err != nil || path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return PortableLayout{}, ErrCandidateIntegrity
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return PortableLayout{}, ErrCandidateIntegrity
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical ||
		filepath.Base(filepath.Dir(canonical)) != "bin" {
		return PortableLayout{}, ErrCandidateIntegrity
	}
	root := filepath.Dir(filepath.Dir(canonical))
	releaseRoot := filepath.Join(root, "release")
	layout := PortableLayout{
		Root: root, Objects: filepath.Join(releaseRoot, "objects"),
		Evidence:            filepath.Join(releaseRoot, "evidence"),
		Publication:         filepath.Join(releaseRoot, "agentmemory-release-publication.json"),
		PublicationSigstore: filepath.Join(releaseRoot, "agentmemory-release-publication.sigstore.json"),
	}
	if !validPortableLayout(layout) {
		return PortableLayout{}, ErrCandidateIntegrity
	}
	for _, directory := range []string{layout.Root, releaseRoot, layout.Objects, layout.Evidence} {
		entry, statError := os.Lstat(directory)
		if statError != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			return PortableLayout{}, ErrCandidateIntegrity
		}
	}
	for _, file := range []string{layout.Publication, layout.PublicationSigstore} {
		entry, statError := os.Lstat(file)
		if statError != nil || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 {
			return PortableLayout{}, ErrCandidateIntegrity
		}
	}
	return layout, nil
}

func validPortableLayout(layout PortableLayout) bool {
	values := []string{
		layout.Root, layout.Objects, layout.Evidence, layout.Publication, layout.PublicationSigstore,
	}
	for _, value := range values {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return false
		}
	}
	if layout.Objects == layout.Evidence || layout.Publication == layout.PublicationSigstore {
		return false
	}
	releaseRoot := filepath.Join(layout.Root, "release")
	for _, value := range []string{layout.Objects, layout.Evidence, layout.Publication, layout.PublicationSigstore} {
		relative, err := filepath.Rel(releaseRoot, value)
		if err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return false
		}
	}
	return true
}
