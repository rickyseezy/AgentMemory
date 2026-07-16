package releasefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPF001ReleaseFileObservationPoliciesRejectEveryInvalidAlternative(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directoryInfo := mustLstat(t, root)
	empty := filepath.Join(root, "empty")
	one := filepath.Join(root, "one")
	two := filepath.Join(root, "two")
	other := filepath.Join(root, "other")
	for path, content := range map[string][]byte{
		empty: nil, one: []byte("x"), two: []byte("xy"), other: []byte("z"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyInfo := mustLstat(t, empty)
	oneInfo := mustLstat(t, one)
	twoInfo := mustLstat(t, two)
	otherInfo := mustLstat(t, other)
	link := filepath.Join(root, "link")
	if err := os.Symlink(one, link); err != nil {
		t.Fatal(err)
	}
	linkInfo := mustLstat(t, link)
	fault := errors.New("injected observation failure")

	assertPolicy(t, "stable directory", StableDirectory(directoryInfo, nil), true)
	assertPolicy(t, "directory file", StableDirectory(oneInfo, nil), false)
	assertPolicy(t, "directory link", StableDirectory(linkInfo, nil), false)
	assertPolicy(t, "directory nil", StableDirectory(nil, nil), false)
	assertPolicy(t, "directory error", StableDirectory(directoryInfo, fault), false)
	assertPolicy(t, "stable regular entry", StableEntry(oneInfo, nil), true)
	assertPolicy(t, "stable directory entry", StableEntry(directoryInfo, nil), true)
	assertPolicy(t, "linked entry", StableEntry(linkInfo, nil), false)
	assertPolicy(t, "nil entry", StableEntry(nil, nil), false)
	assertPolicy(t, "entry error", StableEntry(oneInfo, fault), false)

	assertPolicy(t, "bounded one", BoundedRegular(oneInfo, nil, 1), true)
	assertPolicy(t, "bounded two", BoundedRegular(twoInfo, nil, 2), true)
	assertPolicy(t, "bounded too small", BoundedRegular(twoInfo, nil, 1), false)
	assertPolicy(t, "bounded empty", BoundedRegular(emptyInfo, nil, 1), false)
	assertPolicy(t, "bounded directory", BoundedRegular(directoryInfo, nil, 1), false)
	assertPolicy(t, "bounded link", BoundedRegular(linkInfo, nil, 1), false)
	assertPolicy(t, "bounded nil", BoundedRegular(nil, nil, 1), false)
	assertPolicy(t, "bounded zero maximum", BoundedRegular(oneInfo, nil, 0), false)
	assertPolicy(t, "bounded negative maximum", BoundedRegular(oneInfo, nil, -1), false)
	assertPolicy(t, "bounded error", BoundedRegular(oneInfo, fault, 1), false)

	assertPolicy(t, "exact one", ExactRegularSize(oneInfo, nil, 1), true)
	assertPolicy(t, "exact two", ExactRegularSize(twoInfo, nil, 2), true)
	assertPolicy(t, "exact wrong size", ExactRegularSize(twoInfo, nil, 1), false)
	assertPolicy(t, "exact empty", ExactRegularSize(emptyInfo, nil, 1), false)
	assertPolicy(t, "exact directory", ExactRegularSize(directoryInfo, nil, 1), false)
	assertPolicy(t, "exact link", ExactRegularSize(linkInfo, nil, 1), false)
	assertPolicy(t, "exact zero expected", ExactRegularSize(oneInfo, nil, 0), false)
	assertPolicy(t, "exact nil", ExactRegularSize(nil, nil, 1), false)
	assertPolicy(t, "exact error", ExactRegularSize(oneInfo, fault, 1), false)

	assertPolicy(t, "same regular", SameRegularFile(oneInfo, mustStat(t, one), nil), true)
	assertPolicy(t, "different regular", SameRegularFile(oneInfo, otherInfo, nil), false)
	assertPolicy(t, "opened directory", SameRegularFile(oneInfo, directoryInfo, nil), false)
	assertPolicy(t, "expected directory", SameRegularFile(directoryInfo, directoryInfo, nil), false)
	assertPolicy(t, "same nil expected", SameRegularFile(nil, oneInfo, nil), false)
	assertPolicy(t, "same nil opened", SameRegularFile(oneInfo, nil, nil), false)
	assertPolicy(t, "same error", SameRegularFile(oneInfo, oneInfo, fault), false)
}

func TestPF001ReleaseFileTransferAndConfinementPoliciesAreExact(t *testing.T) {
	t.Parallel()
	fault := errors.New("injected transfer failure")
	for _, test := range []struct {
		name     string
		length   int
		err      error
		expected int64
		maximum  int64
		want     bool
	}{
		{name: "one", length: 1, expected: 1, maximum: 1, want: true},
		{name: "two", length: 2, expected: 2, maximum: 2, want: true},
		{name: "read error", length: 1, err: fault, expected: 1, maximum: 1},
		{name: "empty", expected: 1, maximum: 1},
		{name: "negative", length: -1, expected: 1, maximum: 1},
		{name: "wrong expected", length: 1, expected: 2, maximum: 2},
		{name: "over maximum", length: 2, expected: 2, maximum: 1},
		{name: "zero expected", length: 1, maximum: 1},
		{name: "zero maximum", length: 1, expected: 1},
	} {
		assertPolicy(t, "stable content "+test.name, StableContent(test.length, test.err, test.expected, test.maximum), test.want)
	}
	for _, test := range []struct {
		name     string
		written  int64
		err      error
		expected uint64
		want     bool
	}{
		{name: "one", written: 1, expected: 1, want: true},
		{name: "two", written: 2, expected: 2, want: true},
		{name: "copy error", written: 1, err: fault, expected: 1},
		{name: "empty", expected: 1},
		{name: "negative", written: -1, expected: 1},
		{name: "wrong size", written: 1, expected: 2},
		{name: "zero expected", written: 1},
	} {
		assertPolicy(t, "exact transfer "+test.name, ExactTransfer(test.written, test.err, test.expected), test.want)
	}
	for _, test := range []struct {
		name                       string
		written                    int64
		err                        error
		expected                   uint64
		actualDigest, expectedHash string
		fold, want                 bool
	}{
		{name: "exact", written: 1, expected: 1, actualDigest: "a1", expectedHash: "a1", want: true},
		{name: "folded", written: 1, expected: 1, actualDigest: "A1", expectedHash: "a1", fold: true, want: true},
		{name: "case sensitive", written: 1, expected: 1, actualDigest: "A1", expectedHash: "a1"},
		{name: "wrong digest", written: 1, expected: 1, actualDigest: "b2", expectedHash: "a1"},
		{name: "empty actual", written: 1, expected: 1, expectedHash: "a1"},
		{name: "empty expected", written: 1, expected: 1, actualDigest: "a1"},
		{name: "wrong transfer", written: 2, expected: 1, actualDigest: "a1", expectedHash: "a1"},
		{name: "transfer error", written: 1, err: fault, expected: 1, actualDigest: "a1", expectedHash: "a1"},
	} {
		assertPolicy(t, "digest transfer "+test.name, ExactDigestTransfer(
			test.written, test.err, test.expected, test.actualDigest, test.expectedHash, test.fold,
		), test.want)
	}

	root := t.TempDir()
	child := filepath.Join(root, "child")
	nested := filepath.Join(root, "parent", "child")
	for path, want := range map[string]string{child: "child", nested: filepath.Join("parent", "child")} {
		relative, ok := ConfinedRelative(root, path)
		if !ok || relative != want {
			t.Fatalf("ConfinedRelative(%q)=%q,%t want=%q,true", path, relative, ok, want)
		}
	}
	for _, path := range []string{root, filepath.Dir(root), filepath.Join(filepath.Dir(root), "sibling")} {
		if relative, ok := ConfinedRelative(root, path); ok || relative != "" {
			t.Fatalf("unconfined path %q accepted as %q", path, relative)
		}
	}
}

func assertPolicy(t testing.TB, name string, got bool, want bool) {
	t.Helper()
	if got != want {
		t.Fatalf("%s=%t want=%t", name, got, want)
	}
}

func mustLstat(t testing.TB, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func mustStat(t testing.TB, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
