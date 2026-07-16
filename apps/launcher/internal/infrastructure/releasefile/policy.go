// Package releasefile contains pure filesystem-result policies shared by the
// release assembly commands. Operating-system calls stay in their adapters;
// these predicates make every fail-closed TOCTOU, size, and digest decision
// deterministic and exhaustively testable.
package releasefile

import (
	"os"
	"path/filepath"
	"strings"
)

// StableDirectory accepts only a successfully observed non-link directory.
func StableDirectory(info os.FileInfo, observationError error) bool {
	return observationError == nil && info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

// StableEntry accepts a successfully observed entry that is not a link.
func StableEntry(info os.FileInfo, observationError error) bool {
	return observationError == nil && info != nil && info.Mode()&os.ModeSymlink == 0
}

// BoundedRegular accepts a non-empty regular file no larger than maximum.
func BoundedRegular(info os.FileInfo, observationError error, maximum int64) bool {
	return observationError == nil && info != nil && maximum > 0 && info.Mode().IsRegular() &&
		info.Size() > 0 && info.Size() <= maximum
}

// ExactRegularSize binds a regular file to an expected positive byte length.
func ExactRegularSize(info os.FileInfo, observationError error, expected uint64) bool {
	return observationError == nil && info != nil && expected > 0 && info.Mode().IsRegular() &&
		info.Size() > 0 && uint64(info.Size()) == expected // #nosec G115 -- positivity is proven first.
}

// SameRegularFile proves that the descriptor still names the Lstat-observed
// regular file.
func SameRegularFile(expected os.FileInfo, opened os.FileInfo, descriptorError error) bool {
	return descriptorError == nil && expected != nil && opened != nil &&
		expected.Mode().IsRegular() && opened.Mode().IsRegular() && os.SameFile(expected, opened)
}

// StableContent proves a bounded read returned the exact observed byte count.
func StableContent(length int, readError error, expected int64, maximum int64) bool {
	return readError == nil && length > 0 && expected > 0 && maximum > 0 &&
		int64(length) == expected && int64(length) <= maximum
}

// ExactTransfer proves a copy returned the exact expected positive byte count.
func ExactTransfer(written int64, transferError error, expected uint64) bool {
	return transferError == nil && written > 0 && expected > 0 && uint64(written) == expected // #nosec G115 -- positivity is proven first.
}

// ExactDigestTransfer additionally binds the copied bytes to their expected
// digest. caseInsensitive is used only for formats whose decoder accepts
// uppercase hexadecimal.
func ExactDigestTransfer(
	written int64,
	transferError error,
	expectedSize uint64,
	actualDigest string,
	expectedDigest string,
	caseInsensitive bool,
) bool {
	if !ExactTransfer(written, transferError, expectedSize) || actualDigest == "" || expectedDigest == "" {
		return false
	}
	if caseInsensitive {
		return strings.EqualFold(actualDigest, expectedDigest)
	}
	return actualDigest == expectedDigest
}

// ConfinedRelative returns the canonical relative relationship only when path
// is a strict descendant of root.
func ConfinedRelative(root string, path string) (string, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "" || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}
