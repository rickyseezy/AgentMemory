//go:build darwin && !cgo

package corehttp

import (
	"errors"
	"testing"
)

func TestPF001DarwinNoCGOCredentialACLProofFailsClosed(t *testing.T) {
	t.Parallel()
	for _, directory := range []bool{false, true} {
		if err := verifyCredentialACL(-1, directory); !errors.Is(err, errCredentialUnavailable) {
			t.Fatalf("directory=%t ACL error=%v", directory, err)
		}
	}
}
