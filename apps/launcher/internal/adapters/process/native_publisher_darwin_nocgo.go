//go:build darwin && !cgo

package process

import (
	"errors"
)

// NewNativePublisherVerifier fails closed because native Apple code-sign and
// notarization verification requires Security.framework through cgo.
func NewNativePublisherVerifier(NativePublisherDependencies) (PublisherVerifier, error) {
	return nil, errors.New("native macOS publisher verification requires cgo")
}
