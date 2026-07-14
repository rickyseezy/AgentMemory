//go:build !darwin && !linux && !windows

package process

import "errors"

func NewNativePublisherVerifier(NativePublisherDependencies) (PublisherVerifier, error) {
	return nil, errors.New("native publisher verification is unsupported on this platform")
}
