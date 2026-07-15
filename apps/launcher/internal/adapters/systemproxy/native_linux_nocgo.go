//go:build linux && !cgo

package systemproxy

import "context"

func newNativeLookup() (nativeLookup, error) { return nil, ErrUnavailable }

func nativeCredentialsForProxy(context.Context, string, string) ([]byte, []byte, error) {
	return nil, nil, ErrUnavailable
}
