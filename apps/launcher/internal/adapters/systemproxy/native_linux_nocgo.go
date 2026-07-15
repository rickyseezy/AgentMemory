//go:build linux && !cgo

package systemproxy

func newNativeLookup() (nativeLookup, error) { return nil, ErrUnavailable }
