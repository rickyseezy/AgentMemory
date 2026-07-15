//go:build darwin && !cgo

package systemproxy

func newNativeLookup() (nativeLookup, error) { return nil, ErrUnavailable }
