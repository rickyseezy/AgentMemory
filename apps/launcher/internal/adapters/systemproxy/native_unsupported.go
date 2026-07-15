//go:build !darwin && !windows && !linux

package systemproxy

func newNativeLookup() (nativeLookup, error) { return nil, ErrUnavailable }
