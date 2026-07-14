//go:build !linux

package secretprojector

import "errors"

// RunDefault fails closed outside the Linux-container helper image.
func RunDefault() error { return errors.New("protected projection is Linux-container-only") }
