//go:build !darwin && !linux && !windows

package setuphost

import "context"

// BrowserOpener is the fail-closed unsupported-platform implementation.
type BrowserOpener struct{}

// NewBrowserOpener never manufactures an opener on an uncertified platform.
func NewBrowserOpener() (*BrowserOpener, error) { return nil, ErrBrowserUnavailable }

// Open never launches a browser on an uncertified platform.
func (*BrowserOpener) Open(context.Context, string) error { return ErrBrowserUnavailable }
