//go:build windows

package setuphost

import (
	"context"

	"golang.org/x/sys/windows"
)

const showNormal = 1

type shellExecute func(
	windows.Handle,
	*uint16,
	*uint16,
	*uint16,
	*uint16,
	int32,
) error

// BrowserOpener delegates URL handling directly to the authenticated Windows
// shell rather than invoking cmd.exe, PowerShell, or a mutable browser path.
type BrowserOpener struct{ execute shellExecute }

// NewBrowserOpener constructs the native ShellExecuteW adapter.
func NewBrowserOpener() (*BrowserOpener, error) {
	return &BrowserOpener{execute: windows.ShellExecute}, nil
}

// Open validates the one-use loopback URL and performs one native open action.
func (o *BrowserOpener) Open(ctx context.Context, setupURL string) error {
	if o == nil || o.execute == nil || ctx == nil {
		return ErrBrowserUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSetupURL(setupURL); err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return ErrBrowserUnavailable
	}
	target, err := windows.UTF16PtrFromString(setupURL)
	if err != nil {
		return ErrBrowserUnavailable
	}
	if err := o.execute(0, verb, target, nil, nil, showNormal); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return ErrBrowserUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
