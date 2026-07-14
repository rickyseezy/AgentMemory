//go:build windows

package setuphost

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPF001WindowsSetupPrincipalAndBrowserUseNativeIdentityBoundaries(t *testing.T) {
	verifier := NewPrincipalVerifier()
	principal, err := verifier.CurrentPrincipal(context.Background())
	if err != nil || principal.IsZero() {
		t.Fatalf("CurrentPrincipal() = %s, %v", principal.String(), err)
	}
	capability := base64.RawURLEncoding.EncodeToString(bytesOf(13, setupCapabilityBytes))
	wantedURL := "http://127.0.0.1:49155/#capability=" + capability
	var actualVerb, actualTarget string
	opener := &BrowserOpener{execute: func(
		_ windows.Handle,
		verb *uint16,
		target *uint16,
		_ *uint16,
		_ *uint16,
		show int32,
	) error {
		actualVerb, actualTarget = windows.UTF16PtrToString(verb), windows.UTF16PtrToString(target)
		if show != showNormal {
			t.Fatalf("show = %d", show)
		}
		return nil
	}}
	if err := opener.Open(context.Background(), wantedURL); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if actualVerb != "open" || actualTarget != wantedURL {
		t.Fatalf("ShellExecute(%q, %q)", actualVerb, actualTarget)
	}
}

func TestPF001WindowsBrowserRejectsRemoteAndSanitizesNativeFailure(t *testing.T) {
	t.Parallel()

	opener := &BrowserOpener{execute: func(
		windows.Handle,
		*uint16,
		*uint16,
		*uint16,
		*uint16,
		int32,
	) error {
		return errors.New("private shell failure")
	}}
	if err := opener.Open(context.Background(), "https://example.com/"); !errors.Is(err, ErrInvalidSetupURL) {
		t.Fatalf("Open(remote) error = %v", err)
	}
	capability := base64.RawURLEncoding.EncodeToString(bytesOf(15, setupCapabilityBytes))
	validURL := "http://127.0.0.1:49156/#capability=" + capability
	if err := opener.Open(context.Background(), validURL); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("Open(failure) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := opener.Open(ctx, validURL); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(cancelled) error = %v", err)
	}
}
