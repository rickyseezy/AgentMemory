//go:build darwin || linux

package setuphost

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPF001NativeSetupPrincipalIsStableBoundAndCancellable(t *testing.T) {
	t.Parallel()

	verifier := NewPrincipalVerifier()
	first, err := verifier.CurrentPrincipal(context.Background())
	if err != nil || first.IsZero() {
		t.Fatalf("CurrentPrincipal() = %s, %v", first.String(), err)
	}
	second, err := verifier.CurrentPrincipal(context.Background())
	if err != nil || !first.Equal(second) {
		t.Fatalf("CurrentPrincipal() was unstable: %s, %v", second.String(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.CurrentPrincipal(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CurrentPrincipal(cancelled) error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves the principal boundary fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := verifier.CurrentPrincipal(nil); err == nil {
		t.Fatal("CurrentPrincipal(nil) succeeded")
	}
}

func TestPF001BrowserOpenerUsesExactExecutableURLAndScrubbedEnvironment(t *testing.T) {
	production, err := NewBrowserOpener()
	if errors.Is(err, ErrBrowserUnavailable) {
		if validateRootOwnedExecutable(nativeBrowserExecutable) == nil {
			t.Fatal("trusted native browser executable was reported unavailable")
		}
		t.Skip("host image does not provide the fixed trusted desktop browser launcher")
	}
	if err != nil || production == nil {
		t.Fatalf("NewBrowserOpener() = %v, %v", production, err)
	}
	var actualExecutable, actualURL string
	var actualEnvironment []string
	runner := func(_ context.Context, executable, setupURL string, environment []string) error {
		actualExecutable, actualURL = executable, setupURL
		actualEnvironment = append([]string(nil), environment...)
		return nil
	}
	source := []string{
		"HOME=/home/person",
		"LANG=en_US.UTF-8",
		"SECRET_TOKEN=must-not-pass",
		"PATH=/attacker/bin",
	}
	opener, err := newBrowserOpener(nativeBrowserExecutable, runner, func() []string {
		return append([]string(nil), source...)
	})
	if err != nil {
		t.Fatalf("newBrowserOpener() error = %v", err)
	}
	capability := base64.RawURLEncoding.EncodeToString(bytesOf(9, setupCapabilityBytes))
	wantedURL := "http://127.0.0.1:49153/#capability=" + capability
	if err := opener.Open(context.Background(), wantedURL); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if actualExecutable != nativeBrowserExecutable || actualURL != wantedURL {
		t.Fatalf("browser command = %q %q", actualExecutable, actualURL)
	}
	if slices.Contains(actualEnvironment, "SECRET_TOKEN=must-not-pass") ||
		!slices.Contains(actualEnvironment, "PATH=/usr/bin:/bin") ||
		!slices.Contains(actualEnvironment, "HOME=/home/person") ||
		!slices.IsSorted(actualEnvironment) {
		t.Fatalf("browser environment = %#v", actualEnvironment)
	}
}

func TestPF001BrowserCommandUsesArgvAndHonorsCancellation(t *testing.T) {
	t.Parallel()

	if err := runBrowserCommand(
		context.Background(),
		"/usr/bin/true",
		"http://127.0.0.1:1/#capability=unused",
		[]string{"PATH=/usr/bin:/bin"},
	); err != nil {
		t.Fatalf("runBrowserCommand(true) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runBrowserCommand(
		ctx,
		"/usr/bin/true",
		"http://127.0.0.1:1/#capability=unused",
		[]string{"PATH=/usr/bin:/bin"},
	); err == nil {
		t.Fatal("runBrowserCommand(cancelled) succeeded")
	}
}

func TestPF001BrowserOpenerRejectsInvalidAuthorityContextAndExecution(t *testing.T) {
	t.Parallel()

	capability := base64.RawURLEncoding.EncodeToString(bytesOf(11, setupCapabilityBytes))
	validURL := "http://127.0.0.1:49154/#capability=" + capability
	if _, err := newBrowserOpener("/tmp/open", func(context.Context, string, string, []string) error {
		return nil
	}, os.Environ); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("newBrowserOpener(foreign executable) error = %v", err)
	}
	if validateRootOwnedExecutable(nativeBrowserExecutable) != nil {
		t.Skip("host image does not provide the fixed trusted desktop browser launcher")
	}
	opener, err := newBrowserOpener(nativeBrowserExecutable, func(context.Context, string, string, []string) error {
		return errors.New("private process failure")
	}, os.Environ)
	if err != nil {
		t.Fatal(err)
	}
	if err := opener.Open(context.Background(), validURL); !errors.Is(err, ErrBrowserUnavailable) ||
		strings.Contains(err.Error(), "private") {
		t.Fatalf("Open(process failure) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := opener.Open(ctx, validURL); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(cancelled) error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves the browser boundary fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := opener.Open(nil, validURL); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("Open(nil) error = %v", err)
	}
	if err := opener.Open(context.Background(), "https://example.com/"); !errors.Is(err, ErrInvalidSetupURL) {
		t.Fatalf("Open(remote) error = %v", err)
	}
	duplicateEnvironment := func() []string { return []string{"HOME=/first", "HOME=/second"} }
	opener, err = newBrowserOpener(nativeBrowserExecutable, func(context.Context, string, string, []string) error {
		return nil
	}, duplicateEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if err := opener.Open(context.Background(), validURL); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("Open(ambiguous environment) error = %v", err)
	}
	cancelledAfterCommand, cancelAfterCommand := context.WithCancel(context.Background())
	opener, err = newBrowserOpener(nativeBrowserExecutable, func(context.Context, string, string, []string) error {
		cancelAfterCommand()
		return nil
	}, os.Environ)
	if err != nil {
		t.Fatal(err)
	}
	if err := opener.Open(cancelledAfterCommand, validURL); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(cancelled after command) error = %v", err)
	}
	newlineEnvironment := func() []string { return []string{"HOME=/safe\nunsafe"} }
	opener, err = newBrowserOpener(nativeBrowserExecutable, func(context.Context, string, string, []string) error {
		return nil
	}, newlineEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if err := opener.Open(context.Background(), validURL); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("Open(invalid environment) error = %v", err)
	}
}

func TestPF001BrowserExecutableProofRejectsUserOwnedAndLinkedObjects(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	regular := filepath.Join(root, "open")
	if err := os.WriteFile(regular, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // G306: executable mode is the subject of this rejection test.
		t.Fatal(err)
	}
	if err := validateRootOwnedExecutable(regular); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("validateRootOwnedExecutable(user-owned) error = %v", err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(regular, linked); err != nil {
		t.Fatal(err)
	}
	if err := validateRootOwnedExecutable(linked); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("validateRootOwnedExecutable(symlink) error = %v", err)
	}
	if err := validateRootOwnedExecutable("relative/open"); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("validateRootOwnedExecutable(relative) error = %v", err)
	}
	if err := validateRootOwnedExecutable(filepath.Join(root, "missing")); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("validateRootOwnedExecutable(missing) error = %v", err)
	}
	if err := validateRootOwnedExecutable(root); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("validateRootOwnedExecutable(directory) error = %v", err)
	}
}
