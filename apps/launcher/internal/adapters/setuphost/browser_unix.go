//go:build darwin || linux

package setuphost

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type browserCommand func(context.Context, string, string, []string) error

// BrowserOpener launches the platform-owned URL handler through one fixed,
// root-owned executable and an exact argv boundary.
type BrowserOpener struct {
	executable string
	command    browserCommand
	environ    func() []string
}

// NewBrowserOpener validates the complete executable ancestry before exposing
// the capability. Open repeats the proof immediately before every launch.
func NewBrowserOpener() (*BrowserOpener, error) {
	return newBrowserOpener(nativeBrowserExecutable, runBrowserCommand, os.Environ)
}

func newBrowserOpener(
	executable string,
	command browserCommand,
	environ func() []string,
) (*BrowserOpener, error) {
	if command == nil || environ == nil || executable != nativeBrowserExecutable ||
		validateRootOwnedExecutable(executable) != nil {
		return nil, ErrBrowserUnavailable
	}
	return &BrowserOpener{executable: executable, command: command, environ: environ}, nil
}

// Open validates the exact fragment-bearing URL, re-proves the immutable
// system launcher, and executes without a shell or inherited standard IO.
func (o *BrowserOpener) Open(ctx context.Context, setupURL string) error {
	if o == nil || ctx == nil {
		return ErrBrowserUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSetupURL(setupURL); err != nil {
		return err
	}
	if o.executable != nativeBrowserExecutable || validateRootOwnedExecutable(o.executable) != nil {
		return ErrBrowserUnavailable
	}
	environment, err := sanitizedBrowserEnvironment(o.environ())
	if err != nil {
		return ErrBrowserUnavailable
	}
	if err := o.command(ctx, o.executable, setupURL, environment); err != nil {
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

func runBrowserCommand(ctx context.Context, executable, setupURL string, environment []string) error {
	command := exec.CommandContext(ctx, executable, setupURL) //nolint:gosec // G204: executable is an exact root-owned platform allowlist path.
	command.Env = environment
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func sanitizedBrowserEnvironment(source []string) ([]string, error) {
	allowed := nativeBrowserEnvironmentKeys()
	seen := make(map[string]struct{}, len(allowed))
	values := make([]string, 0, len(allowed)+1)
	for _, entry := range source {
		key, value, present := strings.Cut(entry, "=")
		if !present {
			continue
		}
		if _, wanted := allowed[key]; !wanted {
			continue
		}
		if _, duplicate := seen[key]; duplicate || strings.ContainsAny(value, "\x00\r\n") || len(value) > 4096 {
			return nil, ErrBrowserUnavailable
		}
		seen[key] = struct{}{}
		values = append(values, key+"="+value)
	}
	values = append(values, "PATH=/usr/bin:/bin")
	sort.Strings(values)
	return values, nil
}

func validateRootOwnedExecutable(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrBrowserUnavailable
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrBrowserUnavailable
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrBrowserUnavailable
		}
		if current == path && !info.Mode().IsRegular() {
			return ErrBrowserUnavailable
		}
		if current != path && !info.IsDir() {
			return ErrBrowserUnavailable
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
