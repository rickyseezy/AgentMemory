package nativepackage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const (
	darwinOpenExecutable  = "/usr/bin/open"
	linuxPkexecExecutable = "/usr/bin/pkexec"
	linuxDpkgExecutable   = "/usr/bin/dpkg"
	linuxRPMExecutable    = "/usr/bin/rpm"
	windowsMSIExecutable  = `C:\Windows\System32\msiexec.exe`
)

// ErrInstallation is a sanitized native transaction failure.
var ErrInstallation = errors.New("native package transaction failed")

// Command is one closed no-shell native package transaction.
type Command struct {
	Executable string
	Arguments  []string
}

// CommandRunner executes an absolute trusted system executable, settles its
// process tree, bounds diagnostics, and returns only the numeric exit status.
type CommandRunner interface {
	Run(context.Context, Command) (int, error)
}

// TransactionInstaller maps one exact certified cell to one native package
// manager or operating-system installer invocation.
type TransactionInstaller struct {
	root            string
	operatingSystem string
	architecture    string
	runner          CommandRunner
}

// NewTransactionInstaller is injectable for certified-platform tests.
func NewTransactionInstaller(
	root string,
	operatingSystem string,
	architecture string,
	runner CommandRunner,
) (*TransactionInstaller, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!validPlatformCell(operatingSystem, architecture) || nilCapability(runner) {
		return nil, ErrInstallation
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInstallation
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return nil, ErrInstallation
	}
	return &TransactionInstaller{
		root: canonical, operatingSystem: operatingSystem, architecture: architecture, runner: runner,
	}, nil
}

// NewNativeTransactionInstaller uses only the compile-time target cell.
func NewNativeTransactionInstaller(root string, runner CommandRunner) (*TransactionInstaller, error) {
	return NewTransactionInstaller(root, runtime.GOOS, runtime.GOARCH, runner)
}

// Install executes exactly one UI-capable native transaction. macOS opens the
// notarization-enforcing Installer application, Windows uses Windows Installer
// with UAC and no automatic restart, and Linux uses Polkit before the fixed
// distribution package manager executable.
func (i *TransactionInstaller) Install(ctx context.Context, artifact releasepublication.Artifact) error {
	if i == nil || ctx == nil || i.root == "" || !validPlatformCell(i.operatingSystem, i.architecture) ||
		nilCapability(i.runner) || artifact.Kind() != releasepublication.ArtifactKindNativePackage ||
		artifact.OperatingSystem() != i.operatingSystem || artifact.Architecture() != i.architecture {
		return ErrInstallation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	command, err := nativeInstallCommand(i.root, artifact)
	if err != nil {
		return ErrInstallation
	}
	exitCode, err := i.runner.Run(ctx, command)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return ErrInstallation
	}
	if !successfulInstallExit(i.operatingSystem, exitCode) {
		return ErrInstallation
	}
	return ctx.Err()
}

func validPlatformCell(operatingSystem string, architecture string) bool {
	switch operatingSystem + "/" + architecture {
	case "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64":
		return true
	default:
		return false
	}
}

func nativeInstallCommand(root string, artifact releasepublication.Artifact) (Command, error) {
	packagePath := filepath.Join(root, artifact.FileName())
	switch artifact.OperatingSystem() {
	case "darwin":
		if artifact.Format() != releasepublication.FormatPKG ||
			artifact.NativePublisherPolicy() != releasepublication.PublisherPolicyAppleNotarized {
			return Command{}, ErrInstallation
		}
		return Command{Executable: darwinOpenExecutable, Arguments: []string{"-W", packagePath}}, nil
	case "windows":
		if artifact.Format() != releasepublication.FormatMSI ||
			artifact.NativePublisherPolicy() != releasepublication.PublisherPolicyMicrosoftAuthenticode {
			return Command{}, ErrInstallation
		}
		return Command{Executable: windowsMSIExecutable, Arguments: []string{
			"/i", packagePath, "/passive", "/norestart",
		}}, nil
	case "linux":
		if artifact.NativePublisherPolicy() != releasepublication.PublisherPolicyLinuxPackage {
			return Command{}, ErrInstallation
		}
		switch artifact.Format() {
		case releasepublication.FormatDEB:
			return Command{Executable: linuxPkexecExecutable, Arguments: []string{
				linuxDpkgExecutable, "--install", packagePath,
			}}, nil
		case releasepublication.FormatRPM:
			return Command{Executable: linuxPkexecExecutable, Arguments: []string{
				linuxRPMExecutable, "--upgrade", "--replacepkgs", packagePath,
			}}, nil
		case releasepublication.FormatPKG, releasepublication.FormatMSI,
			releasepublication.FormatTarZstd:
			return Command{}, ErrInstallation
		default:
			return Command{}, ErrInstallation
		}
	default:
		return Command{}, ErrInstallation
	}
}

func successfulInstallExit(operatingSystem string, exitCode int) bool {
	if operatingSystem == "windows" {
		return exitCode == 0 || exitCode == 1641 || exitCode == 3010
	}
	return exitCode == 0
}
