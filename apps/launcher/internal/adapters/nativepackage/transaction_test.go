package nativepackage

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001NativeTransactionUsesOnlyClosedNoShellCommands(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		operatingSystem string
		architecture    string
		format          releasepublication.Format
		executable      string
		arguments       []string
	}{
		"macOS Intel": {"darwin", "amd64", releasepublication.FormatPKG, darwinOpenExecutable, []string{"-W", "PACKAGE"}},
		"macOS ARM":   {"darwin", "arm64", releasepublication.FormatPKG, darwinOpenExecutable, []string{"-W", "PACKAGE"}},
		"Windows":     {"windows", "amd64", releasepublication.FormatMSI, windowsMSIExecutable, []string{"/i", "PACKAGE", "/passive", "/norestart"}},
		"Debian AMD":  {"linux", "amd64", releasepublication.FormatDEB, linuxPkexecExecutable, []string{linuxDpkgExecutable, "--install", "PACKAGE"}},
		"RPM ARM":     {"linux", "arm64", releasepublication.FormatRPM, linuxPkexecExecutable, []string{linuxRPMExecutable, "--upgrade", "--replacepkgs", "PACKAGE"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			artifact := selectedNativeArtifact(t, test.operatingSystem, test.architecture, test.format)
			runner := &commandRunnerStub{}
			installer, err := NewTransactionInstaller(root, test.operatingSystem, test.architecture, runner)
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.Install(context.Background(), artifact); err != nil {
				t.Fatalf("Install() error = %v", err)
			}
			if runner.command.Executable != test.executable ||
				len(runner.command.Arguments) != len(test.arguments) {
				t.Fatalf("command = %+v", runner.command)
			}
			canonicalRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			packagePath := filepath.Join(canonicalRoot, artifact.FileName())
			for index, argument := range test.arguments {
				if argument == "PACKAGE" {
					argument = packagePath
				}
				if runner.command.Arguments[index] != argument {
					t.Fatalf("arguments = %q", runner.command.Arguments)
				}
			}
		})
	}
}

func TestPF001NativeTransactionAcceptsOnlyDocumentedSuccessCodes(t *testing.T) {
	t.Parallel()
	for _, exitCode := range []int{0, 1641, 3010} {
		runner := &commandRunnerStub{exitCode: exitCode}
		installer, err := NewTransactionInstaller(t.TempDir(), "windows", "amd64", runner)
		if err != nil {
			t.Fatal(err)
		}
		if err := installer.Install(
			context.Background(), selectedNativeArtifact(t, "windows", "amd64", releasepublication.FormatMSI),
		); err != nil {
			t.Fatalf("Windows exit %d error = %v", exitCode, err)
		}
	}
	installer, err := NewTransactionInstaller(t.TempDir(), "linux", "amd64", &commandRunnerStub{exitCode: 3010})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(
		context.Background(), selectedNativeArtifact(t, "linux", "amd64", releasepublication.FormatDEB),
	); !errors.Is(err, ErrInstallation) {
		t.Fatalf("Linux nonzero exit error = %v", err)
	}
}

func TestPF001NativeTransactionFailsClosedForInvalidTargetRunnerAndContext(t *testing.T) {
	t.Parallel()
	if installer, err := NewTransactionInstaller(t.TempDir(), "plan9", "amd64", &commandRunnerStub{}); installer != nil || !errors.Is(err, ErrInstallation) {
		t.Fatalf("invalid target = %T, %v", installer, err)
	}
	if installer, err := NewTransactionInstaller(t.TempDir(), "linux", "amd64", (*commandRunnerStub)(nil)); installer != nil || !errors.Is(err, ErrInstallation) {
		t.Fatalf("nil runner = %T, %v", installer, err)
	}
	runner := &commandRunnerStub{err: errors.New("private process failure")}
	installer, err := NewTransactionInstaller(t.TempDir(), "linux", "amd64", runner)
	if err != nil {
		t.Fatal(err)
	}
	artifact := selectedNativeArtifact(t, "linux", "amd64", releasepublication.FormatDEB)
	if err := installer.Install(context.Background(), artifact); !errors.Is(err, ErrInstallation) {
		t.Fatalf("runner failure = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := installer.Install(cancelled, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	runner.err = nil
	wrong := selectedNativeArtifact(t, "linux", "amd64", releasepublication.FormatRPM)
	if err := installer.Install(context.Background(), wrong); err != nil {
		t.Fatalf("same-cell RPM should be supported: %v", err)
	}
	var absent *TransactionInstaller
	if err := absent.Install(context.Background(), artifact); !errors.Is(err, ErrInstallation) {
		t.Fatalf("nil installer error = %v", err)
	}
}

func TestPF001NativeTransactionConstructorUsesCompileTimePlatform(t *testing.T) {
	t.Parallel()
	installer, err := NewNativeTransactionInstaller(t.TempDir(), &commandRunnerStub{})
	if validPlatformCell(runtime.GOOS, runtime.GOARCH) {
		if err != nil || installer == nil {
			t.Fatalf("NewNativeTransactionInstaller() = %T, %v", installer, err)
		}
		return
	}
	if installer != nil || !errors.Is(err, ErrInstallation) {
		t.Fatalf("unsupported native constructor = %T, %v", installer, err)
	}
}

type commandRunnerStub struct {
	command  Command
	exitCode int
	err      error
}

func (r *commandRunnerStub) Run(_ context.Context, command Command) (int, error) {
	r.command = Command{Executable: command.Executable, Arguments: append([]string(nil), command.Arguments...)}
	return r.exitCode, r.err
}

func selectedNativeArtifact(
	t testing.TB,
	operatingSystem string,
	architecture string,
	format releasepublication.Format,
) releasepublication.Artifact {
	t.Helper()
	publication, _ := candidatePublicationFixture(t, releaseinventory.Digest{})
	artifact, err := publication.NativePackage(operatingSystem, architecture, format)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}
