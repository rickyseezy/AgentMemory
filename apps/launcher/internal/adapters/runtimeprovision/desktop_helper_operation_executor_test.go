package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DesktopHelperOperationExecutorVerifiesPostStateBeforeReceipt(t *testing.T) {
	t.Parallel()
	_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	installer, _ := NewDesktopMutationArtifactBinding(
		desktopMutationTargetForTest(authority.Platform(), request.Digest()),
		authority.ArtifactSHA256(), authority.ArtifactBytes(),
	)
	backend := &desktopMutationNativeBackendStub{}
	ports := &desktopMutationPostStateStub{installed: true, prerequisites: true}
	executor, err := newNativeDesktopMutationOperationExecutor(backend, ports, ports)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := NewDesktopMutationAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	observation, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{binding: installer, present: true}, evidence,
	)
	if err != nil || observation.ExitCode != 0 || observation.PostState != request.ExpectedState() ||
		!observation.RebootReceipt.IsZero() || backend.calls != 1 || ports.installedCalls != 1 {
		t.Fatalf("observation=%+v calls=%d/%d error=%v", observation, backend.calls, ports.installedCalls, err)
	}
	ports.installed = false
	if _, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{binding: installer, present: true}, evidence,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("unverified post-state accepted: %v", err)
	}
}

func TestPF001DesktopHelperOperationExecutorEmitsBoundRebootEvidence(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallPrerequisites)
	backend := &desktopMutationNativeBackendStub{exitCode: authority.RebootExitCodes()[0]}
	ports := &desktopMutationPostStateStub{}
	executor, _ := newNativeDesktopMutationOperationExecutor(backend, ports, ports)
	evidence, _ := NewDesktopMutationAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	observation, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{}, evidence,
	)
	if err != nil || observation.ExitCode != backend.exitCode || observation.RebootReceipt.IsZero() ||
		observation.PostState != request.ExpectedState() || ports.hostCalls != 1 {
		t.Fatalf("observation=%+v host calls=%d error=%v", observation, ports.hostCalls, err)
	}
	backend.exitCode = 123
	if _, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{}, evidence,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign exit accepted: %v", err)
	}
}

func TestPF001DesktopHelperOperationExecutorSkipsAlreadyReadyPrerequisites(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	request := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallPrerequisites)
	backend := &desktopMutationNativeBackendStub{}
	ports := &desktopMutationPostStateStub{prerequisites: true}
	executor, _ := newNativeDesktopMutationOperationExecutor(backend, ports, ports)
	evidence, _ := NewDesktopMutationAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	observation, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{}, evidence,
	)
	if err != nil || backend.calls != 0 || ports.hostCalls != 1 || observation.ExitCode != 0 ||
		observation.PostState != request.ExpectedState() || !observation.RebootReceipt.IsZero() {
		t.Fatalf("observation=%+v backend=%d host=%d error=%v", observation, backend.calls, ports.hostCalls, err)
	}
}

func TestPF001DesktopHelperOperationExecutorRejectsIncompleteDependenciesAndSubstitution(t *testing.T) {
	t.Parallel()
	ports := &desktopMutationPostStateStub{}
	if candidate, err := newNativeDesktopMutationOperationExecutor(nil, ports, ports); candidate != nil || err == nil {
		t.Fatalf("nil backend accepted: %+v %v", candidate, err)
	}
	backend := &desktopMutationNativeBackendStub{err: errors.New("private process failure")}
	executor, _ := newNativeDesktopMutationOperationExecutor(backend, ports, ports)
	_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	installer, _ := NewDesktopMutationArtifactBinding(
		desktopMutationTargetForTest(authority.Platform(), request.Digest()),
		authority.ArtifactSHA256(), authority.ArtifactBytes(),
	)
	evidence, _ := NewDesktopMutationAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	if _, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{binding: installer, present: true}, evidence,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || errors.Is(err, backend.err) {
		t.Fatalf("backend error escaped: %v", err)
	}
	foreignEvidence, _ := NewDesktopMutationAuthorityEvidence(
		desktopAdapterAuthorityForTest(t, runtimeinstall.PlatformDarwin),
		runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release")),
	)
	if _, err := executor.ExecuteDesktopMutation(
		t.Context(), request, desktopMutationArtifactSetStub{binding: installer, present: true}, foreignEvidence,
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign evidence accepted: %v", err)
	}
}

func TestPF001ProductionDesktopMutationExecutorComposesExactPostStateAdapters(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	host := &desktopHostProbePortStub{}
	installed := &desktopInstalledProbePortStub{}
	runner := &desktopMutationRunnerStub{}
	source := desktopMutationReleaseSourceStub{}
	executor, err := NewNativeDesktopMutationOperationExecutor(host, installed, runner, source)
	if err != nil || executor == nil {
		t.Fatalf("executor=%+v error=%v", executor, err)
	}
	postState, ok := executor.host.(nativeDesktopMutationPostState)
	if !ok {
		t.Fatalf("host post state type=%T", executor.host)
	}
	if _, err := postState.ProbeDesktopHost(t.Context(), authority); err != nil || host.calls != 1 {
		t.Fatalf("host calls=%d error=%v", host.calls, err)
	}
	if postState.DesktopPrerequisitesReady(authority, runtimeport.DesktopHostEvidence{}) {
		t.Fatal("zero host evidence reported ready")
	}
	if _, err := postState.ProbeDesktopInstalledApplication(t.Context(), authority); err != nil || installed.calls != 1 {
		t.Fatalf("installed calls=%d error=%v", installed.calls, err)
	}
	if postState.DesktopInstalledApplicationVerified(authority, runtimeport.DesktopInstalledApplicationEvidence{}) {
		t.Fatal("zero installed evidence reported verified")
	}
	if candidate, err := NewNativeDesktopMutationOperationExecutor(nil, installed, runner, source); candidate != nil || err == nil {
		t.Fatalf("nil production host accepted: %+v %v", candidate, err)
	}
}

func desktopMutationTargetForTest(platform runtimeinstall.Platform, request runtimeinstall.Hash) string {
	target, _ := desktopMutationArtifactTarget(platform, request)
	return target
}

func desktopAdapterAuthorityForTest(
	t testing.TB,
	platform runtimeinstall.Platform,
) runtimeport.DesktopAuthority {
	t.Helper()
	_, authority := desktopAdapterAuthority(t, platform)
	return authority
}

type desktopMutationArtifactSetStub struct {
	binding DesktopMutationArtifactBinding
	present bool
}

func (s desktopMutationArtifactSetStub) Installer() (DesktopMutationArtifactBinding, bool) {
	return s.binding, s.present
}

type desktopMutationNativeBackendStub struct {
	exitCode uint32
	err      error
	calls    int
}

func (s *desktopMutationNativeBackendStub) ExecuteNativeDesktopMutation(
	context.Context,
	runtimeport.DesktopMutationRequest,
	DesktopMutationArtifactBinding,
	bool,
	DesktopMutationAuthorityEvidence,
) (uint32, error) {
	s.calls++
	return s.exitCode, s.err
}

type desktopMutationReleaseSourceStub struct{}

func (desktopMutationReleaseSourceStub) OpenResource(
	context.Context,
	releaseinventory.Resource,
) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("release-resource")), nil
}

type desktopMutationPostStateStub struct {
	installed, prerequisites  bool
	installedCalls, hostCalls int
}

type desktopHostProbePortStub struct{ calls int }

func (s *desktopHostProbePortStub) ProbeDesktopHost(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	s.calls++
	return runtimeport.DesktopHostEvidence{}, nil
}

type desktopInstalledProbePortStub struct{ calls int }

func (s *desktopInstalledProbePortStub) ProbeDesktopInstalledApplication(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	s.calls++
	return runtimeport.DesktopInstalledApplicationEvidence{}, nil
}

type desktopMutationRunnerStub struct{}

func (*desktopMutationRunnerStub) RunDesktopMutationCommand(
	context.Context,
	DesktopMutationCommand,
) (uint32, error) {
	return 0, nil
}

func (s *desktopMutationPostStateStub) ProbeDesktopInstalledApplication(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	s.installedCalls++
	return runtimeport.DesktopInstalledApplicationEvidence{}, nil
}

func (s *desktopMutationPostStateStub) DesktopInstalledApplicationVerified(
	runtimeport.DesktopAuthority,
	runtimeport.DesktopInstalledApplicationEvidence,
) bool {
	return s.installed
}

func (s *desktopMutationPostStateStub) ProbeDesktopHost(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	s.hostCalls++
	return runtimeport.DesktopHostEvidence{}, nil
}

func (s *desktopMutationPostStateStub) DesktopPrerequisitesReady(
	runtimeport.DesktopAuthority,
	runtimeport.DesktopHostEvidence,
) bool {
	return s.prerequisites
}
