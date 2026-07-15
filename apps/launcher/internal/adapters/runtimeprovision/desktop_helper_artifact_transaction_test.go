package runtimeprovision

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DesktopHelperArtifactStoreDerivesProtectedTransactionTarget(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			_, authority, request := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
			if platform == runtimeinstall.PlatformDarwin {
				_, authority = desktopAdapterAuthority(t, platform)
				request = desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallRuntime)
			}
			binding, err := NewDesktopMutationArtifactBinding(
				authority.ArtifactPath(), authority.ArtifactSHA256(), authority.ArtifactBytes(),
			)
			if err != nil {
				t.Fatal(err)
			}
			copier := &desktopMutationArtifactCopierStub{}
			store, err := newProtectedDesktopMutationArtifactStore(copier)
			if err != nil {
				t.Fatal(err)
			}
			set, err := store.PrepareDesktopMutationArtifact(t.Context(), request, binding, true)
			artifact, present := set.Installer()
			if err != nil || !present || copier.calls != 1 || artifact.SHA256() != binding.SHA256() ||
				artifact.Size() != binding.Size() || copier.artifact.SourcePath() != binding.Path() ||
				artifact.Path() != copier.artifact.TargetPath() ||
				!strings.Contains(copier.artifact.TargetPath(), request.Digest().String()) ||
				copier.artifact.TargetPath() == copier.artifact.SourcePath() {
				t.Fatalf("platform=%s artifact=%+v present=%t calls=%d error=%v", platform, artifact, present, copier.calls, err)
			}
		})
	}
}

func TestPF001DesktopHelperArtifactStoreRejectsSubstitutionAndPrerequisiteArtifacts(t *testing.T) {
	t.Parallel()
	_, authority, installRequest := desktopMutationCodecFixture(t, runtimeport.DesktopMutationInstallRuntime)
	binding, _ := NewDesktopMutationArtifactBinding(
		authority.ArtifactPath(), authority.ArtifactSHA256(), authority.ArtifactBytes(),
	)
	copier := &desktopMutationArtifactCopierStub{}
	store, _ := newProtectedDesktopMutationArtifactStore(copier)
	foreign, _ := NewDesktopMutationArtifactBinding(
		binding.Path(), runtimeinstall.Sum([]byte("foreign")), binding.Size(),
	)
	if _, err := store.PrepareDesktopMutationArtifact(t.Context(), installRequest, foreign, true); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || copier.calls != 0 {
		t.Fatalf("foreign binding error=%v calls=%d", err, copier.calls)
	}
	prerequisite := desktopArtifactRequest(t, authority, runtimeport.DesktopMutationInstallPrerequisites)
	set, err := store.PrepareDesktopMutationArtifact(
		t.Context(), prerequisite, DesktopMutationArtifactBinding{}, false,
	)
	if _, present := set.Installer(); err != nil || present || copier.calls != 0 {
		t.Fatalf("prerequisite set=%+v present=%t error=%v calls=%d", set, present, err, copier.calls)
	}
	if _, err := store.PrepareDesktopMutationArtifact(t.Context(), prerequisite, binding, true); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("prerequisite artifact accepted: %v", err)
	}
	if candidate, err := newProtectedDesktopMutationArtifactStore(nil); candidate != nil || err == nil {
		t.Fatalf("nil copier accepted: %+v %v", candidate, err)
	}
	copier.err = errors.New("private copy path")
	if _, err := store.PrepareDesktopMutationArtifact(t.Context(), installRequest, binding, true); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || errors.Is(err, copier.err) {
		t.Fatalf("copy error escaped: %v", err)
	}
}

func TestPF001ProductionDesktopArtifactStoreCompositionIsAvailableOnDesktop(t *testing.T) {
	t.Parallel()
	store, err := NewProtectedDesktopMutationArtifactStore()
	if err != nil || store == nil || nilArtifactDependency(store.copier) {
		t.Fatalf("store=%+v error=%v", store, err)
	}
	artifact := DesktopMutationTransactionArtifact{
		sourcePath: "/source", targetPath: "/target", sha256: runtimeinstall.Sum([]byte("artifact")), size: 8,
	}
	if artifact.SourcePath() != "/source" || artifact.TargetPath() != "/target" ||
		artifact.SHA256().IsZero() || artifact.Size() != 8 {
		t.Fatalf("artifact getters failed: %+v", artifact)
	}
}

func desktopArtifactRequest(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	operation runtimeport.DesktopMutationOperation,
) runtimeport.DesktopMutationRequest {
	t.Helper()
	artifact := runtimeinstall.Hash{}
	if operation == runtimeport.DesktopMutationInstallRuntime {
		artifact = authority.ArtifactSHA256()
	}
	now := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"019f5f23-5678-7def-9123-abcdef012349", 1, operation, authority,
		runtimeinstall.Sum([]byte("consent")), artifact, runtimeport.Nonce{7, 8, 9},
		now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type desktopMutationArtifactCopierStub struct {
	artifact DesktopMutationTransactionArtifact
	err      error
	calls    int
}

func (s *desktopMutationArtifactCopierStub) CopyDesktopMutationArtifact(
	_ context.Context,
	_ runtimeport.DesktopMutationRequest,
	artifact DesktopMutationTransactionArtifact,
) error {
	s.calls++
	s.artifact = artifact
	return s.err
}
