package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type desktopMutationNativeBackend interface {
	ExecuteNativeDesktopMutation(
		context.Context,
		runtimeport.DesktopMutationRequest,
		DesktopMutationArtifactBinding,
		bool,
		DesktopMutationAuthorityEvidence,
	) (uint32, error)
}

// DesktopMutationReleaseArtifactSource exposes only exact resources from the
// retained, signed offline release bundle.
type DesktopMutationReleaseArtifactSource interface {
	OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error)
}

type desktopMutationHostPostState interface {
	ProbeDesktopHost(context.Context, runtimeport.DesktopAuthority) (runtimeport.DesktopHostEvidence, error)
	DesktopPrerequisitesReady(runtimeport.DesktopAuthority, runtimeport.DesktopHostEvidence) bool
}

type desktopMutationInstalledPostState interface {
	ProbeDesktopInstalledApplication(
		context.Context,
		runtimeport.DesktopAuthority,
	) (runtimeport.DesktopInstalledApplicationEvidence, error)
	DesktopInstalledApplicationVerified(
		runtimeport.DesktopAuthority,
		runtimeport.DesktopInstalledApplicationEvidence,
	) bool
	DesktopInstalledApplicationPresent(runtimeport.DesktopInstalledApplicationEvidence) bool
}

type nativeDesktopMutationPostState struct {
	host      runtimeport.DesktopHostProbe
	installed runtimeport.DesktopInstalledApplicationProbe
}

func (p nativeDesktopMutationPostState) ProbeDesktopHost(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopHostEvidence, error) {
	return p.host.ProbeDesktopHost(ctx, authority)
}

func (nativeDesktopMutationPostState) DesktopPrerequisitesReady(
	authority runtimeport.DesktopAuthority,
	evidence runtimeport.DesktopHostEvidence,
) bool {
	return evidence.PrerequisitesReady(authority)
}

func (p nativeDesktopMutationPostState) ProbeDesktopInstalledApplication(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	return p.installed.ProbeDesktopInstalledApplication(ctx, authority)
}

func (nativeDesktopMutationPostState) DesktopInstalledApplicationVerified(
	authority runtimeport.DesktopAuthority,
	evidence runtimeport.DesktopInstalledApplicationEvidence,
) bool {
	return evidence.VerifiedFor(authority)
}

func (nativeDesktopMutationPostState) DesktopInstalledApplicationPresent(
	evidence runtimeport.DesktopInstalledApplicationEvidence,
) bool {
	return evidence.Present()
}

// NativeDesktopMutationOperationExecutor is the only helper adapter allowed
// to invoke platform mutation. It re-probes semantic post-state before the
// application can sign a successful non-reboot receipt.
type NativeDesktopMutationOperationExecutor struct {
	backend   desktopMutationNativeBackend
	host      desktopMutationHostPostState
	installed desktopMutationInstalledPostState
}

// NewNativeDesktopMutationOperationExecutor constructs the production
// platform backend and exact post-state probes.
func NewNativeDesktopMutationOperationExecutor(
	host runtimeport.DesktopHostProbe,
	installed runtimeport.DesktopInstalledApplicationProbe,
	runner DesktopMutationCommandRunner,
	source DesktopMutationReleaseArtifactSource,
) (*NativeDesktopMutationOperationExecutor, error) {
	if nilArtifactDependency(host) || nilArtifactDependency(installed) || nilArtifactDependency(runner) ||
		nilArtifactDependency(source) {
		return nil, errors.New("native desktop mutation probes, command runner, and release source are required")
	}
	postState := nativeDesktopMutationPostState{host: host, installed: installed}
	return newNativeDesktopMutationOperationExecutor(
		newNativeDesktopMutationBackend(runner, source), postState, postState,
	)
}

func newNativeDesktopMutationOperationExecutor(
	backend desktopMutationNativeBackend,
	host desktopMutationHostPostState,
	installed desktopMutationInstalledPostState,
) (*NativeDesktopMutationOperationExecutor, error) {
	if nilArtifactDependency(backend) || nilArtifactDependency(host) || nilArtifactDependency(installed) {
		return nil, errors.New("complete native desktop mutation execution dependencies are required")
	}
	return &NativeDesktopMutationOperationExecutor{backend: backend, host: host, installed: installed}, nil
}

// ExecuteDesktopMutation admits only the closed runtime/prerequisite cells and
// turns native exit state into authenticated semantic observation.
func (e *NativeDesktopMutationOperationExecutor) ExecuteDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	artifacts DesktopMutationArtifactSet,
	evidence DesktopMutationAuthorityEvidence,
) (DesktopMutationObservationInput, error) {
	if e == nil || ctx == nil || nilArtifactDependency(e.backend) || nilArtifactDependency(e.host) ||
		nilArtifactDependency(e.installed) || request.Digest().IsZero() || nilArtifactDependency(artifacts) ||
		!evidence.Authority().Valid() || evidence.Authority().Digest() != request.Authority().Digest() ||
		evidence.HelperDigest().IsZero() || evidence.ReleaseManifestDigest().IsZero() {
		return DesktopMutationObservationInput{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return DesktopMutationObservationInput{}, err
	}
	installer, present := artifacts.Installer()
	if !validDesktopMutationExecutorArtifact(request, installer, present) {
		return DesktopMutationObservationInput{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if request.Operation() == runtimeport.DesktopMutationInstallPrerequisites {
		host, probeError := e.host.ProbeDesktopHost(ctx, request.Authority())
		if probeError != nil {
			return DesktopMutationObservationInput{}, desktopMutationHelperContextOrIntegrity(ctx)
		}
		if e.host.DesktopPrerequisitesReady(request.Authority(), host) {
			return DesktopMutationObservationInput{ExitCode: 0, PostState: request.ExpectedState()}, nil
		}
	}
	exitCode, err := e.backend.ExecuteNativeDesktopMutation(ctx, request, installer, present, evidence)
	if err != nil {
		return DesktopMutationObservationInput{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	reboot := slices.Contains(request.Authority().RebootExitCodes(), exitCode)
	if exitCode != 0 && !reboot {
		return DesktopMutationObservationInput{}, runtimeport.ErrDesktopMutationIntegrity
	}
	observation := DesktopMutationObservationInput{ExitCode: exitCode, PostState: request.ExpectedState()}
	if reboot {
		encoded, _ := json.Marshal(struct {
			ExitCode uint32 `json:"exit_code"`
			Request  string `json:"request_digest"`
		}{ExitCode: exitCode, Request: request.Digest().String()})
		observation.RebootReceipt = runtimeinstall.Sum(
			append([]byte("agentmemory.desktop-helper.reboot.v1\n"), encoded...),
		)
		return observation, nil
	}
	switch request.Operation() {
	case runtimeport.DesktopMutationInstallPrerequisites:
		host, probeError := e.host.ProbeDesktopHost(ctx, request.Authority())
		if probeError != nil || !e.host.DesktopPrerequisitesReady(request.Authority(), host) {
			return DesktopMutationObservationInput{}, desktopMutationHelperContextOrIntegrity(ctx)
		}
	case runtimeport.DesktopMutationInstallRuntime:
		installed, probeError := e.installed.ProbeDesktopInstalledApplication(ctx, request.Authority())
		if probeError != nil || !e.installed.DesktopInstalledApplicationVerified(request.Authority(), installed) {
			return DesktopMutationObservationInput{}, desktopMutationHelperContextOrIntegrity(ctx)
		}
	case runtimeport.DesktopMutationRemoveRuntime:
		installed, probeError := e.installed.ProbeDesktopInstalledApplication(ctx, request.Authority())
		if probeError != nil || !e.installed.DesktopInstalledApplicationVerified(request.Authority(), installed) ||
			e.installed.DesktopInstalledApplicationPresent(installed) {
			return DesktopMutationObservationInput{}, desktopMutationHelperContextOrIntegrity(ctx)
		}
	default:
		return DesktopMutationObservationInput{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return observation, nil
}

func validDesktopMutationExecutorArtifact(
	request runtimeport.DesktopMutationRequest,
	artifact DesktopMutationArtifactBinding,
	present bool,
) bool {
	switch request.Operation() {
	case runtimeport.DesktopMutationInstallPrerequisites:
		return !present && request.ArtifactDigest().IsZero()
	case runtimeport.DesktopMutationInstallRuntime:
		expected, err := desktopMutationArtifactTarget(request.Authority().Platform(), request.Digest())
		return present && err == nil && artifact.Path() == expected &&
			artifact.SHA256() == request.Authority().ArtifactSHA256() &&
			artifact.SHA256() == request.ArtifactDigest() && artifact.Size() == request.Authority().ArtifactBytes()
	case runtimeport.DesktopMutationRemoveRuntime:
		return !present && request.ArtifactDigest() == request.Authority().ArtifactSHA256()
	default:
		return false
	}
}

var _ DesktopMutationOperationExecutor = (*NativeDesktopMutationOperationExecutor)(nil)
