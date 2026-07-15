// Package nativepackageinstallapp installs the exact native AgentMemory
// package selected by a signed canonical release publication. It owns policy
// and orchestration only; filesystem, publisher, elevation, and package-manager
// behavior remain behind narrow ports.
package nativepackageinstallapp

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const maximumSignatureBundleBytes = 64 * 1024 * 1024

var (
	// ErrInvalidArgument means the use-case invocation or composition is invalid.
	ErrInvalidArgument = errors.New("native package installation argument is invalid")
	// ErrPublicationIntegrity means canonical publication or signature authority failed.
	ErrPublicationIntegrity = errors.New("native package publication integrity failed")
	// ErrUnsupportedTarget means the signed publication has no exact requested cell.
	ErrUnsupportedTarget = errors.New("native package target is unsupported")
	// ErrCandidateIntegrity means the packaged installer bytes or publisher failed verification.
	ErrCandidateIntegrity = errors.New("native package candidate integrity failed")
	// ErrInstallationFailed means the native package transaction did not complete.
	ErrInstallationFailed = errors.New("native package installation failed")
	// ErrPostconditionFailed means installed product authority did not match the publication.
	ErrPostconditionFailed = errors.New("native package installation postcondition failed")
)

// ArtifactSignatureVerifier verifies a non-zero canonical SHA-256 digest with
// one complete offline signature bundle and embedded release trust.
type ArtifactSignatureVerifier interface {
	VerifyArtifactSignature(context.Context, releaseinventory.Digest, []byte) error
}

// CandidateVerifier reopens the fixed packaged candidate, verifies exact size
// and SHA-256, and applies the publication-selected native publisher policy.
type CandidateVerifier interface {
	VerifyCandidate(context.Context, releasepublication.Artifact) error
}

// Installer executes the platform-native package transaction for the fixed,
// already-verified candidate. It must never invoke a shell or ambient package.
type Installer interface {
	Install(context.Context, releasepublication.Artifact) error
}

// InstalledProductVerifier proves the final launcher, helper, and retained
// release match the exact publication after the native transaction settles.
type InstalledProductVerifier interface {
	VerifyInstalled(
		context.Context,
		releasepublication.Publication,
		releasepublication.Artifact,
	) error
}

// Dependencies are the four purpose-separated production capabilities.
type Dependencies struct {
	Signature ArtifactSignatureVerifier
	Candidate CandidateVerifier
	Installer Installer
	Installed InstalledProductVerifier
}

// Application owns exact signed-publication installation orchestration.
type Application struct{ dependencies Dependencies }

// Request carries only canonical authority bytes and one exact platform cell.
type Request struct {
	PublicationJSON           []byte
	PublicationSigstoreBundle []byte
	OperatingSystem           string
	Architecture              string
	Format                    releasepublication.Format
}

// Result is the privacy-safe completed native package identity.
type Result struct {
	ReleaseID string
	Version   string
	PackageID string
}

// New rejects a partial composition before any input is parsed.
func New(dependencies Dependencies) (*Application, error) {
	if nilCapability(dependencies.Signature) || nilCapability(dependencies.Candidate) ||
		nilCapability(dependencies.Installer) || nilCapability(dependencies.Installed) {
		return nil, ErrInvalidArgument
	}
	return &Application{dependencies: dependencies}, nil
}

// Install verifies signed top-level authority, verifies the exact selected
// package, executes one native transaction, and then proves its postcondition.
func (a *Application) Install(ctx context.Context, request Request) (Result, error) {
	if a == nil || ctx == nil || nilCapability(a.dependencies.Signature) ||
		nilCapability(a.dependencies.Candidate) || nilCapability(a.dependencies.Installer) ||
		nilCapability(a.dependencies.Installed) || len(request.PublicationJSON) == 0 ||
		len(request.PublicationSigstoreBundle) == 0 ||
		len(request.PublicationSigstoreBundle) > maximumSignatureBundleBytes ||
		request.OperatingSystem == "" || request.Architecture == "" || request.Format == "" {
		return Result{}, ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	publication, err := releasepublication.DecodeV1(request.PublicationJSON)
	if err != nil {
		return Result{}, ErrPublicationIntegrity
	}
	digest := releaseinventory.DigestBytes(publication.Canonical())
	signature := append([]byte(nil), request.PublicationSigstoreBundle...)
	if err := a.dependencies.Signature.VerifyArtifactSignature(ctx, digest, signature); err != nil {
		return Result{}, mapContext(ctx, ErrPublicationIntegrity)
	}
	artifact, err := publication.NativePackage(
		request.OperatingSystem, request.Architecture, request.Format,
	)
	if err != nil {
		return Result{}, ErrUnsupportedTarget
	}
	if err := a.dependencies.Candidate.VerifyCandidate(ctx, artifact); err != nil {
		return Result{}, mapContext(ctx, ErrCandidateIntegrity)
	}
	if err := a.dependencies.Installer.Install(ctx, artifact); err != nil {
		return Result{}, mapContext(ctx, ErrInstallationFailed)
	}
	if err := a.dependencies.Installed.VerifyInstalled(ctx, publication, artifact); err != nil {
		return Result{}, mapContext(ctx, ErrPostconditionFailed)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{
		ReleaseID: publication.ReleaseID(), Version: publication.Version(), PackageID: artifact.ID(),
	}, nil
}

func mapContext(ctx context.Context, fallback error) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return fallback
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
