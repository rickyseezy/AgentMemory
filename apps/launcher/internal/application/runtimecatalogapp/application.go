package runtimecatalogapp

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// Dependencies is the complete runtime catalog verification composition contract.
type Dependencies struct {
	Clock           Clock
	Host            HostProvider
	Signature       ManifestSignatureVerifier
	NativePublisher NativePublisherVerifier
	AntiRollback    AntiRollbackRepository
}

// Application verifies a runtime catalog cell without acquiring or executing artifacts.
type Application struct {
	clock           Clock
	host            HostProvider
	signature       ManifestSignatureVerifier
	nativePublisher NativePublisherVerifier
	antiRollback    AntiRollbackRepository
}

// NewApplication rejects missing and typed-nil trust dependencies.
func NewApplication(dependencies Dependencies) (*Application, error) {
	required := []struct {
		name  string
		value any
	}{
		{name: "clock", value: dependencies.Clock},
		{name: "host", value: dependencies.Host},
		{name: "signature", value: dependencies.Signature},
		{name: "native publisher", value: dependencies.NativePublisher},
		{name: "anti-rollback", value: dependencies.AntiRollback},
	}
	for _, dependency := range required {
		if nilPort(dependency.value) {
			return nil, fmt.Errorf("runtime catalog dependency %q is required", dependency.name)
		}
	}
	return &Application{
		clock: dependencies.Clock, host: dependencies.Host, signature: dependencies.Signature,
		nativePublisher: dependencies.NativePublisher, antiRollback: dependencies.AntiRollback,
	}, nil
}

// Verify returns immutable execution policy only after every fail-closed gate succeeds.
func (a *Application) Verify(ctx context.Context, request Request) (VerifiedCatalog, error) {
	if ctx == nil {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeCancelled, FailureReasonCancelled, false, "runtime catalog verification context is required",
		)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCatalog{}, mapContextOrDependency(err)
	}
	signed := request.SignedManifest
	if !signed.Valid() || request.ExpectedManifestDigest.IsZero() {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeIntegrity, FailureReasonCatalogIntegrity, false, "runtime catalog envelope is invalid",
		)
	}
	manifest := signed.Manifest()
	var onlineSource *runtimecatalog.SourceLocation
	if request.OnlineSource != (runtimecatalog.SourceLocation{}) {
		copiedSource := request.OnlineSource
		onlineSource = &copiedSource
	}
	if !manifest.Digest().Equal(request.ExpectedManifestDigest) {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeIntegrity, FailureReasonReleaseBinding, false, "runtime catalog is not bound by this release",
		)
	}
	if err := a.signature.VerifyManifestSignature(ctx, signed); err != nil {
		return VerifiedCatalog{}, mapSignatureError(err)
	}
	now := a.clock.Now()
	if now.IsZero() {
		return VerifiedCatalog{}, mapContextOrDependency(ErrDependencyUnavailable)
	}
	if !manifest.SupportedAt(now) {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeUnsupported, FailureReasonSupportExpired, false, "runtime catalog support window has expired",
		)
	}
	host, err := a.host.CurrentHost(ctx)
	if err != nil {
		return VerifiedCatalog{}, mapContextOrDependency(err)
	}
	if err := manifest.Platform().Supports(host); err != nil {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeUnsupported, FailureReasonUnsupportedHost, false, "runtime catalog does not support this host",
		)
	}
	if err := manifest.AuthorizeSource(request.SourceMode, onlineSource); err != nil {
		return VerifiedCatalog{}, verificationError(
			ErrorCodeIntegrity, FailureReasonSourceDenied, false, "runtime artifact source is not authorized",
		)
	}
	if err := a.nativePublisher.VerifyNativePublisherPolicy(ctx, manifest.Artifact().Publisher()); err != nil {
		if errors.Is(err, ErrNativePublisherInvalid) {
			return VerifiedCatalog{}, verificationError(
				ErrorCodeIntegrity, FailureReasonNativePublisher, false, "runtime native publisher policy is invalid",
			)
		}
		return VerifiedCatalog{}, mapContextOrDependency(err)
	}
	next, expected, alreadyAccepted, err := a.checkAntiRollback(ctx, manifest)
	if err != nil {
		return VerifiedCatalog{}, err
	}
	if !alreadyAccepted {
		if err := a.antiRollback.CompareAndSwapCatalogAnchor(ctx, expected, next); err != nil {
			if errors.Is(err, ErrCatalogAnchorIntegrity) {
				return VerifiedCatalog{}, anchorIntegrity()
			}
			if errors.Is(err, ErrCatalogAnchorConflict) {
				return VerifiedCatalog{}, verificationError(
					ErrorCodeConflict, FailureReasonAnchorConflict, true, "runtime catalog acceptance state changed",
				)
			}
			return VerifiedCatalog{}, mapContextOrDependency(err)
		}
	}
	return newVerifiedCatalog(
		manifest, now, request.SourceMode, onlineSource, alreadyAccepted,
	), nil
}

func (a *Application) checkAntiRollback(
	ctx context.Context,
	manifest runtimecatalog.Manifest,
) (CatalogAnchor, *CatalogAnchor, bool, error) {
	next, err := NewCatalogAnchor(manifest.CatalogID(), manifest.CatalogSequence(), manifest.Digest())
	if err != nil {
		return CatalogAnchor{}, nil, false, anchorIntegrity()
	}
	current, loadError := a.antiRollback.LoadCatalogAnchor(ctx, manifest.CatalogID())
	switch {
	case errors.Is(loadError, ErrCatalogAnchorNotFound):
		return next, nil, false, nil
	case errors.Is(loadError, ErrCatalogAnchorIntegrity):
		return CatalogAnchor{}, nil, false, anchorIntegrity()
	case loadError != nil:
		return CatalogAnchor{}, nil, false, mapContextOrDependency(loadError)
	case !current.valid() || current.catalogID != manifest.CatalogID():
		return CatalogAnchor{}, nil, false, anchorIntegrity()
	case manifest.CatalogSequence() < current.sequence:
		return CatalogAnchor{}, nil, false, verificationError(
			ErrorCodeConflict, FailureReasonCatalogRollback, false, "runtime catalog sequence is older than accepted state",
		)
	case manifest.CatalogSequence() == current.sequence && !manifest.Digest().Equal(current.manifestDigest):
		return CatalogAnchor{}, nil, false, verificationError(
			ErrorCodeIntegrity, FailureReasonSequenceEquivocation, false, "runtime catalog sequence has conflicting content",
		)
	case manifest.CatalogSequence() == current.sequence:
		return next, &current, true, nil
	default:
		return next, &current, false, nil
	}
}

func mapSignatureError(err error) *VerificationError {
	switch {
	case errors.Is(err, ErrUntrustedSigner):
		return verificationError(
			ErrorCodeIntegrity, FailureReasonUntrustedSigner, false, "runtime catalog signer is not trusted",
		)
	case errors.Is(err, ErrSignatureInvalid):
		return verificationError(
			ErrorCodeIntegrity, FailureReasonSignatureInvalid, false, "runtime catalog signature is invalid",
		)
	default:
		return mapContextOrDependency(err)
	}
}

func anchorIntegrity() *VerificationError {
	return verificationError(
		ErrorCodeIntegrity, FailureReasonAnchorIntegrity, false, "runtime catalog acceptance state failed integrity verification",
	)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Array, reflect.Bool, reflect.Complex128, reflect.Complex64, reflect.Float32,
		reflect.Float64, reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int8,
		reflect.Invalid, reflect.String, reflect.Struct, reflect.Uint, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uint8, reflect.Uintptr, reflect.UnsafePointer:
		return false
	}
	return false
}
