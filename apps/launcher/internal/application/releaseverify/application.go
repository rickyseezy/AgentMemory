package releaseverify

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// Dependencies is the complete release-verification composition contract.
type Dependencies struct {
	Clock           Clock
	Platform        PlatformProvider
	Protocol        ProtocolProvider
	Signature       ManifestSignatureVerifier
	TrustEvidence   OfflineTrustEvidenceVerifier
	ResourceDigest  ResourceDigestVerifier
	SBOM            SBOMVerifier
	Provenance      ProvenanceVerifier
	License         LicenseVerifier
	Vulnerability   VulnerabilityVerifier
	NativePublisher NativePublisherVerifier
	OCIIndex        OCIIndexVerifier
	AntiRollback    AntiRollbackRepository
}

// Application verifies a release without executing or activating any resource.
type Application struct {
	clock           Clock
	platform        PlatformProvider
	protocol        ProtocolProvider
	signature       ManifestSignatureVerifier
	trustEvidence   OfflineTrustEvidenceVerifier
	resourceDigest  ResourceDigestVerifier
	sbom            SBOMVerifier
	provenance      ProvenanceVerifier
	license         LicenseVerifier
	vulnerability   VulnerabilityVerifier
	nativePublisher NativePublisherVerifier
	ociIndex        OCIIndexVerifier
	antiRollback    AntiRollbackRepository
}

// NewApplication rejects missing and typed-nil security dependencies.
func NewApplication(dependencies Dependencies) (*Application, error) {
	required := []struct {
		name  string
		value any
	}{
		{name: "clock", value: dependencies.Clock},
		{name: "platform", value: dependencies.Platform},
		{name: "protocol", value: dependencies.Protocol},
		{name: "signature", value: dependencies.Signature},
		{name: "trust evidence", value: dependencies.TrustEvidence},
		{name: "resource digest", value: dependencies.ResourceDigest},
		{name: "SBOM", value: dependencies.SBOM},
		{name: "provenance", value: dependencies.Provenance},
		{name: "license", value: dependencies.License},
		{name: "vulnerability", value: dependencies.Vulnerability},
		{name: "native publisher", value: dependencies.NativePublisher},
		{name: "OCI index", value: dependencies.OCIIndex},
		{name: "anti-rollback", value: dependencies.AntiRollback},
	}
	for _, dependency := range required {
		if nilPort(dependency.value) {
			return nil, fmt.Errorf("release verifier dependency %q is required", dependency.name)
		}
	}
	return &Application{
		clock:           dependencies.Clock,
		platform:        dependencies.Platform,
		protocol:        dependencies.Protocol,
		signature:       dependencies.Signature,
		trustEvidence:   dependencies.TrustEvidence,
		resourceDigest:  dependencies.ResourceDigest,
		sbom:            dependencies.SBOM,
		provenance:      dependencies.Provenance,
		license:         dependencies.License,
		vulnerability:   dependencies.Vulnerability,
		nativePublisher: dependencies.NativePublisher,
		ociIndex:        dependencies.OCIIndex,
		antiRollback:    dependencies.AntiRollback,
	}, nil
}

// Verify returns a closed inventory only after all trust and anti-rollback gates pass.
func (a *Application) Verify(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
) (VerifiedInventory, error) {
	if nilPort(ctx) {
		return VerifiedInventory{}, mapUnknownPortError(ErrDependencyUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedInventory{}, mapUnknownPortError(err)
	}
	manifest := signed.Manifest()
	if err := validateOfflineEvidence(signed); err != nil {
		return VerifiedInventory{}, err
	}
	if err := a.signature.VerifyManifestSignature(ctx, signed); err != nil {
		return VerifiedInventory{}, mapSignatureError(err)
	}
	if err := a.trustEvidence.VerifyOfflineTrustEvidence(ctx, signed); err != nil {
		return VerifiedInventory{}, mapTrustError(err)
	}

	now := a.clock.Now()
	if now.IsZero() {
		return VerifiedInventory{}, mapUnknownPortError(errors.New("release policy clock returned zero time"))
	}
	if !manifest.ValidAt(now) {
		return VerifiedInventory{}, verificationError(
			ErrorCodeConflict,
			FailureReasonReleaseExpired,
			false,
			"release is outside its supported installation window",
		)
	}
	platform, err := a.platform.CurrentPlatform(ctx)
	if err != nil {
		return VerifiedInventory{}, mapUnknownPortError(err)
	}
	if platform.IsAny() || !platform.Valid() {
		return VerifiedInventory{}, mapUnknownPortError(errors.New("platform provider returned an invalid platform"))
	}
	protocol, err := a.protocol.CurrentProtocol(ctx)
	if err != nil {
		return VerifiedInventory{}, mapUnknownPortError(err)
	}
	if protocol == 0 {
		return VerifiedInventory{}, mapUnknownPortError(errors.New("protocol provider returned an invalid version"))
	}
	if !manifest.Protocol().Contains(protocol) {
		return VerifiedInventory{}, verificationError(
			ErrorCodeSchemaUnsupported,
			FailureReasonProtocolUnsupported,
			false,
			"release protocol is incompatible with this launcher",
		)
	}
	resources, err := manifest.ResourcesFor(platform)
	if err != nil {
		return VerifiedInventory{}, mapTargetInventoryError(err)
	}

	anchor, expectedAnchor, alreadyAccepted, err := a.checkAntiRollback(ctx, manifest)
	if err != nil {
		return VerifiedInventory{}, err
	}
	if err := a.verifyResources(ctx, manifest, resources); err != nil {
		return VerifiedInventory{}, err
	}
	if !alreadyAccepted {
		if err := a.antiRollback.CompareAndSwapReleaseAnchor(ctx, expectedAnchor, anchor); err != nil {
			return VerifiedInventory{}, mapAnchorMutationError(err)
		}
	}
	return newVerifiedInventory(manifest, platform, now, alreadyAccepted, resources), nil
}

func validateOfflineEvidence(signed releaseinventory.SignedManifest) *VerificationError {
	policy := signed.Manifest().TrustPolicy()
	if signed.TrustMode() != policy.Mode() || signed.TrustRootID() != policy.TrustRootID() {
		return integrity(FailureReasonUntrustedSigner)
	}
	if len(signed.RevocationSet()) == 0 ||
		!releaseinventory.DigestBytes(signed.RevocationSet()).Equal(policy.RevocationSetDigest()) {
		return integrity(FailureReasonRevocationEvidence)
	}
	if len(signed.TrustedTimeEvidence()) == 0 {
		return integrity(FailureReasonTrustedTimeEvidence)
	}
	if policy.Mode() == releaseinventory.SignatureTrustModeCertificateTransparency &&
		len(signed.SigstoreBundle()) == 0 {
		return integrity(FailureReasonTransparencyEvidence)
	}
	return nil
}

func (a *Application) checkAntiRollback(
	ctx context.Context,
	manifest releaseinventory.Manifest,
) (ReleaseAnchor, *ReleaseAnchor, bool, error) {
	next, err := NewReleaseAnchor(manifest.Channel(), manifest.Sequence(), manifest.Digest(), manifest.ReleaseID())
	if err != nil {
		return ReleaseAnchor{}, nil, false, integrity(FailureReasonInternal)
	}
	current, loadError := a.antiRollback.LoadReleaseAnchor(ctx, manifest.Channel())
	switch {
	case errors.Is(loadError, ErrReleaseAnchorIntegrity):
		return ReleaseAnchor{}, nil, false, integrity(FailureReasonAnchorIntegrity)
	case errors.Is(loadError, context.Canceled),
		errors.Is(loadError, context.DeadlineExceeded),
		errors.Is(loadError, ErrDependencyUnavailable):
		return ReleaseAnchor{}, nil, false, mapAnchorLoadError(loadError)
	case loadError != nil && !errors.Is(loadError, ErrReleaseAnchorNotFound):
		return ReleaseAnchor{}, nil, false, mapAnchorLoadError(loadError)
	case errors.Is(loadError, ErrReleaseAnchorNotFound):
		return next, nil, false, nil
	case !current.valid():
		return ReleaseAnchor{}, nil, false, integrity(FailureReasonAnchorIntegrity)
	case manifest.Sequence() < current.Sequence():
		return ReleaseAnchor{}, nil, false, verificationError(
			ErrorCodeConflict,
			FailureReasonReleaseRollback,
			false,
			"release sequence is older than the accepted release",
		)
	case manifest.Sequence() == current.Sequence() && !manifest.Digest().Equal(current.ManifestDigest()):
		return ReleaseAnchor{}, nil, false, integrity(FailureReasonSequenceEquivocation)
	case manifest.Sequence() == current.Sequence() && manifest.ReleaseID() != current.ReleaseID():
		return ReleaseAnchor{}, nil, false, integrity(FailureReasonAnchorIntegrity)
	case manifest.Sequence() == current.Sequence():
		return next, &current, true, nil
	default:
		return next, &current, false, nil
	}
}

func (a *Application) verifyResources(
	ctx context.Context,
	manifest releaseinventory.Manifest,
	resources []releaseinventory.Resource,
) error {
	byID := make(map[string]releaseinventory.Resource, len(resources))
	for _, resource := range resources {
		byID[resource.ID()] = resource
		if err := a.resourceDigest.VerifyResourceDigest(ctx, resource); err != nil {
			return mapDigestError(err)
		}
	}
	for _, subject := range resources {
		if subject.Kind().IsEvidence() {
			continue
		}
		if subject.Kind() == releaseinventory.ResourceKindOCIImage {
			if err := a.ociIndex.VerifyOCIIndex(
				ctx,
				subject,
				byID[subject.OCIIndexResourceID()],
			); err != nil {
				return mapOCIIndexError(err)
			}
		}
		if subject.Kind() == releaseinventory.ResourceKindLauncher ||
			subject.Kind() == releaseinventory.ResourceKindVerifier ||
			subject.Kind() == releaseinventory.ResourceKindHelper {
			if err := a.nativePublisher.VerifyNativePublisher(ctx, subject); err != nil {
				return mapNativePublisherError(err)
			}
		}
		cycloneDX := byID[subject.CycloneDXSBOMResourceID()]
		spdx := byID[subject.SPDXSBOMResourceID()]
		if err := a.sbom.VerifySBOMs(ctx, subject, cycloneDX, spdx); err != nil {
			return mapSBOMError(err)
		}
		if err := a.provenance.VerifyProvenance(
			ctx,
			manifest,
			subject,
			byID[subject.ProvenanceResourceID()],
		); err != nil {
			return mapProvenanceError(err)
		}
		if err := a.license.VerifyLicense(ctx, subject, byID[subject.LicenseResourceID()]); err != nil {
			return mapLicenseError(err)
		}
		if err := a.vulnerability.VerifyVulnerabilities(
			ctx,
			subject,
			byID[subject.VulnerabilityResourceID()],
		); err != nil {
			return mapVulnerabilityError(err)
		}
	}
	return nil
}

func mapSignatureError(err error) error {
	switch {
	case errors.Is(err, ErrUntrustedSigner):
		return integrity(FailureReasonUntrustedSigner)
	case errors.Is(err, ErrSignatureInvalid), errors.Is(err, ErrSignatureModeUnsupported):
		return integrity(FailureReasonSignatureInvalid)
	default:
		return mapUnknownPortError(err)
	}
}

func mapTrustError(err error) error {
	switch {
	case errors.Is(err, ErrTrustRootRevoked):
		return integrity(FailureReasonTrustRootRevoked)
	case errors.Is(err, ErrTrustEvidenceInvalid):
		return integrity(FailureReasonTrustEvidenceInvalid)
	default:
		return mapUnknownPortError(err)
	}
}

func mapDigestError(err error) error {
	switch {
	case errors.Is(err, ErrResourceDigestMismatch):
		return integrity(FailureReasonDigestMismatch)
	case errors.Is(err, ErrResourceUnavailable):
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	default:
		return mapUnknownPortError(err)
	}
}

func mapTargetInventoryError(err error) error {
	if errors.Is(err, releaseinventory.ErrTargetInventoryIncomplete) {
		return integrity(FailureReasonInventoryIncomplete)
	}
	if errors.Is(err, releaseinventory.ErrTargetUnsupported) {
		return verificationError(
			ErrorCodeUnsupportedHost,
			FailureReasonPlatformUnsupported,
			false,
			"release does not support this platform",
		)
	}
	return mapUnknownPortError(err)
}

func mapOCIIndexError(err error) error {
	if errors.Is(err, ErrResourceUnavailable) {
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	}
	if errors.Is(err, ErrOCIIndexInvalid) {
		return integrity(FailureReasonOCIIndexInvalid)
	}
	return mapUnknownPortError(err)
}

func mapNativePublisherError(err error) error {
	if errors.Is(err, ErrNativePublisherInvalid) {
		return integrity(FailureReasonNativePublisherInvalid)
	}
	return mapUnknownPortError(err)
}

func mapSBOMError(err error) error {
	if errors.Is(err, ErrResourceUnavailable) {
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	}
	if errors.Is(err, ErrSBOMInvalid) {
		return integrity(FailureReasonSBOMInvalid)
	}
	return mapUnknownPortError(err)
}

func mapProvenanceError(err error) error {
	if errors.Is(err, ErrResourceUnavailable) {
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	}
	if errors.Is(err, ErrProvenanceInvalid) {
		return integrity(FailureReasonProvenanceInvalid)
	}
	return mapUnknownPortError(err)
}

func mapLicenseError(err error) error {
	if errors.Is(err, ErrResourceUnavailable) {
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	}
	if errors.Is(err, ErrLicenseDenied) {
		return verificationError(ErrorCodeForbidden, FailureReasonLicenseDenied, false, "release license policy blocked installation")
	}
	return mapUnknownPortError(err)
}

func mapVulnerabilityError(err error) error {
	if errors.Is(err, ErrResourceUnavailable) {
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonResourceUnavailable,
			true,
			"release resource is unavailable",
		)
	}
	if errors.Is(err, ErrVulnerabilityDenied) {
		return verificationError(
			ErrorCodeForbidden,
			FailureReasonVulnerabilityDenied,
			false,
			"release vulnerability policy blocked installation",
		)
	}
	return mapUnknownPortError(err)
}

func mapAnchorLoadError(err error) error {
	if errors.Is(err, ErrReleaseAnchorIntegrity) {
		return integrity(FailureReasonAnchorIntegrity)
	}
	return mapUnknownPortError(err)
}

func mapAnchorMutationError(err error) error {
	if errors.Is(err, ErrReleaseAnchorIntegrity) {
		return integrity(FailureReasonAnchorIntegrity)
	}
	if errors.Is(err, ErrReleaseAnchorConflict) {
		return verificationError(
			ErrorCodeConflict,
			FailureReasonAnchorConflict,
			false,
			"accepted release state changed concurrently",
		)
	}
	return mapUnknownPortError(err)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}
