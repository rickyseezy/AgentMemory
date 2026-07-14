package releaseverify

import (
	"context"
	"errors"
)

// ErrorCode is a canonical TECHNICAL_REQUIREMENTS §5.8 boundary code.
type ErrorCode string

// Canonical error codes emitted by release verification.
const (
	ErrorCodeIntegrityViolation    ErrorCode = "AM_INTEGRITY_VIOLATION"
	ErrorCodeConflict              ErrorCode = "AM_CONFLICT"
	ErrorCodeUnsupportedHost       ErrorCode = "AM_UNSUPPORTED_HOST"
	ErrorCodeSchemaUnsupported     ErrorCode = "AM_SCHEMA_UNSUPPORTED"
	ErrorCodeForbidden             ErrorCode = "AM_FORBIDDEN"
	ErrorCodeDependencyUnavailable ErrorCode = "AM_DEPENDENCY_UNAVAILABLE"
	ErrorCodeDeadlineExceeded      ErrorCode = "AM_DEADLINE_EXCEEDED"
	ErrorCodeInternal              ErrorCode = "AM_INTERNAL"
)

// FailureReason is safe release-verification telemetry and UI vocabulary.
type FailureReason string

// Stable, privacy-safe release verification reasons.
const (
	FailureReasonUntrustedSigner        FailureReason = "release_untrusted_signer"
	FailureReasonSignatureInvalid       FailureReason = "release_signature_invalid"
	FailureReasonRevocationEvidence     FailureReason = "release_revocation_evidence_invalid"
	FailureReasonTrustedTimeEvidence    FailureReason = "release_trusted_time_evidence_invalid"
	FailureReasonTransparencyEvidence   FailureReason = "release_transparency_evidence_invalid"
	FailureReasonTrustEvidenceInvalid   FailureReason = "release_trust_evidence_invalid"
	FailureReasonTrustRootRevoked       FailureReason = "release_trust_root_revoked"
	FailureReasonReleaseExpired         FailureReason = "release_support_window_expired"
	FailureReasonPlatformUnsupported    FailureReason = "release_platform_unsupported"
	FailureReasonInventoryIncomplete    FailureReason = "release_inventory_incomplete"
	FailureReasonProtocolUnsupported    FailureReason = "release_protocol_unsupported"
	FailureReasonReleaseRollback        FailureReason = "release_rollback_blocked"
	FailureReasonSequenceEquivocation   FailureReason = "release_sequence_equivocation"
	FailureReasonDigestMismatch         FailureReason = "release_digest_mismatch"
	FailureReasonOCIIndexInvalid        FailureReason = "release_oci_index_invalid"
	FailureReasonNativePublisherInvalid FailureReason = "release_native_publisher_invalid"
	FailureReasonSBOMInvalid            FailureReason = "release_sbom_invalid"
	FailureReasonProvenanceInvalid      FailureReason = "release_provenance_invalid"
	FailureReasonLicenseDenied          FailureReason = "release_license_denied"
	FailureReasonVulnerabilityDenied    FailureReason = "release_vulnerability_denied"
	FailureReasonAnchorConflict         FailureReason = "release_anchor_conflict"
	FailureReasonAnchorIntegrity        FailureReason = "release_anchor_integrity"
	FailureReasonResourceUnavailable    FailureReason = "release_resource_unavailable"
	FailureReasonDependencyUnavailable  FailureReason = "release_dependency_unavailable"
	FailureReasonDeadline               FailureReason = "release_verification_deadline"
	FailureReasonInternal               FailureReason = "release_verification_internal"
)

// VerificationError never stores or unwraps an infrastructure cause.
type VerificationError struct {
	code      ErrorCode
	reason    FailureReason
	retryable bool
	message   string
}

func (e *VerificationError) Error() string { return e.message }

// Code returns the canonical boundary code.
func (e *VerificationError) Code() ErrorCode { return e.code }

// Reason returns the safe release failure reason.
func (e *VerificationError) Reason() FailureReason { return e.reason }

// Retryable reports whether an idempotent retry may make progress.
func (e *VerificationError) Retryable() bool { return e.retryable }

func verificationError(
	code ErrorCode,
	reason FailureReason,
	retryable bool,
	message string,
) *VerificationError {
	return &VerificationError{code: code, reason: reason, retryable: retryable, message: message}
}

func mapUnknownPortError(err error) *VerificationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return verificationError(
			ErrorCodeDeadlineExceeded,
			FailureReasonDeadline,
			true,
			"release verification deadline was exceeded",
		)
	case errors.Is(err, ErrDependencyUnavailable):
		return verificationError(
			ErrorCodeDependencyUnavailable,
			FailureReasonDependencyUnavailable,
			true,
			"release verification dependency is unavailable",
		)
	default:
		return verificationError(
			ErrorCodeInternal,
			FailureReasonInternal,
			false,
			"release verification could not continue",
		)
	}
}

func integrity(reason FailureReason) *VerificationError {
	return verificationError(ErrorCodeIntegrityViolation, reason, false, "release verification failed")
}
