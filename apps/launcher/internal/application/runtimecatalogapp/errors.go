package runtimecatalogapp

import (
	"context"
	"errors"
)

// ErrVerificationFailed is the stable error class for a denied catalog.
var ErrVerificationFailed = errors.New("runtime catalog verification failed")

// ErrorCode is a stable application error category.
type ErrorCode string

// Closed public error categories.
const (
	ErrorCodeIntegrity             ErrorCode = "integrity"
	ErrorCodeConflict              ErrorCode = "conflict"
	ErrorCodeUnsupported           ErrorCode = "unsupported"
	ErrorCodeDependencyUnavailable ErrorCode = "dependency_unavailable"
	ErrorCodeCancelled             ErrorCode = "cancelled"
)

// FailureReason is a privacy-safe deterministic failure identity.
type FailureReason string

// Closed verification failure reasons.
const (
	FailureReasonCatalogIntegrity     FailureReason = "catalog_integrity"
	FailureReasonReleaseBinding       FailureReason = "release_binding"
	FailureReasonUntrustedSigner      FailureReason = "untrusted_signer"
	FailureReasonSignatureInvalid     FailureReason = "signature_invalid"
	FailureReasonSupportExpired       FailureReason = "support_expired"
	FailureReasonUnsupportedHost      FailureReason = "unsupported_host"
	FailureReasonSourceDenied         FailureReason = "source_denied"
	FailureReasonNativePublisher      FailureReason = "native_publisher"
	FailureReasonCatalogRollback      FailureReason = "catalog_rollback"
	FailureReasonSequenceEquivocation FailureReason = "sequence_equivocation"
	FailureReasonAnchorIntegrity      FailureReason = "anchor_integrity"
	FailureReasonAnchorConflict       FailureReason = "anchor_conflict"
	FailureReasonDependency           FailureReason = "dependency"
	FailureReasonCancelled            FailureReason = "cancelled"
)

// VerificationError contains no raw path, URL, argv, or dependency detail.
type VerificationError struct {
	code      ErrorCode
	reason    FailureReason
	retryable bool
	message   string
}

// Error returns a fixed privacy-safe message.
func (e *VerificationError) Error() string { return e.message }

// Unwrap exposes only the stable verification error class.
func (e *VerificationError) Unwrap() error { return ErrVerificationFailed }

// Code returns the stable application category.
func (e *VerificationError) Code() ErrorCode { return e.code }

// Reason returns the stable privacy-safe reason.
func (e *VerificationError) Reason() FailureReason { return e.reason }

// Retryable reports whether retry can succeed without changing the signed policy.
func (e *VerificationError) Retryable() bool { return e.retryable }

func verificationError(code ErrorCode, reason FailureReason, retryable bool, message string) *VerificationError {
	return &VerificationError{code: code, reason: reason, retryable: retryable, message: message}
}

func mapContextOrDependency(err error) *VerificationError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return verificationError(ErrorCodeCancelled, FailureReasonCancelled, true, "runtime catalog verification was cancelled")
	}
	return verificationError(
		ErrorCodeDependencyUnavailable,
		FailureReasonDependency,
		true,
		"runtime catalog verification dependency is unavailable",
	)
}
