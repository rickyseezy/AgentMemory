package installphase

// ErrorCode is a stable privacy-safe phase integration failure.
type ErrorCode string

const (
	// ErrorCodeInvalidBinding rejects cross-plan or incomplete data.
	ErrorCodeInvalidBinding ErrorCode = "invalid_binding"
	// ErrorCodePlanUnavailable reports a typed plan repository failure.
	ErrorCodePlanUnavailable ErrorCode = "plan_unavailable"
	// ErrorCodeReadinessUnavailable reports a readiness use-case failure.
	ErrorCodeReadinessUnavailable ErrorCode = "readiness_unavailable"
	// ErrorCodeActivationUnavailable reports an activation use-case failure.
	ErrorCodeActivationUnavailable ErrorCode = "activation_unavailable"
	// ErrorCodeResourceUnavailable reports resource reconciliation failure.
	ErrorCodeResourceUnavailable ErrorCode = "resource_unavailable"
	// ErrorCodeReleaseUnavailable reports a fail-closed release trust failure.
	ErrorCodeReleaseUnavailable ErrorCode = "release_unavailable"
	// ErrorCodeRuntimeUnavailable reports a failed runtime provisioning use case.
	ErrorCodeRuntimeUnavailable ErrorCode = "runtime_unavailable"
	// ErrorCodeReservationUnavailable reports a non-recoverable reservation boundary failure.
	ErrorCodeReservationUnavailable ErrorCode = "reservation_unavailable"
	// ErrorCodeArtifactUnavailable reports a non-recoverable acquisition boundary failure.
	ErrorCodeArtifactUnavailable ErrorCode = "artifact_unavailable"
	// ErrorCodeAgentConfigurationUnavailable reports an unclassified safe-merge failure.
	ErrorCodeAgentConfigurationUnavailable ErrorCode = "agent_configuration_unavailable"
	// ErrorCodeHostUnavailable reports a fail-closed host trust/probe failure.
	ErrorCodeHostUnavailable ErrorCode = "host_unavailable"
	// ErrorCodeDirectoryUnavailable reports a protected product-layout failure.
	ErrorCodeDirectoryUnavailable ErrorCode = "directory_unavailable"
	// ErrorCodeSecretUnavailable reports a purpose-separated key provisioning failure.
	ErrorCodeSecretUnavailable ErrorCode = "secret_unavailable"
	// ErrorCodeStackUnavailable reports a signed Compose migration/start failure.
	ErrorCodeStackUnavailable ErrorCode = "stack_unavailable"
	// ErrorCodeBrainBootstrapUnavailable reports authenticated Core bootstrap failure.
	ErrorCodeBrainBootstrapUnavailable ErrorCode = "brain_bootstrap_unavailable"
)

// Error deliberately excludes wrapped raw diagnostics.
type Error struct{ code ErrorCode }

func phaseError(code ErrorCode) *Error { return &Error{code: code} }

// Error returns only the stable public code.
func (e *Error) Error() string { return string(e.code) }

// Code returns the stable machine-readable reason.
func (e *Error) Code() ErrorCode { return e.code }
