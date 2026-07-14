package hostverifyapp

// ErrorCode is the stable privacy-safe application failure class.
type ErrorCode string

const (
	// ErrorCodeCancelled means the caller's context ended.
	ErrorCodeCancelled ErrorCode = "cancelled"
	// ErrorCodeIntegrity means policy, signature, or evidence was invalid.
	ErrorCodeIntegrity ErrorCode = "integrity"
	// ErrorCodeDependency means a required trust capability was unavailable.
	ErrorCodeDependency ErrorCode = "dependency_unavailable"
)

// Error never wraps or exposes raw host diagnostics.
type Error struct{ code ErrorCode }

func verificationError(code ErrorCode) *Error { return &Error{code: code} }
func (e *Error) Error() string                { return string(e.code) }

// Code returns the stable machine-readable failure class.
func (e *Error) Code() ErrorCode { return e.code }
